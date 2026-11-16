"""Interceptador: estado compartilhado, decodificacao, correlacao e persistencia.

Este modulo e o "consumidor" do pipeline. A thread de captura (em mitm.py) apenas
le quadros crus do raw socket e os enfileira; aqui eles sao decodificados camada
a camada (via decoders.py), correlacionados (DNS -> IP -> SNI) e acumulados em um
EstadoCompartilhado protegido por lock. Em paralelo, cada evento relevante e
gravado no log detalhado e o resumo consolidado (CSV) e reescrito periodicamente.

Separar a captura (produtor) do processamento (consumidor) por uma fila evita que
o parsing segure o recv() e faca o kernel descartar quadros -- o ponto de
concorrencia discutido em docs/arquitetura.md.
"""
import csv
import threading
import time

from decoders import (
    parse_ethernet, parse_ipv4, parse_udp, parse_tcp,
    parse_dns, parse_http_request, extrair_sni,
    ETHERTYPE_IPV4, IPPROTO_UDP, IPPROTO_TCP,
    PORTA_DNS, PORTA_HTTP, PORTA_HTTPS,
)


class EstadoCompartilhado:
    """Contadores e tabelas compartilhados entre o processador e a TUI.

    TODO acesso (leitura na TUI, escrita no processador) passa pelo `self.lock`.
    As estruturas sao propositalmente simples (dicts/sets) para que a regiao
    critica seja curta: entra, atualiza, sai.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.inicio = time.time()
        # Contadores globais
        self.total_pacotes = 0
        self.total_dns = 0
        self.total_http = 0
        self.total_tls = 0
        self.total_bytes = 0
        # Correlacao DNS: dominio -> set(IPs) e IP -> dominio
        self.dominio_para_ips = {}
        self.ip_para_dominio = {}
        # Destinos: chave (dominio ou IP) -> dict(dominio, ips, protocolos, bytes, ultimo)
        self.destinos = {}
        # Status do ataque ARP (preenchido por mitm.py)
        self.arp = {"vitima": None, "gateway": None,
                    "mac_vitima": None, "mac_gateway": None,
                    "meu_mac": None, "ativo": False, "intervalo": None,
                    "rajadas": 0}
        # Ultimos eventos (para o painel)
        self.ultimos = []

    def chave_destino(self, ip):
        dom = self.ip_para_dominio.get(ip)
        return dom if dom else ip

    def registra_destino(self, ip, protocolo, nbytes, dominio=None):
        chave = dominio or self.chave_destino(ip)
        d = self.destinos.get(chave)
        if d is None:
            d = {"dominio": dominio or "", "ips": set(), "protocolos": set(),
                 "bytes": 0, "ultimo": 0.0}
            self.destinos[chave] = d
        if ip:
            d["ips"].add(ip)
        if dominio and not d["dominio"]:
            d["dominio"] = dominio
        d["protocolos"].add(protocolo)
        d["bytes"] += nbytes
        d["ultimo"] = time.time()
        return d


class Persistencia:
    """Grava o log detalhado (.log) e o resumo consolidado (.csv).

    Os nomes recebem o sufixo temporal YYYYMMDDHHMI exigido no enunciado. O log
    e append (um registro por evento); o CSV e reescrito por inteiro a cada
    flush, sempre refletindo o estado acumulado dos destinos.
    """

    def __init__(self, dir_saida="resultados", sufixo=None):
        import os
        os.makedirs(dir_saida, exist_ok=True)
        if sufixo is None:
            sufixo = time.strftime("%Y%m%d%H%M")
        self.caminho_log = os.path.join(dir_saida, f"captura_{sufixo}.log")
        self.caminho_csv = os.path.join(dir_saida, f"resumo_{sufixo}.csv")
        self._log = open(self.caminho_log, "a", encoding="utf-8")
        self._lock = threading.Lock()
        self.evento(f"# captura iniciada em {time.strftime('%Y-%m-%d %H:%M:%S')}")

    def evento(self, linha):
        with self._lock:
            self._log.write(linha + "\n")
            self._log.flush()

    def registro(self, ts, ip_src, ip_dst, protocolo, metadados, nbytes):
        """Um registro por evento/fluxo, como especificado na secao 3.7."""
        self.evento(
            f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))} "
            f"{ip_src:>15} -> {ip_dst:<15} {protocolo:<5} "
            f"{nbytes:>6}B  {metadados}"
        )

    def salvar_resumo(self, estado):
        """Reescreve o CSV consolidado a partir do estado atual dos destinos."""
        with self._lock, estado.lock:
            linhas = []
            for chave, d in estado.destinos.items():
                linhas.append((
                    d["dominio"] or "",
                    ";".join(sorted(d["ips"])),
                    ";".join(sorted(d["protocolos"])),
                    d["bytes"],
                ))
        linhas.sort(key=lambda r: r[3], reverse=True)
        with open(self.caminho_csv, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["dominio", "ip_destino", "protocolos", "total_bytes"])
            w.writerows(linhas)

    def fechar(self):
        self.evento(f"# captura encerrada em {time.strftime('%Y-%m-%d %H:%M:%S')}")
        with self._lock:
            self._log.close()


def _adiciona_ultimo(estado, texto):
    estado.ultimos.append((time.strftime("%H:%M:%S"), texto))
    if len(estado.ultimos) > 12:
        estado.ultimos.pop(0)


def processar_quadro(frame, ts, estado, persist, ip_vitima):
    """Decodifica UM quadro e atualiza estado/persistencia.

    So interessam os pacotes do fluxo da vitima (origem OU destino = vitima).
    Retorna uma string curta descrevendo o que foi reconhecido (ou None),
    usada tambem pelo autoteste para verificar o comportamento sem socket.
    """
    eth = parse_ethernet(frame)
    if not eth or eth[2] != ETHERTYPE_IPV4:
        return None
    ip = parse_ipv4(eth[3])
    if not ip:
        return None
    ip_src, ip_dst = ip["ip_src"], ip["ip_dst"]

    # Filtro de fluxo: so a vitima (nos dois sentidos)
    if ip_vitima not in (ip_src, ip_dst):
        return None

    nbytes = len(eth[3])                      # tamanho do datagrama IP
    outro = ip_dst if ip_src == ip_vitima else ip_src

    with estado.lock:
        estado.total_pacotes += 1
        estado.total_bytes += nbytes

    descricao = None

    # ----- UDP / DNS (porta 53) -----
    if ip["protocolo"] == IPPROTO_UDP:
        udp = parse_udp(ip["payload"])
        if udp and PORTA_DNS in (udp["sport"], udp["dport"]):
            dns = parse_dns(udp["dados"])
            if dns and dns["qname"]:
                with estado.lock:
                    estado.total_dns += 1
                    if dns["resposta"]:
                        ips = [v for (t, v) in dns["respostas"] if t == "A"]
                        if ips:
                            estado.dominio_para_ips.setdefault(
                                dns["qname"], set()).update(ips)
                            for ipr in ips:
                                estado.ip_para_dominio[ipr] = dns["qname"]
                        estado.registra_destino(outro, "DNS", nbytes,
                                                dominio=dns["qname"])
                        meta = (f"DNS resposta {dns['qname']} -> "
                                f"{', '.join(ips) or '(sem A)'}")
                    else:
                        estado.registra_destino(outro, "DNS", nbytes,
                                                dominio=dns["qname"])
                        meta = f"DNS consulta {dns['qtype']} {dns['qname']}"
                    _adiciona_ultimo(estado, meta)
                persist.registro(ts, ip_src, ip_dst, "DNS", meta, nbytes)
                return meta

    # ----- TCP / HTTP (80) e HTTPS/TLS (443) -----
    if ip["protocolo"] == IPPROTO_TCP:
        tcp = parse_tcp(ip["payload"])
        if not tcp:
            return None
        payload = tcp["payload"]

        if PORTA_HTTP in (tcp["sport"], tcp["dport"]) and payload:
            req = parse_http_request(payload)
            if req:
                dom = req["host"] or estado.ip_para_dominio.get(outro, "")
                extra = []
                if req["user_agent"]:
                    extra.append(f"UA='{req['user_agent']}'")
                if req["cookie"]:
                    extra.append(f"Cookie='{req['cookie']}'")
                meta = (f"HTTP {req['metodo']} http://{req['host']}{req['caminho']}"
                        + ("  " + " ".join(extra) if extra else ""))
                with estado.lock:
                    estado.total_http += 1
                    estado.registra_destino(outro, "HTTP", nbytes,
                                            dominio=dom or None)
                    _adiciona_ultimo(estado, meta)
                persist.registro(ts, ip_src, ip_dst, "HTTP", meta, nbytes)
                return meta
            # trafego HTTP sem ser requisicao (resposta/corpo): so contabiliza
            with estado.lock:
                estado.registra_destino(outro, "HTTP", nbytes)
            return None

        if PORTA_HTTPS in (tcp["sport"], tcp["dport"]):
            if payload:
                sni = extrair_sni(payload)
                if sni:
                    with estado.lock:
                        estado.total_tls += 1
                        estado.dominio_para_ips.setdefault(sni, set()).add(outro)
                        estado.ip_para_dominio.setdefault(outro, sni)
                        estado.registra_destino(outro, "HTTPS", nbytes, dominio=sni)
                        meta = f"TLS ClientHello SNI={sni}"
                        _adiciona_ultimo(estado, meta)
                    persist.registro(ts, ip_src, ip_dst, "HTTPS", meta, nbytes)
                    return meta
            # demais segmentos da sessao TLS (dados cifrados): contabiliza bytes
            dom = estado.ip_para_dominio.get(outro)
            with estado.lock:
                estado.registra_destino(outro, "HTTPS", nbytes, dominio=dom)
            return None

    return descricao


def laco_processador(fila, estado, persist, ip_vitima, parar, intervalo_csv=2.0):
    """Consome a fila de quadros crus ate `parar`; salva o CSV a cada N s."""
    proximo_csv = time.time() + intervalo_csv
    while not parar.is_set() or not fila.empty():
        try:
            frame, ts = fila.get(timeout=0.3)
        except Exception:
            frame = None
        if frame is not None:
            try:
                processar_quadro(frame, ts, estado, persist, ip_vitima)
            except Exception as e:
                persist.evento(f"# erro ao processar quadro: {e!r}")
        if time.time() >= proximo_csv:
            persist.salvar_resumo(estado)
            proximo_csv = time.time() + intervalo_csv
    persist.salvar_resumo(estado)
