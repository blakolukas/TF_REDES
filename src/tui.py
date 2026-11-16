"""Painel textual em tempo real (secao 3.8 do enunciado).

Desenha, a cada ~1 s, o status do envenenamento ARP, os contadores globais e a
tabela dos ultimos destinos acessados. Le o EstadoCompartilhado sob o lock e
monta a tela como texto; nao faz calculo nem I/O de rede, so apresentacao.
"""
import os
import time


def _fmt_bytes(n):
    for unidade in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f}{unidade}" if unidade == "B" else f"{n:.1f}{unidade}"
        n /= 1024
    return f"{n:.1f}TB"


def _limpar():
    # \x1b[H move o cursor para o topo; \x1b[2J limpa a tela
    print("\x1b[H\x1b[2J", end="")


def render(estado):
    """Monta e devolve a tela do painel como string (facilita teste)."""
    with estado.lock:
        arp = dict(estado.arp)
        tp, td = estado.total_pacotes, estado.total_dns
        th, tt, tb = estado.total_http, estado.total_tls, estado.total_bytes
        # Ordena destinos por ultimo acesso (mais recente primeiro)
        destinos = sorted(estado.destinos.values(),
                          key=lambda d: d["ultimo"], reverse=True)[:10]
        destinos = [
            {"dominio": d["dominio"], "ips": sorted(d["ips"]),
             "protocolos": sorted(d["protocolos"]), "bytes": d["bytes"]}
            for d in destinos
        ]
        inicio = estado.inicio
    linhas = []
    larg = 78
    linhas.append("=" * larg)
    linhas.append(" MITM ARP SPOOFING - PAINEL DE INTERCEPTACAO".ljust(larg))
    linhas.append("=" * larg)
    estado_txt = "ATIVO" if arp["ativo"] else "parado"
    linhas.append(f" Envenenamento ARP: {estado_txt}   "
                  f"intervalo={arp['intervalo']}s   rajadas={arp['rajadas']}")
    linhas.append(f"   Vitima : {arp['vitima']}  ({arp['mac_vitima']})")
    linhas.append(f"   Gateway: {arp['gateway']}  ({arp['mac_gateway']})")
    linhas.append(f"   Atacante MAC anunciado aos dois: {arp['meu_mac']}")
    linhas.append("-" * larg)
    tempo = int(time.time() - inicio)
    linhas.append(f" Tempo: {tempo//60:02d}:{tempo%60:02d}   "
                  f"Pacotes: {tp}   DNS: {td}   HTTP: {th}   "
                  f"TLS: {tt}   Volume: {_fmt_bytes(tb)}")
    linhas.append("-" * larg)
    linhas.append(" ULTIMOS DESTINOS".ljust(larg))
    linhas.append(f" {'DOMINIO (DNS/SNI)':<30}{'IP':<16}{'PROTOS':<14}{'BYTES':>8}")
    if not destinos:
        linhas.append("   (aguardando trafego da vitima...)")
    for d in destinos:
        dom = (d["dominio"] or "-")[:29]
        ip = (d["ips"][0] if d["ips"] else "-")[:15]
        protos = ",".join(d["protocolos"])[:13]
        linhas.append(f" {dom:<30}{ip:<16}{protos:<14}{_fmt_bytes(d['bytes']):>8}")
    linhas.append("=" * larg)
    linhas.append(" Ctrl-C encerra e restaura as tabelas ARP (self-healing).")
    return "\n".join(linhas)


def laco_tui(estado, parar, intervalo=1.0):
    """Redesenha o painel ate `parar` ser sinalizado."""
    while not parar.is_set():
        _limpar()
        print(render(estado), flush=True)
        time.sleep(intervalo)
