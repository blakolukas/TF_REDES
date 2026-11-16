"""Painel textual em tempo real (secao 3.8 do enunciado).

Mostra o status do envenenamento ARP, os contadores globais e a tabela dos
ultimos destinos acessados. Usa `curses` (biblioteca padrao) para um painel
que atualiza no lugar, com cores; cai para texto puro quando nao ha terminal
(saida redirecionada, TERM ausente). So le o EstadoCompartilhado sob o lock --
nao faz calculo nem I/O de rede, apenas apresentacao.
"""
import curses
import os
import sys
import time


def _fmt_bytes(n):
    for unidade in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f}{unidade}" if unidade == "B" else f"{n:.1f}{unidade}"
        n /= 1024
    return f"{n:.1f}TB"


def _snapshot(estado):
    """Le o estado compartilhado sob o lock e devolve um dict imutavel."""
    with estado.lock:
        arp = dict(estado.arp)
        destinos = sorted(estado.destinos.values(),
                          key=lambda d: d["ultimo"], reverse=True)[:12]
        destinos = [
            {"dominio": d["dominio"], "ips": sorted(d["ips"]),
             "protocolos": sorted(d["protocolos"]), "bytes": d["bytes"]}
            for d in destinos
        ]
        return {"arp": arp, "tp": estado.total_pacotes, "td": estado.total_dns,
                "th": estado.total_http, "tt": estado.total_tls,
                "tb": estado.total_bytes, "inicio": estado.inicio,
                "destinos": destinos}


# --------------------------------------------------------------------------
# Modo texto puro (fallback + facilita teste): devolve a tela como string.
# --------------------------------------------------------------------------
def render(estado):
    s = _snapshot(estado)
    arp = s["arp"]
    larg = 78
    L = ["=" * larg,
         " MITM ARP SPOOFING - PAINEL DE INTERCEPTACAO".ljust(larg),
         "=" * larg]
    estado_txt = "ATIVO" if arp["ativo"] else "parado"
    L.append(f" Envenenamento ARP: {estado_txt}   "
             f"intervalo={arp['intervalo']}s   rajadas={arp['rajadas']}")
    L.append(f"   Vitima : {arp['vitima']}  ({arp['mac_vitima']})")
    L.append(f"   Gateway: {arp['gateway']}  ({arp['mac_gateway']})")
    L.append(f"   Atacante MAC anunciado aos dois: {arp['meu_mac']}")
    L.append("-" * larg)
    tempo = int(time.time() - s["inicio"])
    L.append(f" Tempo: {tempo//60:02d}:{tempo%60:02d}   "
             f"Pacotes: {s['tp']}   DNS: {s['td']}   HTTP: {s['th']}   "
             f"TLS: {s['tt']}   Volume: {_fmt_bytes(s['tb'])}")
    L.append("-" * larg)
    L.append(" ULTIMOS DESTINOS".ljust(larg))
    L.append(f" {'DOMINIO (DNS/SNI)':<30}{'IP':<16}{'PROTOS':<14}{'BYTES':>8}")
    if not s["destinos"]:
        L.append("   (aguardando trafego da vitima...)")
    for d in s["destinos"]:
        dom = (d["dominio"] or "-")[:29]
        ip = (d["ips"][0] if d["ips"] else "-")[:15]
        protos = ",".join(d["protocolos"])[:13]
        L.append(f" {dom:<30}{ip:<16}{protos:<14}{_fmt_bytes(d['bytes']):>8}")
    L.append("=" * larg)
    L.append(" Ctrl-C encerra e restaura as tabelas ARP (self-healing).")
    return "\n".join(L)


def _laco_texto(estado, parar, intervalo):
    while not parar.is_set():
        print("\x1b[H\x1b[2J", end="")
        print(render(estado), flush=True)
        parar.wait(intervalo)


# --------------------------------------------------------------------------
# Painel curses
# --------------------------------------------------------------------------
_TITULO, _ATIVO, _PARADO, _ROTULO, _VALOR, _CAB = range(1, 7)


def _init_cores():
    if not curses.has_colors():
        return False
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(_TITULO, curses.COLOR_CYAN, -1)
    curses.init_pair(_ATIVO, curses.COLOR_GREEN, -1)
    curses.init_pair(_PARADO, curses.COLOR_RED, -1)
    curses.init_pair(_ROTULO, curses.COLOR_YELLOW, -1)
    curses.init_pair(_VALOR, curses.COLOR_WHITE, -1)
    curses.init_pair(_CAB, curses.COLOR_BLACK, curses.COLOR_CYAN)
    return True


def _put(win, y, x, texto, attr=0):
    """addstr seguro: nunca estoura os limites da janela."""
    alt, larg = win.getmaxyx()
    if 0 <= y < alt and 0 <= x < larg:
        win.addnstr(y, x, texto, max(0, larg - x - 1), attr)


def _desenhar(win, s, cores):
    win.erase()
    alt, larg = win.getmaxyx()
    arp = s["arp"]
    C = (lambda p: curses.color_pair(p)) if cores else (lambda p: 0)
    B = curses.A_BOLD

    _put(win, 0, 0, " MITM ARP SPOOFING - PAINEL DE INTERCEPTACAO ".ljust(larg - 1),
         C(_CAB) | B)

    ativo = arp["ativo"]
    _put(win, 2, 1, "Envenenamento ARP:", C(_ROTULO) | B)
    _put(win, 2, 20, "ATIVO" if ativo else "parado",
         (C(_ATIVO) if ativo else C(_PARADO)) | B)
    _put(win, 2, 30, f"intervalo={arp['intervalo']}s   rajadas={arp['rajadas']}", C(_VALOR))
    _put(win, 3, 3, f"Vitima : {arp['vitima']}  ({arp['mac_vitima']})", C(_VALOR))
    _put(win, 4, 3, f"Gateway: {arp['gateway']}  ({arp['mac_gateway']})", C(_VALOR))
    _put(win, 5, 3, f"Atacante (meu MAC): {arp['meu_mac']}", C(_VALOR))

    t = int(time.time() - s["inicio"])
    _put(win, 7, 1, f"Tempo {t//60:02d}:{t%60:02d}", C(_TITULO) | B)
    _put(win, 7, 16,
         f"Pacotes {s['tp']}   DNS {s['td']}   HTTP {s['th']}   "
         f"TLS {s['tt']}   Volume {_fmt_bytes(s['tb'])}", C(_VALOR) | B)

    _put(win, 9, 1, "ULTIMOS DESTINOS", C(_TITULO) | B)
    _put(win, 10, 0,
         f" {'DOMINIO (DNS/SNI)':<30}{'IP':<16}{'PROTOS':<14}{'BYTES':>8}".ljust(larg - 1),
         C(_CAB))
    if not s["destinos"]:
        _put(win, 11, 3, "(aguardando trafego da vitima...)", C(_PARADO))
    else:
        for i, d in enumerate(s["destinos"]):
            y = 11 + i
            if y >= alt - 1:
                break
            dom = (d["dominio"] or "-")[:29]
            ip = (d["ips"][0] if d["ips"] else "-")[:15]
            protos = ",".join(d["protocolos"])[:13]
            _put(win, y, 0,
                 f" {dom:<30}{ip:<16}{protos:<14}{_fmt_bytes(d['bytes']):>8}", C(_VALOR))

    _put(win, alt - 1, 0,
         " Ctrl-C (ou q) encerra e restaura as tabelas ARP (self-healing).",
         C(_ROTULO))
    win.noutrefresh()
    curses.doupdate()


def _laco_curses(stdscr, estado, parar, intervalo):
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.timeout(int(intervalo * 1000))
    cores = _init_cores()
    while not parar.is_set():
        try:
            _desenhar(stdscr, _snapshot(estado), cores)
        except curses.error:
            pass  # terminal pequeno demais; tenta de novo no proximo ciclo
        try:
            ch = stdscr.getch()
        except (curses.error, KeyboardInterrupt):
            ch = -1
        if ch in (ord("q"), ord("Q")):
            parar.set()
            break


def laco_tui(estado, parar, intervalo=1.0):
    """Redesenha o painel ate `parar` ser sinalizado.

    Usa curses quando a saida e um terminal interativo; senao (pipe, redirect,
    TERM ausente) cai no modo texto puro. Qualquer falha de curses tambem cai
    no texto -- a UI nunca derruba o ataque.
    """
    if not sys.stdout.isatty() or os.environ.get("TERM", "") in ("", "dumb"):
        _laco_texto(estado, parar, intervalo)
        return
    try:
        curses.wrapper(_laco_curses, estado, parar, intervalo)
    except (curses.error, KeyboardInterrupt):
        if not parar.is_set():
            _laco_texto(estado, parar, intervalo)
