#!/usr/bin/env python3
"""Autoteste offline dos decodificadores e do pipeline de persistencia.

NAO precisa de root, de rede nem de containers: constroi quadros Ethernet
completos byte a byte (fixtures de teste) e os passa pelos mesmos parsers e pelo
mesmo processar_quadro usados no ataque real. Serve para:
  (1) provar que a decodificacao manual esta correta (asserts); e
  (2) gerar exemplos reais de captura_*.log e resumo_*.csv a partir de um fluxo
      sintetico DNS -> HTTP -> HTTPS, sem precisar subir o laboratorio.

Rodar:  python3 scripts/autoteste.py
"""
import os
import socket
import struct
import sys
import tempfile
import time

SRC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
sys.path.insert(0, SRC)

import decoders as D          # noqa: E402
import interceptador as I     # noqa: E402

# ---- Construtores de pacotes (fixtures) ------------------------------------
MAC_ATACANTE = b"\x02\x00\x00\x00\x00\xfe"
MAC_VITIMA = b"\x02\x00\x00\x00\x00\x02"
MAC_GATEWAY = b"\x02\x00\x00\x00\x00\x01"


def eth(dst, src, etype):
    return struct.pack("!6s6sH", dst, src, etype)


def checksum(dados):
    if len(dados) % 2:
        dados += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(dados) // 2), dados))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def ipv4(src, dst, proto, payload, ttl=64):
    ver_ihl = 0x45
    total = 20 + len(payload)
    cab = struct.pack("!BBHHHBBH4s4s", ver_ihl, 0, total, 0, 0, ttl, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    chk = checksum(cab)
    cab = struct.pack("!BBHHHBBH4s4s", ver_ihl, 0, total, 0, 0, ttl, proto, chk,
                      socket.inet_aton(src), socket.inet_aton(dst))
    return cab + payload


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(sport, dport, payload, flags=0x18, seq=1, ack=1):
    offset_flags = (5 << 4)   # data offset = 5 palavras (20 bytes), sem opcoes
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack,
                       offset_flags, flags, 65535, 0, 0) + payload


def _nome_dns(nome):
    out = b""
    for label in nome.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def dns_query(qname, tid=0x1234):
    cab = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)   # flags: consulta RD
    pergunta = _nome_dns(qname) + struct.pack("!HH", 1, 1)  # tipo A, classe IN
    return cab + pergunta


def dns_response(qname, ip, tid=0x1234):
    cab = struct.pack("!HHHHHH", tid, 0x8180, 1, 1, 0, 0)   # flags: resposta
    pergunta = _nome_dns(qname) + struct.pack("!HH", 1, 1)
    # Resposta usando ponteiro de compressao 0xC00C (nome na pergunta, offset 12)
    resposta = struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4) + socket.inet_aton(ip)
    return cab + pergunta + resposta


def http_get(host, caminho="/", metodo="GET"):
    req = (f"{metodo} {caminho} HTTP/1.1\r\n"
           f"Host: {host}\r\n"
           f"User-Agent: curl/8.0\r\n"
           f"Cookie: sessao=abc123\r\n\r\n")
    return req.encode()


def tls_client_hello(sni):
    host = sni.encode()
    server_name = b"\x00" + struct.pack("!H", len(host)) + host     # tipo 0 host
    lista = struct.pack("!H", len(server_name)) + server_name
    ext_sni = struct.pack("!HH", 0x0000, len(lista)) + lista
    extensoes = struct.pack("!H", len(ext_sni)) + ext_sni
    corpo = (struct.pack("!H", 0x0303) + b"\x00" * 32 +            # versao+random
             b"\x00" +                                            # session id len 0
             struct.pack("!H", 2) + b"\x13\x01" +                 # 1 cipher suite
             b"\x01\x00" +                                        # comp: 1 metodo (0)
             extensoes)
    n = len(corpo)
    handshake = b"\x01" + bytes([(n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF]) + corpo
    registro = b"\x16" + struct.pack("!H", 0x0303) + struct.pack("!H", len(handshake))
    return registro + handshake


# ---- Testes unitarios dos decodificadores ----------------------------------
def testes_unitarios():
    ok = 0

    # Ethernet
    frame = eth(MAC_GATEWAY, MAC_VITIMA, D.ETHERTYPE_IPV4) + b"xyz"
    dst, src, etype, payload = D.parse_ethernet(frame)
    assert dst == "02:00:00:00:00:01" and etype == D.ETHERTYPE_IPV4
    assert payload == b"xyz"; ok += 1

    # ARP parse + montar (ida e volta)
    quadro = D.montar_arp(D.ARP_OP_REPLY, MAC_ATACANTE, socket.inet_aton("172.10.20.1"),
                          MAC_VITIMA, socket.inet_aton("172.10.20.2"))
    _, _, et, corpo = D.parse_ethernet(quadro)
    arp = D.parse_arp(corpo)
    assert et == D.ETHERTYPE_ARP and arp["oper"] == D.ARP_OP_REPLY
    assert arp["ip_remetente"] == "172.10.20.1"
    assert arp["mac_remetente"] == "02:00:00:00:00:fe"
    assert arp["ip_alvo"] == "172.10.20.2"; ok += 1

    # IPv4
    pkt = ipv4("172.10.20.2", "172.10.30.10", D.IPPROTO_UDP, b"abcd", ttl=63)
    ip = D.parse_ipv4(pkt)
    assert ip["ip_src"] == "172.10.20.2" and ip["ip_dst"] == "172.10.30.10"
    assert ip["ttl"] == 63 and ip["protocolo"] == D.IPPROTO_UDP
    assert ip["payload"] == b"abcd"; ok += 1

    # UDP
    seg = udp(40000, 53, b"hello")
    u = D.parse_udp(seg)
    assert u["sport"] == 40000 and u["dport"] == 53 and u["dados"] == b"hello"; ok += 1

    # TCP + flags
    seg = tcp(44444, 443, b"dados", flags=0x02)   # SYN
    t = D.parse_tcp(seg)
    assert t["sport"] == 44444 and t["dport"] == 443
    assert t["flags_txt"] == "SYN" and t["payload"] == b"dados"; ok += 1

    # DNS consulta
    d = D.parse_dns(dns_query("loja.lab"))
    assert d["resposta"] is False and d["qname"] == "loja.lab" and d["qtype"] == "A"; ok += 1

    # DNS resposta (com compressao)
    d = D.parse_dns(dns_response("loja.lab", "172.10.30.10"))
    assert d["resposta"] is True and d["qname"] == "loja.lab"
    assert ("A", "172.10.30.10") in d["respostas"]; ok += 1

    # HTTP
    h = D.parse_http_request(http_get("site-http.lab", "/login", "POST"))
    assert h["metodo"] == "POST" and h["host"] == "site-http.lab"
    assert h["caminho"] == "/login" and h["cookie"] == "sessao=abc123"; ok += 1

    # TLS SNI
    assert D.extrair_sni(tls_client_hello("banco.lab")) == "banco.lab"; ok += 1
    # Nao e ClientHello -> None
    assert D.extrair_sni(b"\x17\x03\x03\x00\x05abcde") is None; ok += 1

    print(f"[OK] {ok} testes unitarios dos decodificadores passaram.")


# ---- Teste de ponta a ponta do pipeline ------------------------------------
def teste_pipeline():
    vitima, gw, srv = "172.10.20.2", "172.10.20.1", "172.10.30.10"

    def da_vitima(l3):
        return eth(MAC_GATEWAY, MAC_VITIMA, D.ETHERTYPE_IPV4) + l3

    def para_vitima(l3):
        return eth(MAC_VITIMA, MAC_GATEWAY, D.ETHERTYPE_IPV4) + l3

    dominios = [("loja.lab", "172.10.30.10"), ("banco.lab", "172.10.30.11"),
                ("noticias.lab", "172.10.30.12"), ("video.lab", "172.10.30.13")]

    quadros = []
    # Experimento 1: HTTP puro
    quadros.append(da_vitima(ipv4(vitima, srv, D.IPPROTO_UDP,
                                  udp(40001, 53, dns_query("site-http.lab")))))
    quadros.append(para_vitima(ipv4(srv, vitima, D.IPPROTO_UDP,
                                    udp(53, 40001, dns_response("site-http.lab", srv)))))
    quadros.append(da_vitima(ipv4(vitima, srv, D.IPPROTO_TCP,
                                  tcp(44001, 80, http_get("site-http.lab", "/segredo")))))
    # Experimento 2: 4 dominios HTTPS, cada um com DNS -> ClientHello(SNI)
    for i, (dom, ipd) in enumerate(dominios):
        porta = 45000 + i
        quadros.append(da_vitima(ipv4(vitima, srv, D.IPPROTO_UDP,
                                      udp(40100 + i, 53, dns_query(dom)))))
        quadros.append(para_vitima(ipv4(srv, vitima, D.IPPROTO_UDP,
                                        udp(53, 40100 + i, dns_response(dom, ipd)))))
        quadros.append(da_vitima(ipv4(vitima, ipd, D.IPPROTO_TCP,
                                      tcp(porta, 443, tls_client_hello(dom)))))
        quadros.append(para_vitima(ipv4(ipd, vitima, D.IPPROTO_TCP,
                                        tcp(443, porta, b"\x16\x03\x03" + b"\x00" * 60))))
    # Ruido: trafego que NAO e da vitima deve ser ignorado pelo filtro
    quadros.append(eth(MAC_GATEWAY, MAC_ATACANTE, D.ETHERTYPE_IPV4) +
                   ipv4("172.10.20.9", srv, D.IPPROTO_TCP, tcp(5000, 443,
                        tls_client_hello("intruso.lab"))))

    estado = I.EstadoCompartilhado()
    with estado.lock:
        estado.arp.update({"vitima": vitima, "gateway": gw,
                           "mac_vitima": "02:..:02", "mac_gateway": "02:..:01",
                           "meu_mac": "02:..:fe", "intervalo": 2.0, "ativo": True})
    tmp = tempfile.mkdtemp(prefix="autoteste_")
    persist = I.Persistencia(dir_saida=tmp, sufixo="exemplo")

    reconhecidos = 0
    for frame in quadros:
        r = I.processar_quadro(frame, time.time(), estado, persist, vitima)
        if r:
            reconhecidos += 1
    persist.salvar_resumo(estado)
    persist.fechar()

    # Verificacoes do estado acumulado
    assert estado.total_dns == 10, estado.total_dns          # 5 consultas + 5 respostas
    assert estado.total_http == 1, estado.total_http
    assert estado.total_tls == 4, estado.total_tls
    assert estado.ip_para_dominio.get("172.10.30.11") == "banco.lab"
    assert "intruso.lab" not in estado.destinos              # ruido filtrado
    print(f"[OK] pipeline: {reconhecidos} eventos reconhecidos, "
          f"{len(estado.destinos)} destinos, filtro de fluxo funcionando.")

    print(f"\n--- exemplo gerado: {persist.caminho_log} ---")
    with open(persist.caminho_log) as f:
        print(f.read().rstrip())
    print(f"\n--- exemplo gerado: {persist.caminho_csv} ---")
    with open(persist.caminho_csv) as f:
        print(f.read().rstrip())
    return persist.caminho_log, persist.caminho_csv


if __name__ == "__main__":
    testes_unitarios()
    teste_pipeline()
    print("\n[SUCESSO] todos os autotestes passaram.")
