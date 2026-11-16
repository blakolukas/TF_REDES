"""Decodificadores de pacotes feitos a mao (Trabalho Final).

Todas as funcoes deste modulo recebem BYTES crus (lidos de um socket AF_PACKET)
e devolvem os campos ja interpretados. NAO ha nenhuma biblioteca de parsing de
pacotes (Scapy, dpkt, libpcap...): a decodificacao e byte a byte com `struct`,
exatamente como exige o enunciado. Cada parser e uma funcao pura (sem efeito
colateral e sem socket), o que permite testa-los isoladamente com quadros
forjados -- ver scripts/autoteste.py.

Pilha decodificada:
    Ethernet II  -> EtherType (IPv4 / ARP)
      ARP        -> operacao, pares (IP, MAC) de remetente e alvo
      IPv4       -> protocolo (UDP/TCP), IPs, TTL
        UDP      -> portas, comprimento, dados (DNS na porta 53)
        TCP      -> portas, flags, payload (HTTP na 80, TLS na 443)
          DNS    -> QNAME da consulta e respostas A/AAAA
          HTTP   -> metodo, Host, caminho (texto claro)
          TLS    -> SNI extraido do ClientHello
"""
import socket
import struct

# ---- Constantes de protocolo (valores dos campos, em hexadecimal) ----------
ETH_P_ALL = 0x0003          # captura de todos os EtherTypes no AF_PACKET
ETH_HDR_LEN = 14            # 6 (dst) + 6 (src) + 2 (ethertype)

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806

ARP_HTYPE_ETHERNET = 0x0001
ARP_PTYPE_IPV4 = 0x0800
ARP_OP_REQUEST = 1
ARP_OP_REPLY = 2

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17

PORTA_DNS = 53
PORTA_HTTP = 80
PORTA_HTTPS = 443

MAC_BROADCAST = b"\xff\xff\xff\xff\xff\xff"
MAC_ZERO = b"\x00\x00\x00\x00\x00\x00"


# ---- Utilitarios de formatacao ---------------------------------------------
def mac_para_texto(mac):
    """Converte 6 bytes de MAC em 'aa:bb:cc:dd:ee:ff'."""
    return ":".join("%02x" % b for b in mac)


def texto_para_mac(texto):
    """Converte 'aa:bb:cc:dd:ee:ff' nos 6 bytes correspondentes."""
    return bytes(int(parte, 16) for parte in texto.split(":"))


def flags_tcp_texto(flags):
    """Nomes das flags TCP ativas em um byte de flags (ex.: 'SYN,ACK')."""
    nomes = [("FIN", 0x01), ("SYN", 0x02), ("RST", 0x04),
             ("PSH", 0x08), ("ACK", 0x10), ("URG", 0x20)]
    return ",".join(n for n, bit in nomes if flags & bit) or "-"


# ---- Camada de enlace: Ethernet II -----------------------------------------
def parse_ethernet(frame):
    """Decodifica o cabecalho Ethernet de 14 bytes.

    Retorna (mac_dst, mac_src, ethertype, payload). MACs em texto.
    """
    if len(frame) < ETH_HDR_LEN:
        return None
    mac_dst, mac_src, ethertype = struct.unpack("!6s6sH", frame[:ETH_HDR_LEN])
    return (mac_para_texto(mac_dst), mac_para_texto(mac_src),
            ethertype, frame[ETH_HDR_LEN:])


# ---- Camada de enlace: ARP --------------------------------------------------
def parse_arp(pkt):
    """Decodifica um pacote ARP sobre Ethernet/IPv4 (28 bytes uteis).

    Retorna um dict com operacao e os pares (IP, MAC) de remetente e alvo, ou
    None se o pacote nao for ARP Ethernet/IPv4.
    """
    if len(pkt) < 28:
        return None
    htype, ptype, hlen, plen, oper = struct.unpack("!HHBBH", pkt[:8])
    if htype != ARP_HTYPE_ETHERNET or ptype != ARP_PTYPE_IPV4:
        return None
    sha = pkt[8:14]      # sender hardware address (MAC de quem envia)
    spa = pkt[14:18]     # sender protocol address (IP de quem envia)
    tha = pkt[18:24]     # target hardware address (MAC do alvo)
    tpa = pkt[24:28]     # target protocol address (IP do alvo)
    return {
        "oper": oper,
        "ip_remetente": socket.inet_ntoa(spa),
        "mac_remetente": mac_para_texto(sha),
        "ip_alvo": socket.inet_ntoa(tpa),
        "mac_alvo": mac_para_texto(tha),
    }


def montar_arp(oper, mac_src, ip_src, mac_dst, ip_dst, eth_dst=None):
    """Monta um quadro Ethernet + ARP completo pronto para send().

    Usado tanto na descoberta (ARP Request em broadcast) quanto no
    envenenamento (ARP Reply forjado) e na cura (ARP Reply legitimo). Todos os
    enderecos entram como bytes crus (MAC: 6 bytes; IP: usar inet_aton).

    `mac_dst` vira o THA (target hardware address) do corpo ARP. Em um Request,
    o THA e desconhecido (00:00:..) e o destino Ethernet e o broadcast: nesse
    caso passa-se eth_dst=MAC_BROADCAST separadamente. Nos Reply (veneno/cura) o
    destino Ethernet coincide com o MAC do alvo, entao eth_dst pode ser omitido.
    """
    eth_destino = eth_dst if eth_dst is not None else mac_dst
    # Cabecalho Ethernet: destino, origem, EtherType=ARP
    eth = struct.pack("!6s6sH", eth_destino, mac_src, ETHERTYPE_ARP)
    # Corpo ARP
    arp = struct.pack(
        "!HHBBH6s4s6s4s",
        ARP_HTYPE_ETHERNET, ARP_PTYPE_IPV4, 6, 4, oper,
        mac_src, ip_src,   # remetente (quem "diz" possuir ip_src)
        mac_dst, ip_dst,   # alvo
    )
    return eth + arp


# ---- Camada de rede: IPv4 ---------------------------------------------------
def parse_ipv4(pkt):
    """Decodifica o cabecalho IPv4 (IHL trata o tamanho variavel).

    Retorna dict com versao, ihl, ttl, protocolo, IPs e o payload (segmento da
    camada de transporte). Retorna None se nao for IPv4 bem formado.
    """
    if len(pkt) < 20:
        return None
    primeiro = pkt[0]
    versao = primeiro >> 4
    ihl = (primeiro & 0x0F) * 4          # tamanho do cabecalho em bytes
    if versao != 4 or ihl < 20 or len(pkt) < ihl:
        return None
    total_len = struct.unpack("!H", pkt[2:4])[0]
    ttl = pkt[8]
    proto = pkt[9]
    ip_src = socket.inet_ntoa(pkt[12:16])
    ip_dst = socket.inet_ntoa(pkt[16:20])
    # O payload pode vir com padding do Ethernet; respeita total_len do IP.
    fim = total_len if 0 < total_len <= len(pkt) else len(pkt)
    return {
        "versao": versao, "ihl": ihl, "ttl": ttl, "protocolo": proto,
        "ip_src": ip_src, "ip_dst": ip_dst, "payload": pkt[ihl:fim],
    }


# ---- Camada de transporte: UDP ---------------------------------------------
def parse_udp(seg):
    """Decodifica o cabecalho UDP (8 bytes). Retorna portas, comprimento, dados."""
    if len(seg) < 8:
        return None
    sport, dport, length, _checksum = struct.unpack("!HHHH", seg[:8])
    return {"sport": sport, "dport": dport, "length": length, "dados": seg[8:]}


# ---- Camada de transporte: TCP ---------------------------------------------
def parse_tcp(seg):
    """Decodifica o cabecalho TCP (data offset variavel por causa das opcoes).

    Retorna portas, flags (byte e texto), numero de sequencia e o payload.
    """
    if len(seg) < 20:
        return None
    sport, dport, seq, ack = struct.unpack("!HHII", seg[:12])
    data_offset = (seg[12] >> 4) * 4
    flags = seg[13]
    if data_offset < 20 or len(seg) < data_offset:
        return None
    return {
        "sport": sport, "dport": dport, "seq": seq, "ack": ack,
        "flags": flags, "flags_txt": flags_tcp_texto(flags),
        "payload": seg[data_offset:],
    }


# ---- Camada de aplicacao: DNS (UDP/53) -------------------------------------
_DNS_TIPOS = {1: "A", 28: "AAAA", 5: "CNAME", 2: "NS", 15: "MX", 16: "TXT"}


def _ler_nome_dns(dados, offset):
    """Le um nome DNS a partir de offset, resolvendo compressao (ponteiros 0xC0).

    Retorna (nome_em_texto, proximo_offset_apos_o_nome_no_fluxo_principal).
    """
    labels = []
    pos = offset
    saltou = False
    fim_sequencial = offset
    protecao = 0
    while pos < len(dados):
        protecao += 1
        if protecao > 128:            # evita loop em pacote malformado
            break
        tam = dados[pos]
        if tam == 0:                  # fim do nome
            pos += 1
            if not saltou:
                fim_sequencial = pos
            break
        if (tam & 0xC0) == 0xC0:      # ponteiro de compressao (2 bytes)
            if pos + 1 >= len(dados):
                break
            ponteiro = ((tam & 0x3F) << 8) | dados[pos + 1]
            if not saltou:
                fim_sequencial = pos + 2
            saltou = True
            pos = ponteiro            # segue o ponteiro
            continue
        pos += 1
        labels.append(dados[pos:pos + tam].decode("ascii", "replace"))
        pos += tam
    nome = ".".join(labels)
    return nome, fim_sequencial


def parse_dns(dados):
    """Decodifica uma mensagem DNS (cabecalho de 12 bytes + secoes).

    Extrai o QNAME da primeira pergunta e, nas respostas, os registros A/AAAA.
    Retorna dict ou None. Interessa sobretudo o QNAME (dominio consultado) e o
    mapeamento dominio -> IPs para correlacionar com as conexoes web seguintes.
    """
    if len(dados) < 12:
        return None
    (tid, flags, qdcount, ancount,
     _nscount, _arcount) = struct.unpack("!HHHHHH", dados[:12])
    qr = (flags >> 15) & 1            # 0 = consulta, 1 = resposta
    off = 12
    perguntas = []
    for _ in range(qdcount):
        nome, off = _ler_nome_dns(dados, off)
        if off + 4 > len(dados):
            return None
        qtype, _qclass = struct.unpack("!HH", dados[off:off + 4])
        off += 4
        perguntas.append((nome, _DNS_TIPOS.get(qtype, str(qtype))))

    respostas = []
    for _ in range(ancount if qr else 0):
        _nome, off = _ler_nome_dns(dados, off)
        if off + 10 > len(dados):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", dados[off:off + 10])
        off += 10
        rdata = dados[off:off + rdlen]
        off += rdlen
        if rtype == 1 and len(rdata) == 4:        # A
            respostas.append(("A", socket.inet_ntoa(rdata)))
        elif rtype == 28 and len(rdata) == 16:    # AAAA
            respostas.append(("AAAA", socket.inet_ntop(socket.AF_INET6, rdata)))
    qname = perguntas[0][0] if perguntas else ""
    qtipo = perguntas[0][1] if perguntas else ""
    return {
        "id": tid, "resposta": bool(qr), "qname": qname, "qtype": qtipo,
        "respostas": respostas,
    }


# ---- Camada de aplicacao: HTTP em texto claro (TCP/80) ---------------------
_METODOS_HTTP = (b"GET", b"POST", b"PUT", b"DELETE", b"HEAD",
                 b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE")


def parse_http_request(payload):
    """Se o payload TCP comeca com uma requisicao HTTP, extrai metodo/Host/path.

    Retorna dict {metodo, caminho, host, user_agent, cookie} ou None. So olha o
    cabecalho (ate a linha em branco); nao reconstroi o corpo.
    """
    if not payload or not payload.startswith(_METODOS_HTTP):
        return None
    try:
        cabecalho = payload.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    except Exception:
        return None
    linhas = cabecalho.split("\r\n")
    primeira = linhas[0].split(" ")
    if len(primeira) < 2:
        return None
    metodo, caminho = primeira[0], primeira[1]
    host = user_agent = cookie = ""
    for linha in linhas[1:]:
        baixo = linha.lower()
        if baixo.startswith("host:"):
            host = linha.split(":", 1)[1].strip()
        elif baixo.startswith("user-agent:"):
            user_agent = linha.split(":", 1)[1].strip()
        elif baixo.startswith("cookie:"):
            cookie = linha.split(":", 1)[1].strip()
    return {"metodo": metodo, "caminho": caminho, "host": host,
            "user_agent": user_agent, "cookie": cookie}


# ---- Camada de aplicacao: TLS ClientHello -> SNI (TCP/443) -----------------
def extrair_sni(payload):
    """Extrai o Server Name Indication de um TLS ClientHello.

    Caminha pela estrutura do registro TLS ate a extensao server_name (0x0000),
    tudo na mao. Retorna o dominio (str) ou None se nao for um ClientHello com
    SNI. Referencia: estrutura TLS 1.2/1.3 do ClientHello (RFC 6066 para o SNI).

    Formato resumido percorrido:
      Record:    ContentType(1)=0x16 handshake | Versao(2) | Tamanho(2)
      Handshake: Tipo(1)=0x01 ClientHello | Tamanho(3)
                 Versao(2) | Random(32) | SessionID(1+n)
                 CipherSuites(2+n) | Compression(1+n)
                 Extensions(2+n): cada uma Tipo(2)|Tam(2)|Dados
      Ext 0x0000 server_name: ListLen(2) | Tipo(1)=0 | NomeLen(2) | nome
    """
    p = payload
    try:
        # Registro TLS
        if len(p) < 5 or p[0] != 0x16:            # 0x16 = handshake
            return None
        pos = 5                                   # pula ContentType+Versao+Tam
        # Handshake header
        if len(p) < pos + 4 or p[pos] != 0x01:    # 0x01 = ClientHello
            return None
        pos += 4                                  # pula Tipo(1) + Tamanho(3)
        pos += 2 + 32                             # versao (2) + random (32)
        if pos >= len(p):
            return None
        # Session ID
        sid_len = p[pos]
        pos += 1 + sid_len
        # Cipher suites
        if pos + 2 > len(p):
            return None
        cs_len = struct.unpack("!H", p[pos:pos + 2])[0]
        pos += 2 + cs_len
        # Compression methods
        if pos + 1 > len(p):
            return None
        comp_len = p[pos]
        pos += 1 + comp_len
        # Bloco de extensoes
        if pos + 2 > len(p):
            return None
        ext_total = struct.unpack("!H", p[pos:pos + 2])[0]
        pos += 2
        fim_ext = min(pos + ext_total, len(p))
        while pos + 4 <= fim_ext:
            ext_tipo, ext_len = struct.unpack("!HH", p[pos:pos + 4])
            pos += 4
            corpo = p[pos:pos + ext_len]
            pos += ext_len
            if ext_tipo == 0x0000:                # extensao server_name
                if len(corpo) < 5:
                    return None
                # ServerNameList: tam(2) | tipo(1)=0 host | tam(2) | nome
                nome_tipo = corpo[2]
                nome_len = struct.unpack("!H", corpo[3:5])[0]
                if nome_tipo != 0:
                    return None
                nome = corpo[5:5 + nome_len]
                return nome.decode("ascii", "replace") or None
    except Exception:
        return None
    return None
