#!/usr/bin/env python3
"""Servidores web do laboratorio: HTTP (80), HTTPS (443) e DoH (8443).

Faz parte da INFRAESTRUTURA do lab (o "site" que a vitima acessa), nao da
aplicacao de ataque -- por isso pode usar a stdlib de rede a vontade. Serve so
para dar a vitima um destino deterministico e isolado.

- HTTP/80  : pagina em texto claro; expoe metodo, caminho, Host, cookies ao MITM.
- HTTPS/443: mesma pagina sobre TLS; o atacante so consegue ver o SNI.
- DoH/8443 : endpoint DNS-over-HTTPS (RFC 8484) que repassa a consulta ao dnsmasq
             local. Usado no Experimento 2 para mostrar que, com DoH, a consulta
             UDP/53 some do sniffer, mas o SNI continua exposto.
"""
import argparse
import base64
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGINA = """<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><title>{host}</title></head>
<body>
  <h1>Site do laboratorio: {host}</h1>
  <p>Voce acessou <code>{caminho}</code> via <b>{esquema}</b>.</p>
  <p>SEGREDO-DEMO: FLAG{{metadados-vazam-mesmo-sem-ler-o-conteudo}}</p>
</body></html>
"""


class Handler(BaseHTTPRequestHandler):
    esquema = "HTTP"
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass  # silencia o log padrao

    def _pagina(self):
        host = self.headers.get("Host", "desconhecido")
        corpo = PAGINA.format(host=host, caminho=self.path,
                              esquema=self.esquema).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(corpo)))
        self.end_headers()
        self.wfile.write(corpo)

    def do_GET(self):
        if self.path.startswith("/dns-query"):
            return self._doh_get()
        self._pagina()

    def do_POST(self):
        if self.path.startswith("/dns-query"):
            return self._doh_post()
        self._pagina()

    # ---- DoH: repassa o wireformat DNS para o dnsmasq local (127.0.0.1:53) ----
    def _resolver(self, consulta):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        try:
            s.sendto(consulta, ("127.0.0.1", 53))
            resposta, _ = s.recvfrom(4096)
            return resposta
        finally:
            s.close()

    def _responder_dns(self, resposta):
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.send_header("Content-Length", str(len(resposta)))
        self.end_headers()
        self.wfile.write(resposta)

    def _doh_get(self):
        from urllib.parse import urlparse, parse_qs
        q = parse_qs(urlparse(self.path).query)
        dns_b64 = q.get("dns", [""])[0]
        pad = "=" * (-len(dns_b64) % 4)
        consulta = base64.urlsafe_b64decode(dns_b64 + pad)
        self._responder_dns(self._resolver(consulta))

    def _doh_post(self):
        n = int(self.headers.get("Content-Length", 0))
        consulta = self.rfile.read(n)
        self._responder_dns(self._resolver(consulta))


class HandlerHTTPS(Handler):
    esquema = "HTTPS"


def servir(porta, handler, contexto=None):
    srv = ThreadingHTTPServer(("0.0.0.0", porta), handler)
    if contexto:
        srv.socket = contexto.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--cert", required=True)
    p.add_argument("--key", required=True)
    args = p.parse_args()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(args.cert, args.key)

    alvos = [
        (80, Handler, None),
        (443, HandlerHTTPS, ctx),
        (8443, HandlerHTTPS, ctx),   # DoH sobre HTTPS
    ]
    threads = []
    for porta, handler, contexto in alvos:
        t = threading.Thread(target=servir, args=(porta, handler, contexto),
                             daemon=True)
        t.start()
        threads.append(t)
    print("[servidores] HTTP:80  HTTPS:443  DoH:8443  prontos.", flush=True)
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
