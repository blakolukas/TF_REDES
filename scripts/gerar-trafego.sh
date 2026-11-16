#!/bin/sh
set -eu

# Gerador de trafego da VITIMA (roda dentro do container vitima).
# Cada acesso dispara: consulta DNS (UDP/53) -> conexao TCP -> HTTP ou TLS.
# Com o atacante no caminho, tudo isso aparece no sniffer e no Wireshark.
#
# Uso:  gerar-trafego [tudo|http|https|dns|doh]

DOH_URL="https://172.10.30.10:8443/dns-query"
PAUSA=1

acesso() {           # acesso <url> [flags extras do curl]
  url=$1; shift
  echo ">>> curl $* $url"
  curl -s -o /dev/null -w '    HTTP %{http_code}  %{size_download} bytes  (%{remote_ip})\n' \
       --connect-timeout 5 "$@" "$url" || echo "    (falha/timeout -- esperado se ip_forward=0)"
  sleep "$PAUSA"
}

bloco_http() {
  echo "== Experimento 1: HTTP em texto claro =="
  acesso "http://site-http.lab/login?user=alice"
  acesso "http://site-http.lab/painel/segredo"
}

bloco_https() {
  echo "== Experimento 1/2: HTTPS (so o SNI vaza) =="
  acesso "https://site-seguro.lab/" -k
}

bloco_dns() {
  echo "== Experimento 2: 4 dominios distintos (DNS -> TLS SNI) =="
  for dom in loja.lab banco.lab noticias.lab video.lab; do
    acesso "https://$dom/" -k
  done
}

bloco_doh() {
  echo "== Experimento 2 (DoH): a consulta DNS some do UDP/53, o SNI permanece =="
  # Com --doh-url, a resolucao vai cifrada por HTTPS; o sniffer nao ve mais a
  # consulta em UDP/53, mas o ClientHello para loja.lab ainda expoe o SNI.
  acesso "https://loja.lab/" -k --doh-url "$DOH_URL" --doh-insecure
}

case "${1:-tudo}" in
  http)  bloco_http ;;
  https) bloco_https ;;
  dns)   bloco_dns ;;
  doh)   bloco_doh ;;
  tudo)  bloco_http; bloco_https; bloco_dns; bloco_doh ;;
  *) echo "Uso: gerar-trafego [tudo|http|https|dns|doh]" >&2; exit 2 ;;
esac
echo "== fim do trafego =="
