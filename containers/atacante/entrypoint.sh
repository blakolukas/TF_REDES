#!/bin/sh
set -eu
# ---------------------------------------------------------------------------
# A ponte do Podman injeta 172.10.20.253 como gateway default de TODO container.
# Mas o trafego que o ATACANTE reencaminha (MITM) precisa sair pelo gateway DO
# LAB (172.10.20.1) -- o unico no que conhece a rede_externa (172.10.30.0/24),
# onde ficam os servidores. Sem esta rota, o kernel entrega os pacotes
# reencaminhados a ponte do Podman, que nao roteia para a rede_externa, e eles
# morrem: DNS sem resposta e SYN para :443/:8443 sem SYN-ACK (o "blackhole").
# ---------------------------------------------------------------------------
GATEWAY_LAB=172.10.20.1
VITIMA_LAB=172.10.20.2
REDE_EXTERNA=172.10.30.0/24
TABELA_VITIMA=100

ip route replace "$REDE_EXTERNA" via "$GATEWAY_LAB" 2>/dev/null \
  && echo "[atacante] rota $REDE_EXTERNA via $GATEWAY_LAB (gateway do lab) ok" \
  || echo "[atacante] aviso: nao consegui ajustar a rota para $REDE_EXTERNA" >&2

# Modo internet: o trafego externo reencaminhado da vitima precisa sair PELO
# gateway do lab (172.10.20.1), nao pela ponte do Podman -- assim ele volta pelo
# gateway (cuja cache ARP esta envenenada) e o atacante captura IDA e VOLTA,
# mantendo a topologia vitima -> atacante -> gateway -> internet.
#
# IMPORTANTE: NAO trocamos a rota default principal. A ponte do Podman usa a
# default para devolver o encaminhamento de portas do host (o noVNC/Wireshark em
# 127.0.0.1:6080). Entao usamos ROTEAMENTO POR POLITICA: so o trafego ORIGINADO
# pela vitima vai para o gateway (tabela $TABELA_VITIMA); o trafego do proprio
# atacante (inclusive as respostas do 6080) continua na default do Podman.
if [ "${MODO_GATEWAY:-servidor}" = "internet" ]; then
  if ip route replace default via "$GATEWAY_LAB" table "$TABELA_VITIMA" 2>/dev/null \
     && ip rule add from "$VITIMA_LAB" lookup "$TABELA_VITIMA" 2>/dev/null; then
    echo "[atacante] modo internet: trafego da vitima ($VITIMA_LAB) via $GATEWAY_LAB (tabela $TABELA_VITIMA)"
  else
    echo "[atacante] aviso: nao consegui aplicar o roteamento por politica da vitima" >&2
  fi
fi

exec /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf
