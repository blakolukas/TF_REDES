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
REDE_EXTERNA=172.10.30.0/24

ip route replace "$REDE_EXTERNA" via "$GATEWAY_LAB" 2>/dev/null \
  && echo "[atacante] rota $REDE_EXTERNA via $GATEWAY_LAB (gateway do lab) ok" \
  || echo "[atacante] aviso: nao consegui ajustar a rota para $REDE_EXTERNA" >&2

exec /usr/bin/supervisord -n -c /etc/supervisor/supervisord.conf
