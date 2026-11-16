#!/bin/sh
set -eu

# IPs fixos do laboratorio (ver compose.yaml)
GATEWAY_IP=172.10.20.1
DNS_IP=172.10.30.10

# 1) Rota default pelo GATEWAY do laboratorio (e nao pela bridge do Podman),
#    para que o trafego ate os servidores atravesse a rede_lab.
ip route replace default via "$GATEWAY_IP" 2>/dev/null || \
  echo "[vitima] aviso: nao consegui ajustar a rota default" >&2

# 2) DNS do laboratorio (servidor .lab nos SERVIDORES).
printf 'nameserver %s\n' "$DNS_IP" > /etc/resolv.conf 2>/dev/null || \
  echo "[vitima] aviso: nao consegui ajustar o resolv.conf" >&2

echo "[vitima] pronta. rota default via $GATEWAY_IP, DNS $DNS_IP"
echo "[vitima] gere trafego com: gerar-trafego   (ou curl manual)"
exec sleep infinity
