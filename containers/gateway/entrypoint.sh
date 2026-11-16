#!/bin/sh
# Sem 'set -e'. IMPORTANTE: nao escrevemos em /proc/sys aqui -- o Podman monta
# /proc/sys como somente-leitura no container, e no /bin/sh (dash) um '>' que
# falha MATA o script. O ip_forward ja e ligado na criacao do container pelo
# compose.yaml (sysctls); aqui so confirmamos e configuramos o NAT (iptables
# funciona com CAP_NET_ADMIN, sem depender de /proc).
set -u

# Descobre qual interface esta em cada rede (a ordem eth0/eth1 nao e garantida):
#   rede_lab     172.10.20.0/24  -> lado da vitima/atacante
#   rede_externa 172.10.30.0/24  -> lado dos servidores
IFACE_LAN=""
IFACE_EXT=""
for IFACE in $(ls /sys/class/net | grep -v lo); do
  ADDR=$(ip -o -4 addr show dev "$IFACE" 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
  case "$ADDR" in
    172.10.20.*) IFACE_LAN="$IFACE" ;;
    172.10.30.*) IFACE_EXT="$IFACE" ;;
  esac
done
echo "[gateway] LAN=$IFACE_LAN  EXT=$IFACE_EXT"
echo "[gateway] ip_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null) (definido pelo compose)"

# NAT na saida para a rede externa (os servidores respondem ao gateway).
if [ -n "$IFACE_EXT" ]; then
  if iptables -t nat -A POSTROUTING -o "$IFACE_EXT" -j MASQUERADE 2>/dev/null; then
    echo "[gateway] NAT (MASQUERADE) em $IFACE_EXT"
  else
    echo "[gateway] AVISO: iptables NAT falhou"
  fi
fi
iptables -P FORWARD ACCEPT 2>/dev/null || true

echo "[gateway] pronto; mantendo o container ativo"
exec sleep infinity
