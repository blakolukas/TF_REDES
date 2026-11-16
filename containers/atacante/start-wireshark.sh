#!/bin/sh
set -eu

# Abre o Wireshark ja capturando na interface do laboratorio. O filtro de
# captura 'ip or arp' guarda o trafego IP (DNS/HTTP/TLS) e tambem os quadros ARP
# forjados, que sao a propria evidencia do envenenamento.
#
# Observacoes de robustez (evitam a "tela preta" no noVNC):
#   - espera o socket do X (:0) existir antes de abrir a GUI;
#   - QT_X11_NO_MITSHM/ QT_QPA_PLATFORM sao exportados pelo supervisord e
#     impedem o Qt de desenhar preto sobre o VNC;
#   - qualquer falha e impressa no log do container (podman logs atacante).

log() { echo "[start-wireshark] $*" >&2; }

# 1) Espera o servidor X subir.
log "aguardando o servidor X (:0)..."
i=0
while [ ! -S /tmp/.X11-unix/X0 ]; do
  sleep 0.2
  i=$((i + 1))
  if [ "$i" -gt 150 ]; then   # ~30s
    log "ERRO: o servidor X (:0) nao subiu. Veja o log do Xvfb."
    exit 1
  fi
done

# 2) Confere a interface de captura.
IFACE=${CAPTURE_IFACE:-eth0}
if ! ip link show dev "$IFACE" >/dev/null 2>&1; then
  log "ERRO: interface '$IFACE' nao existe. Interfaces disponiveis:"
  ip -o link show 2>&1 | sed 's/^/[start-wireshark]   /' >&2 || true
  exit 1
fi

ip link set dev "$IFACE" promisc on 2>/dev/null || true

export DISPLAY=:0
log "abrindo Wireshark em '$IFACE' (filtro de captura: ip or arp)"
exec wireshark -k -i "$IFACE" -f 'arp or (ip and not port 6080)'
