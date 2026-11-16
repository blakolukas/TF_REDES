#!/bin/sh
set -eu

# Grava a captura de evidencia (captura_auditoria.pcapng) com dumpcap na
# interface do atacante. Guarda IP e ARP para comprovar tanto o trafego
# interceptado quanto os quadros ARP forjados.
PID_FILE=/run/lab-dumpcap.pid

client_interface() {
  printf '%s\n' "${CAPTURE_IFACE:-eth0}"
}

case "${1:-}" in
  start)
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
      echo "Ja existe uma captura ativa" >&2
      exit 1
    fi
    RELATIVE_PATH=${2:-captura_auditoria.pcapng}
    case "$RELATIVE_PATH" in
      /*|*..*) echo "Caminho de captura invalido" >&2; exit 2 ;;
    esac
    OUTPUT="/lab/resultados/$RELATIVE_PATH"
    mkdir -p "$(dirname "$OUTPUT")"
    IFACE=$(client_interface)
    ip link set dev "$IFACE" promisc on 2>/dev/null || true
    LOG="${OUTPUT%.pcapng}.dumpcap.log"
    nohup dumpcap -q -i "$IFACE" -f 'arp or (ip and not port 6080)' -w "$OUTPUT" </dev/null >"$LOG" 2>&1 &
    PID=$!
    echo "$PID" > "$PID_FILE"
    sleep 0.5
    if ! kill -0 "$PID" 2>/dev/null; then
      cat "$LOG" >&2 || true
      rm -f "$PID_FILE"
      exit 1
    fi
    echo "Captura iniciada em $OUTPUT pela interface $IFACE"
    ;;
  stop)
    if [ -f "$PID_FILE" ]; then
      PID=$(cat "$PID_FILE")
      kill -INT "$PID" 2>/dev/null || true
      while kill -0 "$PID" 2>/dev/null; do sleep 0.1; done
      rm -f "$PID_FILE"
      echo "Captura encerrada"
    else
      echo "Nenhuma captura ativa"
    fi
    ;;
  status)
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
      echo "Captura ativa (PID $(cat "$PID_FILE"))"
    else
      echo "Nenhuma captura ativa"
    fi
    ;;
  *)
    echo "Uso: capture start [arquivo-relativo.pcapng]|stop|status" >&2
    exit 2
    ;;
esac
