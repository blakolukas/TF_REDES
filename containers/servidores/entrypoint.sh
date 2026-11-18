#!/bin/sh
set -eu

MEU_IP=172.10.30.10
CERT_DIR=/lab/servidores/certs
mkdir -p "$CERT_DIR"

# 1) Certificado self-signed curinga para *.lab (cobre loja.lab, banco.lab, ...).
#    O SNI que a vitima envia no ClientHello independe da validacao do cert, mas
#    um cert valido deixa a resposta HTTPS limpa.
if [ ! -f "$CERT_DIR/cert.pem" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" \
    -subj "/CN=*.lab" \
    -addext "subjectAltName=DNS:*.lab,DNS:lab,DNS:dns.lab,IP:${MEU_IP}" \
    >/dev/null 2>&1
  echo "[servidores] certificado *.lab gerado em $CERT_DIR"
fi

# 2) DNS: depende do modo escolhido no `lab.sh up`.
#    - servidor (autocontido): QUALQUER dominio resolve para este host.
#    - internet (hibrido): so *.lab resolve aqui; o resto e encaminhado a um
#      resolvedor real (este container alcanca 1.1.1.1 pela rota default do Podman).
MODO="${MODO_GATEWAY:-servidor}"
if [ "$MODO" = "internet" ]; then
  cat > /etc/dnsmasq.conf <<EOF
no-resolv
no-hosts
log-queries
address=/lab/${MEU_IP}
server=1.1.1.1
server=8.8.8.8
EOF
  echo "[servidores] dnsmasq no ar (modo internet): *.lab -> ${MEU_IP}, resto -> 1.1.1.1/8.8.8.8"
else
  cat > /etc/dnsmasq.conf <<EOF
no-resolv
no-hosts
log-queries
address=/#/${MEU_IP}
EOF
  echo "[servidores] dnsmasq no ar (modo servidor): qualquer dominio -> ${MEU_IP}"
fi
dnsmasq --keep-in-foreground &

# 3) HTTP (80), HTTPS (443) e DoH (8443) num unico processo Python (stdlib).
echo "[servidores] subindo HTTP/HTTPS/DoH..."
exec python3 /lab/servidores/web.py --cert "$CERT_DIR/cert.pem" --key "$CERT_DIR/key.pem"
