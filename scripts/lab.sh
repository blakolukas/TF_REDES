#!/usr/bin/env bash
set -Eeuo pipefail

# Orquestrador do laboratorio do Trabalho Final (MITM / ARP Spoofing).
# Topologia fixa de 4 containers em 2 redes (ver compose.yaml): vitima,
# atacante, gateway e servidores.

export PODMAN_COMPOSE_WARNING_LOGS=false

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
COMPOSE=(podman compose -f "$ROOT_DIR/compose.yaml")
MONITOR_CONTAINER=atacante
CONTAINERS=(vitima atacante gateway servidores)

usage() {
  cat <<'EOF'
Uso: ./scripts/lab.sh COMANDO [argumentos]

  build                         Constroi as 4 imagens
  up                            Sobe o lab; pergunta se o gateway fala com os
                                servidores do lab (autocontido) ou com a internet
  down                          Encerra o laboratorio e remove as redes
  status                        Mostra os containers e a captura
  shell NOME                    Abre terminal em vitima|atacante|gateway|servidores
  trafego [tudo|lab|web|http|https|dns|doh]
                                Gera trafego na vitima (atalho p/ gerar-trafego).
                                'tudo' segue o modo: servidor=>.lab, internet=>web.
                                'lab' = so .lab ; 'web' = so sites reais.
  capture start [arq.pcapng]|stop|status
                                Controla a captura de evidencia (dumpcap no atacante)

Exemplos:
  ./scripts/lab.sh up                    # pergunta: servidores do lab ou internet
  MODO_GATEWAY=internet ./scripts/lab.sh up   # sobe direto no modo internet
  ./scripts/lab.sh shell atacante        # e la: python3 /lab/src/mitm.py --iface eth0
  ./scripts/lab.sh capture start captura_auditoria.pcapng
  ./scripts/lab.sh trafego tudo
EOF
}

compose() { "${COMPOSE[@]}" "$@"; }

# Pergunta com quem o GATEWAY deve falar (upstream da rede). Escreve o MENU no
# stderr e devolve SO o valor escolhido no stdout, para poder ser capturado por
# $(...). Respeita MODO_GATEWAY ja definido no ambiente e cai em 'servidor'
# quando nao ha terminal (execucao nao interativa).
escolher_modo_gateway() {
  if [[ -n "${MODO_GATEWAY:-}" ]]; then
    printf '%s' "$MODO_GATEWAY"; return
  fi
  if [[ ! -t 0 ]]; then
    printf 'servidor'; return
  fi
  {
    echo
    echo "Com quem o GATEWAY deve falar (para onde o trafego da vitima vai)?"
    echo "  [1] Servidores do lab   (autocontido / Cenario A: tudo .lab, sem internet)"
    echo "  [2] Internet real       (hibrido: *.lab continua local, o resto vai pra web)"
  } >&2
  printf 'Escolha [1]: ' >&2
  local escolha
  read -r escolha || escolha=1
  case "$escolha" in
    2|internet|Internet|INTERNET) printf 'internet' ;;
    *) printf 'servidor' ;;
  esac
}

# No macOS/Windows o Podman roda numa VM Linux que precisa estar ligada. Um
# reinicio da maquina a desliga; este check troca o erro cru do Podman por uma
# instrucao clara.
check_podman() {
  if ! podman info >/dev/null 2>&1; then
    cat >&2 <<'EOF'
Nao consegui falar com o Podman. No macOS/Windows a VM Linux do Podman precisa
estar ligada. Rode:

  podman machine start          # se disser que nao existe maquina:
  podman machine init && podman machine start

Confira com 'podman machine list' e repita: ./scripts/lab.sh up
EOF
    exit 1
  fi
}

build_images() {
  compose build
}

require_container() {
  local c=$1
  if [[ "$(podman inspect -f '{{.State.Running}}' "$c" 2>/dev/null || true)" != true ]]; then
    echo "O container $c nao esta ativo. Rode: ./scripts/lab.sh up" >&2
    exit 1
  fi
}

comando=${1:-help}
case "$comando" in
  build)
    check_podman
    build_images
    ;;
  up)
    check_podman
    MODO_GATEWAY=$(escolher_modo_gateway)
    export MODO_GATEWAY
    echo "[lab] gateway -> ${MODO_GATEWAY} (ex.: MODO_GATEWAY=internet ./scripts/lab.sh up pula a pergunta)"
    compose up -d --build
    echo
    echo "Ambiente no ar (gateway em modo '${MODO_GATEWAY}'). Wireshark do atacante em http://127.0.0.1:6080/"
    echo "Proximo passo: ./scripts/lab.sh shell atacante"
    ;;
  down)
    compose down || echo "Aviso: compose down nao concluiu a limpeza; seguindo." >&2
    for c in "${CONTAINERS[@]}"; do
      podman container exists "$c" 2>/dev/null && podman rm -f "$c" >/dev/null || true
    done
    for n in mitm_rede_lab mitm_rede_externa; do
      podman network exists "$n" 2>/dev/null && \
        { podman network rm "$n" >/dev/null 2>&1 || podman network rm -f "$n" >/dev/null 2>&1 || true; }
    done
    echo "Laboratorio encerrado."
    ;;
  status)
    compose ps || true
    if podman inspect "$MONITOR_CONTAINER" >/dev/null 2>&1; then
      echo; podman exec "$MONITOR_CONTAINER" capture status 2>/dev/null || true
    fi
    ;;
  shell)
    alvo=${2:-}
    case "$alvo" in
      vitima|atacante|gateway|servidores)
        require_container "$alvo"; podman exec -it "$alvo" /bin/bash 2>/dev/null \
          || podman exec -it "$alvo" /bin/sh ;;
      *) echo "Escolha: vitima | atacante | gateway | servidores" >&2; exit 2 ;;
    esac
    ;;
  trafego)
    require_container vitima
    podman exec vitima gerar-trafego "${2:-tudo}"
    ;;
  capture)
    require_container "$MONITOR_CONTAINER"
    acao=${2:-status}
    if [[ "$acao" == start ]]; then
      nome=${3:-captura_auditoria.pcapng}
      podman exec "$MONITOR_CONTAINER" capture start "$nome"
    else
      podman exec "$MONITOR_CONTAINER" capture "$acao"
    fi
    ;;
  help|-h|--help)
    usage ;;
  *)
    usage >&2; exit 2 ;;
esac
