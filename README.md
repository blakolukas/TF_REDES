# Trabalho Final — Man-in-the-Middle com ARP Spoofing

Laboratório de Redes (PUCRS, 2026/2). A máquina **atacante** se posiciona entre a
**vítima** e o **gateway** da rede local via **ARP Spoofing**, mantém o
encaminhamento transparente (`ip_forward`) e **audita os metadados** do tráfego
web: DNS em claro (UDP/53), HTTP (TCP/80) e o domínio vazado pelo **SNI** do
HTTPS (TCP/443).

Toda a manipulação de pacotes é feita com **raw sockets** (`AF_PACKET`) e
decodificação própria byte a byte — **sem** Scapy, arpspoof, ettercap ou
libpcap/tcpdump, como exige o enunciado. Só usa a **biblioteca padrão do Python 3**.

> ⚠️ **ARP Spoofing 100% isolado.** O envenenamento acontece só na `rede_lab`
> privada dos contêineres — nunca numa rede real (fazer isso em rede de terceiros
> é crime, Seção 10 do enunciado). O lab roda offline por padrão; opcionalmente o
> gateway pode encaminhar para a internet real (veja [Modos do gateway](#modos-do-gateway)),
> sem jamais forjar nada fora da bridge privada.

📖 Conceitos e arquitetura interna: [`docs/arquitetura.md`](docs/arquitetura.md) ·
Experimentos e relatório: [`docs/relatorio.md`](docs/relatorio.md)

---

## 🚀 Início rápido

### Pré-requisito (só na primeira vez)

O Podman precisa rodar em **modo rootful** — sem isso o `gateway` não sobe e a
varredura ARP não acha ninguém. No **macOS/Windows** o Podman roda numa VM Linux;
rode os comandos abaixo, um a um (no **Linux nativo**, pule isto e use `sudo`).

Cria a VM (só se você nunca criou):

```bash
podman machine init
```

Para a VM para poder trocar o modo:

```bash
podman machine stop
```

Habilita o modo rootful:

```bash
podman machine set --rootful
```

Liga a VM:

```bash
podman machine start
```

Fica salvo. Nas próximas sessões basta `podman machine start` (reiniciar o PC desliga a VM).

### Rodar o lab

Use **2 terminais no Mac**, na raiz do projeto.

**Terminal 1** — sobe os 4 contêineres:

```bash
./scripts/lab.sh up
```

Ele pergunta **com quem o gateway deve falar** (veja [Modos do gateway](#modos-do-gateway)):

```
Com quem o GATEWAY deve falar (para onde o trafego da vitima vai)?
  [1] Servidores do lab   (autocontido / Cenario A: tudo .lab, sem internet)
  [2] Internet real       (hibrido: *.lab continua local, o resto vai pra web)
Escolha [1]:
```

Para pular a pergunta: `MODO_GATEWAY=internet ./scripts/lab.sh up`.

Confira que subiram `vitima`, `atacante`, `gateway` e `servidores` (todos `Up`):

```bash
podman ps
```

**Terminal 2** — entra no atacante (o prompt vira `root@...:/lab#`):

```bash
./scripts/lab.sh shell atacante
```

Já **dentro do contêiner**, inicia o ataque:

```bash
python3 /lab/src/mitm.py --iface eth0 --vitima 172.10.20.2 --gateway 172.10.20.1
```

Ele pergunta se deve **encaminhar os pacotes** (MITM transparente, padrão) ou não
(blackhole do Experimento 3). Para não ser perguntado, passe `--forward` ou
`--sem-forward`.

**Terminal 1** — começa a captura da evidência:

```bash
./scripts/lab.sh capture start captura_auditoria.pcapng
```

Gera o tráfego na vítima (veja o painel reagir no Terminal 2). Escolha uma opção:

**Tudo** — segue o modo (`servidor` → `.lab`, `internet` → sites reais):

```bash
./scripts/lab.sh trafego tudo
```

**Só os servidores `.lab`** (fictícios):

```bash
./scripts/lab.sh trafego lab
```

**Só sites reais** (requer modo `internet`):

```bash
./scripts/lab.sh trafego web
```

**HTTP em texto claro** — Experimento 1 (`site-http.lab`):

```bash
./scripts/lab.sh trafego http
```

**HTTPS / SNI** — Experimento 1 (`site-seguro.lab`):

```bash
./scripts/lab.sh trafego https
```

**DNS → SNI** — Experimento 2 (4 domínios `.lab`):

```bash
./scripts/lab.sh trafego dns
```

**DoH** — Experimento 2 (a consulta UDP/53 some, o SNI permanece):

```bash
./scripts/lab.sh trafego doh
```

Fecha o `.pcapng` em `resultados/`:

```bash
./scripts/lab.sh capture stop
```

### Encerrar

No **Terminal 2** (dentro do atacante), `Ctrl-C` restaura as caches ARP e o `ip_forward`. Depois, no **Terminal 1**:

```bash
./scripts/lab.sh down
```

**Onde cada comando roda — a regra de ouro:**

| Comando | Onde |
|---|---|
| `./scripts/lab.sh ...` (`up`/`down`/`shell`/`capture`/`trafego`) | sempre **no Mac** |
| `python3 /lab/src/mitm.py ...` | **dentro do atacante** (depois do `shell atacante`) |

🔍 **Wireshark no navegador:** <http://127.0.0.1:6080/> — abre o Wireshark do
atacante já capturando em `eth0` (filtro `ip or arp`). A evidência em `.pcapng`
**não depende** dessa aba: quem grava é o `capture start`.

---

## Topologia

<p align="center">
  <img src="docs/topologia.svg" alt="Topologia do Trabalho Final" width="820">
</p>

```
  rede_lab — 172.10.20.0/24                      rede_externa — 172.10.30.0/24
 ┌───────────────────────────────────┐          ┌────────────────────────────┐
 │  vitima .20.2 ──rota default──┐    │          │                            │
 │                               ▼    │          │                            │
 │  atacante .20.254 ◄══ARP══► gateway .20.1 / .30.1 ──NAT──► servidores .30.10│
 │     (mitm.py)                 │    │          │   DNS · HTTP · HTTPS · DoH  │
 └──────────────────────────────┼────┘          └────────────────────────────┘
                                 └── NAT (só no modo internet) ──►  🌐 Internet real
```

| Papel | Contêiner | IP | Programa |
|---|---|---|---|
| Vítima | `vitima` | 172.10.20.2 | gera tráfego (`curl`) |
| Atacante (MITM) | `atacante` | 172.10.20.254 | `src/mitm.py` + Wireshark |
| Gateway | `gateway` | 172.10.20.1 / 172.10.30.1 | roteamento (`ip_forward` + NAT) |
| Servidores | `servidores` | 172.10.30.10 | DNS + HTTP + HTTPS(SNI) + DoH |

A vítima roteia pelo gateway; o atacante, na mesma `rede_lab`, envenena as caches
ARP da vítima e do gateway para entrar no caminho em nível 2 e enxergar todo o
tráfego dela. Os servidores ficam **depois** do gateway de propósito — é o que dá
sentido ao Experimento 3 (sem encaminhamento, o tráfego da vítima não chega lá).
No modo **servidor** todos os domínios resolvem para `172.10.30.10` (diferenciados
pelo Host/SNI); no modo **internet** só os `*.lab` ficam nesse IP e o resto vai
para a web real (veja [Modos do gateway](#modos-do-gateway)).

---

## Modos do gateway

Ao subir (`./scripts/lab.sh up`), você escolhe **para onde o gateway encaminha o
tráfego da vítima**. Isso casa com a própria topologia do enunciado (§2.1): o
gateway encaminha "para a Internet **ou para o restante da rede**".

| Modo | DNS | Para onde vai o tráfego | Quando usar |
|---|---|---|---|
| **servidor** (padrão) | tudo → `172.10.30.10` | só os servidores `.lab` do lab | Cenário A autocontido. Determinístico e offline — ideal para a **demo ao vivo** e para o **Experimento 1** (HTTP em claro só existe no `site-http.lab`). |
| **internet** (híbrido) | `*.lab` → `172.10.30.10`; resto → `1.1.1.1` | `.lab` local **+** sites reais na web | **Experimento 2** com sites de verdade (`trafego tudo` → só web nesse modo): DNS→IP→SNI reais. O `site-http.lab` continua resolvendo p/ o Experimento 1 (`trafego http`). |

O modo **internet** mantém o `site-http.lab` local (o único HTTP em texto claro,
porque na web real quase tudo é HTTPS) e ainda deixa a vítima navegar em sites
reais. A escolha "ou um ou outro" seria pior: perderia o Experimento 1.

> ⚠️ **O ARP Spoofing continua 100% dentro da `rede_lab` privada** nos dois modos
> — o atacante nunca forja nada na rede real. No modo internet, só o gateway/os
> servidores fazem conexões de saída normais (como qualquer contêiner). A proibição
> do enunciado (Seção 10) é sobre *spoofar redes de terceiros*, o que não acontece aqui.

---

## A aplicação (`src/mitm.py`)

1. **Descoberta** — varredura ARP lista os nós ativos (IP/MAC) e seleciona vítima e gateway.
2. **Envenenamento bidirecional** — `ARP Reply` forjados periódicos enganam vítima e gateway.
3. **Encaminhamento** — mantém `ip_forward=1` para a vítima não perder conexão.
4. **Captura e decodificação** — raw socket desmonta Ethernet/IPv4/UDP/TCP e extrai DNS (QNAME), HTTP (método/Host/URI) e SNI (TLS `ClientHello`).
5. **Persistência + painel** — grava `captura_*.log` e `resumo_*.csv` e mostra um painel em tempo real.
6. **Self-healing** — no `Ctrl-C`, restaura as caches ARP verdadeiras e o `ip_forward`.

Sem `--vitima/--gateway`, o programa varre a rede e pergunta os alvos. Threads,
filas e sincronização estão em [`docs/arquitetura.md`](docs/arquitetura.md).

---

## Os três experimentos

A vítima gera o tráfego via `./scripts/lab.sh trafego ...` (no Mac). Detalhes e o
que apresentar: [`docs/relatorio.md`](docs/relatorio.md).

| # | Comando | O que demonstra |
|---|---|---|
| 1 | `trafego http` e `trafego https` | HTTP expõe tudo (método, URI, cookies); HTTPS só o SNI |
| 2 | `trafego dns` e depois `trafego doh` | correlação DNS→SNI; com DoH a consulta UDP/53 some, mas o SNI continua exposto |
| 3 | no atacante: responda **n** à pergunta do `mitm.py` (ou `echo 0 > /proc/sys/net/ipv4/ip_forward`) | a espionagem vira blackhole (a vítima perde conexão) |

O `trafego tudo` **segue o modo** e nunca mistura os dois mundos: em **servidor**
gera só os `.lab`; em **internet** gera só sites reais (google, wikipedia, github,
cloudflare) — DNS, IP e SNI de verdade para o Experimento 2. Alvos explícitos:
`trafego lab` (só `.lab`) e `trafego web` (só web). Para o **Experimento 1 em modo
internet**, use `trafego http` — o `site-http.lab` continua resolvendo localmente
(HTTP em claro só existe no lab; na web real quase tudo é HTTPS).

O Experimento 3 agora pode ser escolhido já na partida: o `mitm.py` **pergunta** se
deve encaminhar (responda **n** para o blackhole), ou passe `--sem-forward`. Para
ligar/desligar com o ataque já rodando, use `echo 0`/`echo 1 > /proc/sys/net/ipv4/ip_forward`.

---

## Conferir a evidência

- **Gerada pelo programa** (`resultados/`): `captura_*.log` (um evento por linha) e `resumo_*.csv` (destinos consolidados: domínio, IP, protocolos, bytes).
- **Captura do Wireshark:** `resultados/captura_auditoria.pcapng`. Abra em <http://127.0.0.1:6080/> ou no Wireshark do seu Mac. Filtros úteis: `arp`, `dns`, `http`, `tls.handshake.type == 1`.

**Testar sem subir o lab** (offline, sem root/rede/contêineres):

```bash
python3 scripts/autoteste.py
```

Valida os parsers (Ethernet/ARP/IPv4/UDP/TCP/DNS/HTTP/SNI) e gera exemplos em
`resultados/captura_exemplo-autoteste.log` e `resumo_exemplo-autoteste.csv`.

---

## 🛠️ Se der problema

| Sintoma | Causa | Solução |
|---|---|---|
| `Cannot connect to Podman... connection refused` | VM do Podman desligada (reiniciar o PC desliga). | `podman machine start` e repita. |
| `podman ps` mostra só 3 contêineres (falta `gateway`); `ping 172.10.20.1` falha; `mitm.py` diz `Nao consegui resolver o MAC` | Podman em modo **rootless**. | Refaça o setup rootful do Início rápido e `./scripts/lab.sh up`. |
| `No such file or directory` ao rodar `./scripts/lab.sh ...` | Você está **dentro do contêiner**. | Rode `lab.sh` num terminal **do Mac**, na raiz do projeto. |
| Wireshark (`127.0.0.1:6080`) abre **preto / vazio** | Imagem do atacante **antiga** (antes da correção de renderização Qt sobre VNC). | `./scripts/lab.sh down && ./scripts/lab.sh up` para **reconstruir** a imagem. Depois recarregue a aba (F5). |
| Aba preta **mesmo após reconstruir** | Wireshark não subiu. | `podman logs atacante \| grep start-wireshark` mostra o motivo (ex.: interface ausente). O `.pcapng` segue sendo gravado pelo `capture start`, independente da GUI. |
| No **modo internet**, `ping google.com` na vítima falha mas `curl` funciona | No macOS o Podman (gvproxy) encaminha só **TCP/UDP**, não ICMP. | Normal — todos os experimentos usam `curl` (TCP) e DNS (UDP). Não use `ping` para testar a internet. |
| No **modo internet** a vítima não abre sites reais (`curl` trava/timeout) | VM do Podman sem internet, ou subiu em modo `servidor`. | Confira `podman logs gateway \| grep modo` (tem que dizer `internet`) e a internet da VM: `podman machine ssh ping -c1 1.1.1.1`. |

Diagnóstico rápido (dentro do atacante): `ping -c2 172.10.20.1` tem que responder
— se responder, a varredura ARP acha os alvos.

> **Nota sobre a tela preta:** a interface gráfica roda dentro do atacante
> (Xvfb → x11vnc → noVNC) e era servida com o MIT-SHM do Qt ligado, o que fazia o
> Wireshark desenhar preto sobre o VNC; além disso a janela abria pequena no meio
> de um desktop preto. A correção (`QT_X11_NO_MITSHM`, `-noxdamage` no x11vnc e
> Wireshark iniciando maximizado) está na imagem — por isso é preciso
> **reconstruir** (`up` reconstrói) se o lab já estava no ar.

---

## Estrutura do repositório

```text
TF_Lab_Redes/
├── compose.yaml                 4 contêineres (vitima, atacante, gateway, servidores), 2 redes
├── scripts/
│   ├── lab.sh                   orquestra o lab (up [servidor/internet]/down/shell/capture/trafego)
│   ├── gerar-trafego.sh         tráfego da vítima (tudo/lab/web/http/https/dns/doh)
│   └── autoteste.py             testes offline dos decoders + pipeline
├── containers/                  imagens: atacante (Wireshark/noVNC), vitima, gateway, servidores
├── src/
│   ├── decoders.py              parsers byte a byte (Ethernet/ARP/IP/UDP/TCP/DNS/HTTP/SNI)
│   ├── arp.py                   raw socket, descoberta, envenenamento, cura
│   ├── interceptador.py         estado compartilhado, correlação, persistência
│   ├── tui.py                   painel em tempo real
│   └── mitm.py                  APLICAÇÃO PRINCIPAL (orquestra tudo)
├── docs/
│   ├── topologia.svg            diagrama da topologia e do ataque
│   ├── arquitetura.md           threads, filas, sincronização, conceitos
│   ├── relatorio.md             esqueleto do relatório (3 experimentos + análise)
│   └── evidencias/              capturas de tela dos experimentos
└── resultados/                  pcapng, captura_*.log e resumo_*.csv
```

---

## Entregáveis (Seção 7 do enunciado)

- **Código-fonte comentado:** `src/` (+ infra em `containers/` e `scripts/`).
- **Instruções do ambiente:** este README + `compose.yaml` + `containers/`.
- **Dados de evidência:** `resultados/captura_auditoria.pcapng`, `captura_*.log`, `resumo_*.csv`.
- **Relatório técnico (PDF):** exportar `docs/relatorio.md` preenchido com as evidências da sua execução.
