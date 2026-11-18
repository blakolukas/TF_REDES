# Relatório Técnico — Ataque MITM com ARP Spoofing e Auditoria de Metadados

**Disciplina:** Fundamentos de Redes de Computadores — PUCRS 2026/2
**Grupo:** Dhara Hadi, Eduarda Fuchs, Lucas Blacovicz e Lucas Volkweis
**Ambiente:** contêineres Podman em rede bridge isolada (Cenário A do enunciado)

> Este documento é o **esqueleto** do relatório, com a arquitetura e a análise de
> segurança já desenvolvidas. Os trechos marcados **`[PREENCHER]`** dependem da
> **sua própria execução** (saídas de terminal, números de pacote do seu
> `captura_auditoria.pcapng` e capturas de tela do Wireshark) — a arguição exige
> que o grupo entenda e reproduza tudo. Exporte este `.md` para PDF ao final.

---

## 1. Arquitetura da aplicação

Resumo em `docs/arquitetura.md` (incluir no PDF). Pontos obrigatórios cobertos:

- **Módulos:** `decoders` (parsers puros), `arp` (raw socket, descoberta,
  veneno/cura), `interceptador` (estado + persistência + correlação), `tui`,
  `mitm` (orquestração).
- **Threads:** capturador (produtor), processador (consumidor), envenenador,
  principal (TUI + sinais).
- **Filas:** `queue.Queue` entre capturador e processador.
- **Sincronização:** `EstadoCompartilhado.lock` protege contadores e tabelas;
  `Persistencia._lock` serializa a escrita dos arquivos.
- **Estruturas de dados:** `dominio_para_ips`, `ip_para_dominio`, `destinos`.
- **Manipulação binária:** `struct` em cada cabeçalho (ver seção da arquitetura).

Diagrama da topologia: `docs/topologia.svg`.

## 2. Metodologia do ambiente de testes

Ambiente **totalmente isolado**, sem contato com qualquer rede real (exigência
ética e legal do enunciado, Seção 10). Quatro contêineres em duas bridges
privadas:

| Papel      | Container    | IP                        | Função                                                  |
| ---------- | ------------ | ------------------------- | ------------------------------------------------------- |
| Vítima     | `vitima`     | 172.10.20.2               | gera tráfego (DNS, HTTP, HTTPS); rota default → gateway |
| Atacante   | `atacante`   | 172.10.20.254             | `mitm.py` + Wireshark (NoVNC :6080)                     |
| Gateway    | `gateway`    | 172.10.20.1 / 172.10.30.1 | roteia com `ip_forward` + NAT                           |
| Servidores | `servidores` | 172.10.30.10              | DNS, HTTP, HTTPS (SNI) e DoH, todos `.lab`              |

Procedimento de subida e execução: ver `README.md`. Todos os domínios `.lab`
resolvem para `172.10.30.10` (determinismo total), diferenciados pelo SNI/Host.

**Ambiente — preencher com a saída da sua máquina.** Rode no Mac, na raiz do projeto, e cole a saída:

```bash
sw_vers                 # SO do host (macOS)
podman --version        # versão do Podman
podman machine ls       # VM Linux do Podman (modo rootful)
./scripts/lab.sh status # 4 contêineres no ar + estado da captura
```

Versão do Python dos contêineres: `podman exec atacante python3 --version`.

```text
[cole aqui a saída dos comandos acima]
```

## 3. Resultados dos experimentos obrigatórios

Antes de cada experimento: `./scripts/lab.sh capture start captura_auditoria.pcapng`
no atacante e `mitm.py` rodando; ao final, `capture stop`. Os arquivos
`captura_*.log` e `resumo_*.csv` ficam em `resultados/`.

> Exemplos de saída do pipeline (gerados pelo `scripts/autoteste.py`, sem subir o
> lab) estão em `resultados/captura_exemplo-autoteste.log` e
> `resultados/resumo_exemplo-autoteste.csv` — úteis para comparar o **formato**
> com a sua execução real.

### 3.1 Experimento 1 — Exposição: HTTP vs. HTTPS

**Procedimento:** na vítima, `gerar-trafego http` e depois `gerar-trafego https`
(ou `curl http://site-http.lab/painel/segredo` e `curl -k https://site-seguro.lab/`).

**Tabela comparativa (o que o interceptador conseguiu ver):**

| Dado                            | HTTP (porta 80)      | HTTPS (porta 443)                   |
| ------------------------------- | -------------------- | ----------------------------------- |
| Endereços IP e portas           | ✅ visível           | ✅ visível                          |
| Nome de domínio                 | ✅ Host no cabeçalho | ✅ apenas via **SNI** (ClientHello) |
| Método (GET/POST)               | ✅ visível           | ❌ cifrado                          |
| URI / caminho                   | ✅ visível           | ❌ cifrado                          |
| Cabeçalhos (User-Agent, Cookie) | ✅ visível           | ❌ cifrado                          |
| Corpo da mensagem               | ✅ visível           | ❌ cifrado                          |

**Explicação teórica.** No HTTP, a mensagem de aplicação trafega em texto claro
sobre o TCP: quem está no caminho lê tudo. No HTTPS, o TLS cifra a camada de
aplicação **após** o handshake; antes disso, porém, o cliente envia o
`ClientHello` em claro, e a extensão **SNI** carrega o domínio em texto legível
(para o servidor saber qual certificado apresentar em hospedagem compartilhada).
Por isso o domínio vaza mesmo no HTTPS, mas método, URI, cabeçalhos e corpo não.

**Evidência do `captura_*.log` (execução real):**

```text
172.10.20.2 -> 172.10.30.10  HTTP   145B  HTTP GET http://site-http.lab/login?user=alice  UA='curl/7.88.1'
172.10.20.2 -> 172.10.30.10  HTTP   143B  HTTP GET http://site-http.lab/painel/segredo    UA='curl/7.88.1'
172.10.20.2 -> 172.10.30.10  HTTPS  569B  TLS ClientHello SNI=site-seguro.lab
```

No HTTP o interceptador leu método, caminho e User-Agent em claro; no HTTPS só apareceu o SNI (`site-seguro.lab`) — método, URI, cabeçalhos e corpo ficaram cifrados.

**`[PREENCHER]`** prints do Wireshark: _Follow → TCP Stream_ do HTTP (tudo legível) e o filtro `tls.handshake.extensions_server_name` no HTTPS (só o SNI); anote os números dos pacotes do seu `captura_auditoria.pcapng`.

### 3.2 Experimento 2 — Correlação DNS ↔ HTTPS (e efeito do DoH)

**Procedimento:** `gerar-trafego dns` (acessa loja/banco/noticias/video `.lab`).

**Sequência causal observada por acesso** (três pacotes encadeados):

1. **DNS (UDP/53)** — consulta e resposta em claro: QNAME = `loja.lab`, IP
   resolvido = `172.10.30.10` (registrado em `ip_para_dominio`).
2. **TCP** — estabelecimento da conexão (SYN/SYN-ACK/ACK) com esse IP.
3. **TLS `ClientHello` (TCP/443)** — mesmo domínio no **SNI** (`loja.lab`).

É essa cadeia que o `interceptador` correlaciona: o QNAME do DNS rotula o IP, e o
SNI confirma o domínio da sessão cifrada.

**DoH (DNS over HTTPS).** Rode `gerar-trafego doh`. Agora a resolução vai cifrada
para o endpoint `https://172.10.30.10:8443/dns-query`: a consulta **some do
UDP/53** no sniffer (não há mais QNAME em claro), mas o **SNI do `ClientHello`
continua exposto** — o atacante ainda sabe qual site foi acessado. Isso mostra
que o DoH protege a _resolução_, não o _destino_ da conexão TLS convencional.

**Evidência do `captura_*.log` (execução real — 4 domínios distintos):**

```text
172.10.20.2 -> 172.10.30.10  DNS    54B  DNS consulta A loja.lab
172.10.30.10 -> 172.10.20.2  DNS    70B  DNS resposta loja.lab -> 172.10.30.10
172.10.20.2 -> 172.10.30.10  HTTPS 569B  TLS ClientHello SNI=loja.lab
172.10.20.2 -> 172.10.30.10  DNS    55B  DNS consulta A banco.lab
172.10.20.2 -> 172.10.30.10  HTTPS 569B  TLS ClientHello SNI=banco.lab
172.10.20.2 -> 172.10.30.10  HTTPS 569B  TLS ClientHello SNI=noticias.lab
172.10.20.2 -> 172.10.30.10  HTTPS 569B  TLS ClientHello SNI=video.lab
```

Cada domínio aparece primeiro como consulta/resposta DNS em claro (QNAME) e, logo depois, como `ClientHello` com o mesmo nome no SNI — a cadeia DNS→TLS que o `interceptador` correlaciona.

**Trecho do `resumo_*.csv` (execução real):**

```text
dominio,ip_destino,protocolos,total_bytes
video.lab,172.10.30.10,DNS;HTTPS,7820
loja.lab,172.10.30.10,DNS;HTTPS,4876
noticias.lab,172.10.30.10,DNS;HTTPS,4335
banco.lab,172.10.30.10,DNS;HTTPS,4262
```

**`[PREENCHER]`** prints do Wireshark: a linha do tempo com o filtro `dns || tls.handshake.type == 1` para os ≥4 domínios, e o antes/depois do DoH (com pacotes UDP/53 e, após `gerar-trafego doh`, sem o UDP/53 mas com o SNI ainda visível).

### 3.3 Experimento 3 — IP forwarding (espionagem → blackhole)

**Procedimento:** com o ataque ativo e a vítima navegando, desative o
encaminhamento no atacante. Duas formas:

- subir o `mitm.py` com `--sem-forward` (já inicia em modo blackhole); ou
- durante o ataque, em outro shell do atacante: `echo 0 > /proc/sys/net/ipv4/ip_forward`.

**Resultado esperado.** Com `ip_forward = 0`, o atacante continua desviando os
pacotes da vítima (as caches ARP seguem envenenadas), mas **não os repassa** ao
gateway: o tráfego morre no atacante. A vítima perde conectividade — o ataque de
espionagem (confidencialidade) degrada para **negação de serviço / blackhole**
(disponibilidade). Ao reativar (`echo 1 > ...`), a navegação volta.

**`[PREENCHER]`** Saída do `curl` na vítima falhando por timeout; print do
Wireshark mostrando os pacotes chegando ao atacante e nada saindo para o gateway;
evidência da retomada após reativar o `ip_forward`.

## 4. Análise de Segurança e Investigação de Contramedidas

### 4.1 Superfície de exposição residual do HTTPS

Mesmo com TLS, continuam visíveis na rede: **IP de destino**, **portas** e o
**SNI**. Não é descuido — cada campo tem papel funcional:

- **IP de destino:** é o endereço para onde o IP roteia o pacote; sem ele, a rede
  não entrega nada. É intrinsecamente visível a qualquer nó no caminho.
- **Portas (TCP):** multiplexam os serviços no host e permitem o roteamento do
  fluxo pela pilha de transporte (e o rastreio de estado em firewalls/NAT).
- **SNI:** informa ao servidor, **antes** do handshake cifrado, qual host virtual
  o cliente quer, para que ele escolha o certificado correto em hospedagem
  compartilhada (muitos domínios sob um mesmo IP). É enviado em claro por
  necessidade de bootstrap da própria sessão TLS.

Ou seja, o HTTPS protege **conteúdo**, não **metadados de encaminhamento**.

### 4.2 Contramedidas por camada

**Enlace — contra o envenenamento de cache ARP.** O ARP (RFC 826) não tem
autenticação: aceita qualquer `reply`. Mitigações reais:

- **Dynamic ARP Inspection (DAI)** em switches gerenciáveis: valida cada par
  IP↔MAC contra a tabela do **DHCP Snooping** e descarta ARP forjado em portas
  não confiáveis.
- **Port Security / IP Source Guard:** amarram MAC/IP a portas físicas.
- **Client/AP Isolation** em Wi-Fi: impede que um cliente fale ARP diretamente
  com outro (é o que bloqueia o ataque no eduroam da PUCRS, citado na Seção 10).
- **Entradas ARP estáticas** para o gateway em hosts críticos; segmentação por
  VLAN reduz o domínio de broadcast exposto.

**Resolução de nomes — contra a espionagem de DNS.** O DNS tradicional é UDP/53
em claro. Protegem a _consulta_:

- **DoT (DNS over TLS, RFC 7858)** e **DoH (DNS over HTTPS, RFC 8484):** cifram a
  resolução entre cliente e resolver.
- **DNSSEC:** garante _integridade/autenticidade_ das respostas (não
  confidencialidade).

Por que não bastam sozinhos: mesmo com DoH/DoT, a conexão TLS seguinte ainda
expõe o **SNI** em claro — como demonstrado no Experimento 2. O observador deixa
de ver o QNAME, mas continua identificando o site pelo SNI (e pelo IP de destino).

**Conexões cifradas — contra o vazamento do SNI.** A proposta é o **ECH
(Encrypted Client Hello)**, extensão do TLS 1.3 que cifra o próprio `ClientHello`
(incluindo o SNI) usando **HPKE** e uma chave pública do servidor publicada via
DNS (registros **HTTPS/SVCB**). Desafios para adoção ampla: exige suporte
coordenado de cliente, servidor e CDN; depende de DNS seguro (DoH/DoT) para
buscar a chave sem vazá-la; e esbarra em middleboxes/políticas de rede que hoje
inspecionam o SNI. O ECH foi padronizado como **RFC 9849** (TLS Encrypted Client Hello, Standards Track, março/2026); a publicação da configuração ECH via DNS (registros SVCB/HTTPS) é tratada na **RFC 9848**. A adoção ampla ainda depende de suporte coordenado de cliente, servidor e CDN, e enfrenta middleboxes/políticas de rede que hoje inspecionam o SNI.

### Referências

1. RFC 826 — _An Ethernet Address Resolution Protocol_ (ARP). IETF, 1982.
2. RFC 2131 — _Dynamic Host Configuration Protocol_ (DHCP; base do DHCP Snooping). IETF, 1997.
3. RFC 6066 — _TLS Extensions: Extension Definitions_ (define o SNI). IETF, 2011.
4. RFC 8446 — _The Transport Layer Security (TLS) Protocol Version 1.3_. IETF, 2018.
5. RFC 7858 — _Specification for DNS over TLS (DoT)_. IETF, 2016.
6. RFC 8484 — _DNS Queries over HTTPS (DoH)_. IETF, 2018.
7. RFC 9180 — _Hybrid Public Key Encryption (HPKE)_ (criptografia usada pelo ECH). IETF, 2022.
8. RFC 9460 — _Service Binding and Parameter Specification via the DNS (SVCB/HTTPS RR)_. IETF, 2023.
9. RFC 9848 — publicação de configurações ECH em registros SVCB/HTTPS do DNS. IETF, 2026.
10. RFC 9849 — _TLS Encrypted Client Hello (ECH)_. IETF, março/2026 (Standards Track).
11. Cisco — _Dynamic ARP Inspection (DAI)_ e _DHCP Snooping_, Catalyst Security Configuration Guide (documentação do fornecedor).

## 5. Uso de Inteligência Artificial

_(Seção obrigatória — preencher honestamente; a autoria técnica é do grupo.)_

- **Ferramentas e modelos utilizados:** `[PREENCHER]` (ex.: Claude, ChatGPT…).
- **Como a IA foi empregada:** `[PREENCHER]` — ex.: explicação da estrutura do
  `ClientHello` e da extensão SNI; revisão do modelo produtor/consumidor
  (fila entre captura e processamento); esqueleto dos Containerfiles; depuração
  do parsing de compressão de nomes DNS.
- **Exemplos de prompts e avaliação crítica:** `[PREENCHER]` — citar 2–3 prompts
  reais e o que o grupo aceitou/rejeitou e por quê.
- **Dificuldades / respostas incorretas e como superaram:** `[PREENCHER]` —
  ex.: ajustes no `ip_forward` dentro do contêiner, ordem das interfaces no
  gateway, flags do `curl` para DoH.

---

### Anexos / evidências entregues

- `resultados/captura_auditoria.pcapng` — captura do Wireshark na máquina atacante.
- `resultados/captura_*.log` e `resultados/resumo_*.csv` — gerados pelo `mitm.py`.
- `docs/evidencias/*.png` — capturas de tela dos três experimentos.
