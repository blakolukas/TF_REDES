# Arquitetura da aplicação MITM

Documento de referência da estrutura interna do `src/mitm.py` e seus módulos.
Serve de base para a seção de arquitetura do relatório e para a arguição
individual (o professor pergunta sobre threads, filas, sincronização e
manipulação binária dos cabeçalhos).

## Visão geral dos módulos

| Módulo | Responsabilidade |
|---|---|
| `src/decoders.py` | Funções **puras** de (de)codificação byte a byte: Ethernet, ARP, IPv4, UDP, TCP, DNS, HTTP e o SNI do TLS. Nenhum socket, nenhum efeito colateral. |
| `src/arp.py` | Operações de baixo nível sobre `AF_PACKET`: abrir socket, ler MAC/IP/máscara da interface (ioctl), descoberta de hosts, montagem dos quadros de veneno e de cura. |
| `src/interceptador.py` | O consumidor do pipeline: `EstadoCompartilhado` (sob lock), `Persistencia` (log + CSV) e `processar_quadro` (decodifica, correlaciona e grava). |
| `src/tui.py` | Painel textual em tempo real; só leitura do estado + apresentação. |
| `src/mitm.py` | Orquestração: descoberta, seleção de alvos, `ip_forward`, criação das threads, tratamento de sinais e self-healing. |

Separar os **decoders puros** do resto é o que torna o sistema testável sem root
e sem rede: `scripts/autoteste.py` constrói quadros à mão e verifica cada parser
e o pipeline inteiro.

## Modelo de concorrência (threads + fila)

Quatro fluxos de execução, coordenados por um `threading.Event` (`parar`):

```
          +-----------------+        queue.Queue (10000)        +------------------+
 kernel ->| thread          |  (frame_bruto, timestamp)  ---->  | thread           |
 (NIC)    | CAPTURADOR      |---------------------------------->| PROCESSADOR      |
          | só faz recv()   |                                   | decodifica +     |
          +-----------------+                                   | correlaciona +   |
                                                                | persiste         |
          +-----------------+                                   +------------------+
          | thread          |  envia ARP Reply forjado                  |
          | ENVENENADOR     |  a cada `intervalo` s                     v
          +-----------------+                            EstadoCompartilhado (lock)
                                                                        ^
          +-----------------+                                           |
          | thread PRINCIPAL|  painel TUI (lê estado 1x/s) + sinais ----+
          +-----------------+
```

- **Capturador (produtor).** Só executa `recv()` no raw socket e enfileira o
  quadro cru com um *timestamp*. Mantém-se mínimo de propósito: se o parsing
  rodasse aqui, o `recv()` ficaria parado e o kernel descartaria quadros sob
  rajada. É o ponto clássico de produtor/consumidor.
- **Processador (consumidor).** Tira da fila, decodifica camada a camada,
  atualiza o `EstadoCompartilhado` e grava o log; a cada 2 s reescreve o CSV de
  resumo. É o **único escritor** do arquivo de log e do CSV (nenhuma disputa de
  arquivo entre threads).
- **Envenenador.** Reenvia os dois `ARP Reply` forjados a cada `intervalo`
  (padrão 2 s), mantendo o desvio contra a renovação legítima das caches. Usa um
  socket de envio separado do socket de captura, para não competir com o
  `recv()`.
- **Principal.** Desenha o painel 1x/s lendo o estado sob lock e instala os
  *handlers* de `SIGINT`/`SIGTERM`. Ao receber o sinal, apenas seta `parar`; o
  encerramento limpo (join das threads, cura ARP, restauração do `ip_forward`)
  acontece em seguida, de forma determinística.

## Sincronização e regiões críticas

- **`EstadoCompartilhado.lock`** (um `threading.Lock`): protege todos os
  contadores e tabelas (`dominio_para_ips`, `ip_para_dominio`, `destinos`,
  `arp`, `ultimos`). As regiões críticas são curtas — entra, incrementa/insere,
  sai — para não serializar captura e apresentação. Escreve o processador; lê a
  TUI e o resumo.
- **`queue.Queue`**: é *thread-safe* por si só; é a fronteira produtor/consumidor
  e o único canal entre capturador e processador. O `maxsize` limita memória sob
  rajada (se encher, o produtor bloqueia brevemente — preferível a estourar RAM).
- **`Persistencia._lock`**: serializa a escrita do `.log` e a reescrita do
  `.csv`, já que o resumo pode ser disparado tanto pelo laço periódico quanto
  pelo encerramento.

## Estruturas de dados

- `dominio_para_ips: dict[str, set[str]]` e `ip_para_dominio: dict[str, str]` —
  o mapa de correlação construído a partir das respostas DNS (A/AAAA). É o que
  liga a consulta DNS em claro (QNAME→IP) às conexões HTTPS seguintes (mesmo IP,
  mesmo SNI).
- `destinos: dict[chave, {dominio, ips:set, protocolos:set, bytes, ultimo}]` —
  agregado por destino (domínio quando conhecido, senão IP). Alimenta o painel e
  o `resumo_*.csv`.
- `ultimos: list` (janela das últimas ~12 linhas) — só para o painel.

## Manipulação binária dos cabeçalhos (resumo)

Tudo com `struct` sobre `bytes` crus (ver `decoders.py`):

- **Ethernet**: `!6s6sH` → MAC destino, MAC origem, EtherType.
- **ARP**: `!HHBBH6s4s6s4s` → htype, ptype, hlen, plen, oper, e os quatro
  endereços (SHA/SPA/THA/TPA).
- **IPv4**: IHL = `(primeiro_byte & 0x0F) * 4` trata o cabeçalho de tamanho
  variável; lê-se TTL (byte 8), protocolo (byte 9) e os IPs (bytes 12–19).
- **TCP**: data offset = `(byte[12] >> 4) * 4`; as flags estão no byte 13
  (bitmask FIN/SYN/RST/PSH/ACK/URG).
- **DNS**: cabeçalho de 12 bytes; o QNAME é lido label a label, resolvendo
  **compressão** (ponteiros `0xC0`).
- **TLS SNI**: caminha pelo registro (ContentType `0x16`), handshake
  (`0x01` ClientHello), pula versão/random/session-id/cipher-suites/compression e
  varre as extensões até `server_name` (`0x0000`), de onde extrai o host.

## Ciclo de vida

1. Abre dois raw sockets (`captura` e `envio`) e lê MAC/IP/máscara da interface.
2. **Descoberta ARP**: pergunta "quem tem X?" para cada IP da sub-rede e lista os
   nós ativos (pares IP/MAC).
3. Seleção de **vítima** e **gateway** (por argumento ou interativa).
4. Salva e ajusta os sysctls do kernel: ativa o `ip_forward` (ou desativa, no
   modo `--sem-forward` do Experimento 3) e **desliga os ICMP `send_redirects`**
   — senão o atacante avisaria a vítima da rota real e o desvio se desfaria.
   Ambos são restaurados no encerramento (`SysctlTemporario`).
5. Sobe as threads (envenenador, capturador, processador) e o painel.
6. **`Ctrl-C`** → `parar` setado → join das threads → **cura ARP** (rajada de
   `ARP Reply` legítimos) → `ip_forward` restaurado → arquivos fechados → resumo
   final no terminal.
