# limithit

CLI em Go para **simulação de ataques HTTP** e testes de resiliência — reproduz vetores reais de DDoS, esgotamento de conexão, bypass de rate limit e enumeração de endpoints contra seu próprio ambiente.

Sem dependências externas — stdlib Go apenas.

## Requisitos

- Go 1.22+

## Instalação

```bash
git clone https://github.com/conantorreswf/limithit.git
cd limithit
go build -o limithit .
```

## Painel Web (recomendado)

```bash
./limithit webui
# abre em http://localhost:9090
```

Interface web para configurar, lançar e monitorar ataques. **Mais completa que o terminal** — use por padrão.

> A CLI e TUI ainda estão em desenvolvimento ativo.

## CLI / TUI

```bash
./limithit <ataque> [flags] <url>
./limithit          # TUI interativa (sem args)
```

A URL pode vir antes ou depois das flags.

## Ataques disponíveis

| Ataque | O que testa |
|--------|-------------|
| `flood` | Rate limiting básico, throughput sob carga |
| `slowloris` | `ReadHeaderTimeout`, esgotamento de conexões |
| `spoof` | Bypass de rate limit por IP via `X-Forwarded-For` |
| `fuzz` | Endpoints expostos, cache bypass |
| `headerbomb` | `MaxHeaderBytes`, limites de parser |
| `h2flood` | Rate limit HTTP/2, `MaxConcurrentStreams` |
| `wsflood` | Esgotamento de conexões WebSocket |
| `gzipbomb` | Decompressão sem limite, exaustão de memória |
| `replay` | Reprodução de tráfego real (HAR/arquivo) |
| `methodspray` | Rate limit por verbo HTTP, rotas que escapam por método |

Ver [`docs/`](docs/README.md) para flags, exemplos e como interpretar resultados.

## Cenários YAML

Orquestre múltiplos ataques em sequência com assertions:

```bash
./limithit scenario run examples/scenario.yaml
./limithit scenario run examples/scenario.yaml --continue-on-fail
./limithit scenario validate examples/scenario.yaml
./limithit scenario init > limithit.yaml   # scaffold
```

## Testserver local

Servidor alvo com rate limiting, dashboard em tempo real e hardening configurável:

```bash
cd testserver
go run . --rate 5 --burst 5

# Com suporte a XFF (para testar spoof bypass)
go run . --rate 5 --burst 5 --trust-xff-cidr 127.0.0.0/8

# Algoritmo de rate limit alternativo
go run . --rate 5 --burst 5 --algo slidingwindow
```

Dashboard disponível em `http://localhost:8080`. Algoritmos: `tokenbucket` (padrão), `fixedwindow`, `slidingwindow`, `leakybucket`.

---

> **Aviso legal:** use apenas contra sistemas que você possui ou tem autorização explícita para testar.
