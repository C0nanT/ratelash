# limithit — Documentação de Ataques

> Use apenas contra sistemas que você possui ou tem autorização explícita para testar.

## Ataques

| Ataque | Categoria | O que testa |
|--------|-----------|-------------|
| [flood](flood.md) | Volumétrico | Rate limiting básico, throughput sob carga |
| [slowloris](slowloris.md) | Slow HTTP | `ReadHeaderTimeout`, pool de conexões |
| [spoof](spoof.md) | IP bypass | Confiança em `X-Forwarded-For`, `--trust-xff-cidr` |
| [fuzz](fuzz.md) | Enumeração | Rotas ocultas, proteção por caminho, cache bypass |
| [headerbomb](headerbomb.md) | Exaustão de recursos | `MaxHeaderBytes`, `MaxBytesReader`, limites de parser |
| [h2flood](h2flood.md) | Volumétrico HTTP/2 | Rate limit por conexão vs stream, `MaxConcurrentStreams` |
| [wsflood](wsflood.md) | WebSocket | Conexões simultâneas, rate limit no upgrade |
| [gzipbomb](gzipbomb.md) | Amplificação | Decompressão sem limite, exaustão de memória |
| [replay](replay.md) | Reprodução | Tráfego real sob carga, HAR import |
| [methodspray](methodspray.md) | Enumeração | Rate limiting por verbo, rotas que escapam por método |

## Referência rápida

```bash
./limithit flood       <url> --total 200 --concurrency 20
./limithit slowloris   <url> --connections 50 --hold 30
./limithit spoof       <url> --ip-pool 10.0.0.0/28 --total 200
./limithit fuzz        <url> --cache-bust --total 200
./limithit headerbomb  <url> --header-count 100 --header-size 256
./limithit h2flood     <url> --total 200
./limithit wsflood     <url> --total 100
./limithit gzipbomb    <url> --i-understand
./limithit replay      <url> --file requests.txt --total 200
./limithit methodspray <url> --total 200
```

## Flags globais

| Flag | Efeito |
|------|--------|
| `--ramp-start` + `--ramp-duration` | Aumenta taxa linearmente até o ritmo cheio |
| `--keepalive=false` | Força novo handshake TCP/TLS por requisição |
| `--expect-status <N>` | Exit code 1 se o status esperado não aparecer |

## Cenários YAML

```bash
./limithit scenario run      examples/scenario.yaml
./limithit scenario run      examples/scenario.yaml --continue-on-fail
./limithit scenario validate examples/scenario.yaml
./limithit scenario init > limithit.yaml
```
