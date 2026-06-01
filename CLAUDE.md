# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build
go build -o limithit .
cd testserver && go build ./...

# Format — required before commit
gofmt -w .
gofmt -w testserver/

# Vet
go vet ./...
cd testserver && go vet ./...

# Test
go test ./internal/...
cd testserver && go test ./...
```

Git hooks in `.githooks/` run `gofmt` on commit and `build + vet + gofmt` on push — both root and `testserver/` module.

## Docs

`docs/` — one Markdown file per attack (flags, examples, how to interpret results). `docs/README.md` is the index. Running `./limithit` with no args opens the interactive TUI.

## Architecture

Two independent Go modules:

**Root module** (`github.com/conantorreswf/limithit`) — CLI attacker + TUI (bubbletea/huh):
- `main.go` → `internal/cli.Run()` → dispatches subcommands or launches TUI
- `internal/cli/cli.go` — one `runX()` per attack
- `internal/attacks/<name>/` — each attack implements `Attack` interface (`Name`, `Synopsis`, `Flags`, `Validate`, `Run`, `FormFields`); registers via `attacks.Register` in `init()`
- `internal/attacks/all/all.go` — blank imports every attack package; imported by scenario runner and TUI
- `internal/attacks/registry.go` — `Register` / `Lookup` / `All`
- `internal/metrics/` — `metrics.go`, `connreport.go`, `pacer.go`, `ippool.go`, `wordlist.go`, `progress.go`
- `internal/config/config.go` — YAML scenario config; env vars expand as `${VAR}`; `Defaults` apply to all steps
- `internal/scenario/runner.go` — `Validate` + `Run`; `expect-status` assertions; `--continue-on-fail`
- `internal/safety/guard.go` — pre-flight checks

**`testserver/` module** — local target with rate limiting and live dashboard:
- `ratelimit/` — `Limiter` interface; algorithms: `tokenbucket`, `fixedwindow`, `slidingwindow`, `leakybucket`
- `handler/` — ping/echo, auth lockout, gzip bomb endpoint, WebSocket flood target, dashboard SSE

## Terminology

- **webui** = the web-based attack panel served by `internal/webui/` — browser UI for launching and monitoring attacks.

## Key design decisions

- **Attack registry**: adding a new attack = new package + `Register` call in `init()` + blank import in `all/all.go`.
- **URL position-agnostic**: `extractURLArg` in `cli/common.go` strips the URL before `flag.Parse`, so `--flag value <url>` and `<url> --flag value` both work.
- **Spoof bypass condition**: spoof only bypasses per-IP rate limit when `--trust-xff-cidr` includes the attacker's real IP.
- **Slowloris detection**: `DroppedByServer > 0` = server protected. `DroppedByServer = 0` with `AvgHold ≈ --hold` = vulnerable.
- **Safety guard**: `gzipbomb` requires `--i-understand`; non-localhost targets warn unless `--allow-target <host>` suppresses it.
- **Scenario `expect-status`**: asserts at least one response with that HTTP status was observed; only meaningful for attacks returning `*metrics.Report`.
- **Tests exist** in `internal/metrics/`, `internal/config/`, `internal/attacks/`, and `testserver/`.
