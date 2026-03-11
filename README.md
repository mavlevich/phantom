# Phantom 👻

> A fast, end-to-end encrypted messenger built with privacy and security as first-class citizens.

[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/mavlevich/phantom/actions/workflows/ci.yml/badge.svg)](https://github.com/mavlevich/phantom/actions)

## Philosophy

- **Zero-knowledge server** — the server never sees message content
- **Security by default** — no opt-in required for E2E encryption
- **Modular** — every feature is an isolated module, easy to extend
- **Fast** — built on Go + WebSockets, QUIC-ready

---

## Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Go | 1.25+ | `brew install go` |
| Docker Desktop | latest | [docker.com](https://www.docker.com/products/docker-desktop/) |
| Make | built-in | — |

First-time dev tools setup:
```bash
make setup
```

This installs: `air` (hot reload), `golangci-lint`, `govulncheck`, `goimports`, `mockgen`.

---

## Project Structure

```
phantom/
├── apps/
│   ├── server/              # Go backend
│   │   ├── cmd/api/         # Entry point
│   │   ├── config/          # Environment config
│   │   ├── internal/        # Business logic (auth, messaging, crypto...)
│   │   ├── migrations/      # SQL migrations
│   │   └── tests/           # Unit + integration tests
│   └── ios/                 # Swift/SwiftUI iOS client (coming soon)
├── packages/
│   └── proto/               # Protobuf definitions (shared contracts)
├── docs/                    # Architecture, security, API docs
├── scripts/                 # Dev tooling helpers
├── .github/workflows/       # CI/CD pipelines
├── docker-compose.yml       # Local dev: PostgreSQL + Redis
└── Makefile                 # All common commands
```

---

## Quick Start

### 1. Clone

```bash
git clone https://github.com/mavlevich/phantom
cd phantom
```

### 2. Configure environment

```bash
cp apps/server/.env.example apps/server/.env
```

Open `apps/server/.env` and set a JWT secret (min 32 chars):
```
JWT_SECRET=your-random-secret-minimum-32-chars
```

Generate a secure one with:
```bash
openssl rand -hex 32
```

### 3. Start dependencies (PostgreSQL + Redis)

```bash
make dev-up
```

Check they are running:
```bash
docker compose ps
```

Both containers should show `healthy`.

### 4. Start the server

```bash
cd apps/server
export $(cat .env | grep -v '^#' | grep -v '^$' | xargs)
go run ./cmd/api
```

You should see:
```
{"level":"INFO","msg":"starting server","port":"8080","env":"development"}

 ┌───────────────────────────────────────────────────┐
 │                      Phantom                      │
 │                  Fiber v2.52.12                   │
 │               http://127.0.0.1:8080               │
 └───────────────────────────────────────────────────┘
```

### 5. Verify

```bash
curl http://localhost:8080/health
# → {"status":"ok"}
```

---

## Stopping Everything

### Stop the server
Press `Ctrl+C` in the terminal where the server is running.

### Stop Docker services (PostgreSQL + Redis)
```bash
make dev-down
```

### Stop and remove all data (full reset)
```bash
docker compose down -v
```
> ⚠️ This deletes all local database data.

---

## Common Commands

Run all commands from the **repo root** (`phantom/`):

```bash
make dev-up          # Start PostgreSQL + Redis
make dev-down        # Stop PostgreSQL + Redis
make dev-logs        # Follow Docker logs

make run             # Start server with hot reload (requires air)
make run-plain       # Start server without hot reload
make build           # Build production binary → apps/server/bin/phantom

make test            # Run all tests
make test-unit       # Unit tests only
make test-coverage   # Tests + open HTML coverage report
make lint            # Run golangci-lint
make security        # Run govulncheck

make migrate-up      # Run pending DB migrations
make migrate-down    # Rollback last migration
```

---

## Hot Reload (recommended for development)

Instead of restarting the server manually on every change, use `air`:

```bash
make run
```

Air watches for file changes and automatically rebuilds + restarts the server.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_ENV` | `development` | Environment (`development` / `production`) |
| `SERVER_PORT` | `8080` | HTTP server port |
| `DATABASE_URL` | — | PostgreSQL connection string (**required**) |
| `REDIS_URL` | `redis://localhost:6379` | Redis connection string |
| `JWT_SECRET` | — | JWT signing secret, min 32 chars (**required**) |
| `JWT_EXPIRY` | `15m` | Access token lifetime |
| `REFRESH_TOKEN_EXPIRY` | `720h` | Refresh token lifetime (30 days) |

---

## Architecture Overview

```
iOS Client ─────────────┐
                        ▼
Web Client ──── [ TLS 1.3 ] ──── Go Server ──── PostgreSQL
                        │                │
                        │                └──── Redis (presence, sessions)
                   [ WebSocket ]
                  (E2E encrypted
                    payloads)
```

The server acts as an **encrypted relay**. It routes ciphertext blobs but cannot decrypt them.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for full diagrams and flow.
See [docs/SECURITY.md](docs/SECURITY.md) for the cryptographic model.

---

## Roadmap

- [x] Project structure & CI/CD
- [x] Server boots, health endpoint
- [ ] Auth module (registration, login, JWT)
- [ ] User profiles + public key publication
- [ ] WebSocket hub (real-time messaging)
- [ ] E2E encryption (X25519 + ChaCha20-Poly1305)
- [ ] iOS client MVP
- [ ] Group chats
- [ ] Push notifications (APNs)
- [ ] Media messages
- [ ] Crypto payments integration

---

## Troubleshooting

**`JWT_SECRET is required` on startup**
```bash
export $(cat .env | grep -v '^#' | grep -v '^$' | xargs)
```

**`docker: command not found`**
Docker Desktop is not running. Open the Docker app from Applications.

**`connection refused` on port 5432**
PostgreSQL container is not healthy yet. Wait a few seconds and run `make dev-up` again.

**Port 8080 already in use**
```bash
lsof -ti:8080 | xargs kill
```

---

## License

MIT
