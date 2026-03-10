# Phantom 🔒

> A fast, end-to-end encrypted messenger built with privacy and security as first-class citizens.

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/yourusername/phantom/actions/workflows/ci.yml/badge.svg)](https://github.com/yourusername/phantom/actions)

## Philosophy

- **Zero-knowledge server** — the server never sees message content
- **Security by default** — no opt-in required for E2E encryption
- **Modular** — every feature is an isolated module, easy to extend
- **Fast** — built on Go + WebSockets, QUIC-ready

## Monorepo Structure

```
phantom/
├── apps/
│   ├── server/          # Go backend (main deliverable)
│   └── ios/             # Swift/SwiftUI iOS client
├── packages/
│   └── proto/           # Protobuf definitions (shared contracts)
├── docs/                # Architecture, security, API docs
├── scripts/             # Dev tooling, DB migrations, deploy helpers
├── .github/workflows/   # CI/CD pipelines
├── docker-compose.yml   # Local dev environment
└── Makefile             # All common commands
```

## Quick Start

```bash
# Prerequisites: Go 1.22+, Docker, Make

git clone https://github.com/yourusername/phantom
cd phantom

# Start all dependencies (PostgreSQL, Redis)
make dev-up

# Run the server
make run

# Run tests
make test

# Run tests with coverage
make test-coverage
```

## Architecture Overview

```
iOS Client ──────────┐
                     ▼
Web Client ──── [ TLS 1.3 ] ──── Go Server ──── PostgreSQL
                     │                    │
                     │                    └──── Redis (presence, sessions)
                [ WebSocket ]
                (E2E encrypted
                 payloads)
```

The server acts as an **encrypted relay**. It routes ciphertext blobs but cannot decrypt them.

## Modules

| Module | Responsibility |
|--------|---------------|
| `auth` | Registration, JWT, key exchange initiation |
| `user` | Profiles, contacts, key publication |
| `messaging` | Message routing, delivery guarantees |
| `crypto` | Key management helpers, validation |
| `presence` | Online status, typing indicators |
| `notifications` | Push notifications (APNs, FCM) |
| `storage` | DB abstractions, repository pattern |

## Security Model

See [docs/SECURITY.md](docs/SECURITY.md) for the full security model.

**Short version:**
- Keys generated client-side, never sent to server in plaintext
- X25519 for key exchange, ChaCha20-Poly1305 for messages
- JWT with short expiry + refresh token rotation
- Rate limiting on all endpoints
- No logging of message content, ever

## Roadmap

- [x] Project structure & CI/CD
- [ ] Auth + key exchange
- [ ] 1-1 messaging (WebSocket)
- [ ] iOS client MVP
- [ ] Group chats
- [ ] Media messages (voice, video)
- [ ] Crypto payments integration

## Contributing

See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).

## License

MIT
