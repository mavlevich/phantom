# Phantom — AI Context & Working Instructions

This file is the entry point for AI assistants (Claude, Cursor, Copilot, etc.) working on this project.
Read this before writing any code.

---

## What Is This Project

Phantom is an end-to-end encrypted messenger. The server is a **zero-knowledge relay** — it routes
encrypted messages but never has access to plaintext content. Security is not a feature, it's the foundation.

## Tech Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| Backend | Go 1.22+ | Concurrency, single binary deploy, learning |
| Framework | Fiber v2 | Fast, Express-like DX |
| WebSocket | gorilla/websocket via Fiber | Real-time messaging |
| Database | PostgreSQL + GORM | Relational, reliable |
| Cache/Presence | Redis | Fast ephemeral state |
| Crypto | golang.org/x/crypto (NaCl/box) | Audited, standard |
| Auth | JWT (short-lived) + refresh tokens | Stateless + revocable |
| iOS | Swift + SwiftUI | Native performance |
| API contract | Protobuf | Typed, versioned |
| CI/CD | GitHub Actions | Integrated, free |

## Project Layout (Server)

```
apps/server/
├── cmd/api/main.go              # Entry point — wire everything together here
├── internal/                    # Business logic — NOT importable outside server
│   ├── auth/                    # Registration, login, JWT, refresh
│   ├── user/                    # User profiles, contacts, public keys
│   ├── messaging/               # Core: message routing, hub, delivery
│   ├── crypto/                  # Key validation, helpers (NO key generation — client-side only)
│   ├── presence/                # Online status, typing indicators via Redis
│   ├── notifications/           # APNs/FCM push
│   └── storage/                 # Repository interfaces + GORM implementations
├── api/
│   ├── http/                    # REST handlers (auth, user management)
│   └── ws/                      # WebSocket handlers (messaging, presence)
├── config/                      # Config struct, env loading
├── migrations/                  # SQL migrations (numbered: 001_init.sql, etc.)
└── tests/
    ├── unit/                    # Pure unit tests, no DB
    └── integration/             # Tests with real DB (uses testcontainers)
```

## Architecture Rules — ALWAYS Follow

1. **Repository pattern** — all DB access goes through interfaces in `storage/`.
   Never write `db.Where(...)` in a handler or service directly.

2. **Dependency injection** — services receive their dependencies via constructor.
   No global variables (except logger).

3. **No business logic in handlers** — handlers only: parse input → call service → write response.

4. **Errors** — use sentinel errors + wrapping: `fmt.Errorf("auth.Login: %w", err)`.
   Define domain errors in each package: `var ErrUserNotFound = errors.New("user not found")`.

5. **Context everywhere** — all functions that do I/O must accept `context.Context` as first arg.

6. **NEVER log message content** — logging middleware must explicitly exclude message body fields.
   Logs are for metadata only: user IDs, timestamps, error types.

7. **Security-first** — when in doubt, refuse the request. Rate limit aggressively.

## Module Boundaries

Each `internal/` package should be thought of as a mini-service:
- Has its own `service.go` (business logic interface + implementation)
- Has its own `repository.go` (DB interface + implementation)
- Has its own `model.go` (domain structs)
- Has its own `errors.go` (sentinel errors)
- Packages may depend on `storage` and `config`, but NOT on each other's internals

```
✅ messaging.Service depends on user.Repository (interface)
❌ messaging.Service imports user.Service directly
```

## Cryptography Rules

- **Key generation is CLIENT-SIDE ONLY.** The server never generates private keys.
- Server stores only public keys (published by clients during registration).
- Message payloads arriving at the server are already encrypted. Server must not attempt to decrypt.
- Crypto primitives to use: X25519 (key exchange), ChaCha20-Poly1305 (AEAD encryption).
- Use `golang.org/x/crypto/nacl/box` for simplicity in v1.

## Testing Standards

- Unit tests for all service methods (mock repository with interfaces).
- Integration tests for all HTTP endpoints and WebSocket flows.
- Test file naming: `service_test.go` sits next to `service.go`.
- Minimum coverage target: 80% for `internal/`.
- Use `testify` for assertions.
- Use `testcontainers-go` for integration tests (spins up real Postgres/Redis).

## API Conventions

- REST for: auth, user management, key publication
- WebSocket for: messaging, presence, typing indicators
- All REST responses: `{ "data": ..., "error": null }` or `{ "data": null, "error": "message" }`
- Versioned: `/api/v1/...`
- All times: RFC3339 UTC

## Environment Variables

See `config/config.go` for full list. Key ones:
```
APP_ENV=development|production
SERVER_PORT=8080
DATABASE_URL=postgres://...
REDIS_URL=redis://...
JWT_SECRET=...
JWT_EXPIRY=15m
REFRESH_TOKEN_EXPIRY=30d
```

## Common Make Commands

```bash
make run            # Start server (hot reload with air)
make test           # Run all tests
make test-coverage  # Tests + HTML coverage report
make lint           # golangci-lint
make migrate-up     # Run DB migrations
make migrate-down   # Rollback last migration
make generate       # Generate protobuf + mocks
make dev-up         # Docker: start Postgres + Redis
make dev-down       # Docker: stop all
make build          # Build production binary
```

## Current Development Phase

**Phase 1 (current):** Foundation
- Project structure ✅
- CI/CD ✅
- Auth module (in progress)
- Key exchange (next)

**Phase 2:** MVP messaging
- WebSocket hub
- 1-1 message delivery
- iOS client v1

**Phase 3:** Features
- Group chats
- Media messages
- Push notifications

## When Adding a New Module

1. Create `internal/<module>/` directory
2. Add `model.go`, `service.go`, `repository.go`, `errors.go`
3. Define repository interface (mock-friendly)
4. Register routes in `api/http/router.go` or `api/ws/router.go`
5. Wire dependencies in `cmd/api/main.go`
6. Add tests in same package + integration test

## Known Constraints & Decisions

- No ORM magic — use GORM for basic CRUD but write raw SQL for complex queries
- Redis for presence only, not for message persistence (messages go to Postgres)
- No message fan-out on server — delivery confirmation is the client's responsibility
- Push notifications metadata: only "you have a new message", never content
