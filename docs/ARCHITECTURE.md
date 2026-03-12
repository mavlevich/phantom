# Phantom Architecture

## Overview

Phantom is a **zero-knowledge relay** messenger. The server's job is routing - not reading.

## System Diagram

```
┌─────────────┐     TLS 1.3     ┌──────────────────────────┐
│  iOS Client │◄───────────────►│                          │
└─────────────┘                 │       Phantom Server     │
                                │        (Go/Fiber)        │
┌─────────────┐     TLS 1.3     │                          │
│  Web Client │◄───────────────►│  ┌────────┐ ┌────────┐  │
└─────────────┘                 │  │  Auth  │ │  Hub   │  │
                                │  └────────┘ └────────┘  │
                                └──────┬───────────┬───────┘
                                       │           │
                                  ┌────▼───┐  ┌───▼───┐
                                  │Postgres│  │ Redis │
                                  └────────┘  └───────┘
```

## Request Flow - Sending a Message

```
Alice (iOS)                    Server                    Bob (iOS)
    │                             │                          │
    │  1. Encrypt msg with Bob's  │                          │
    │     public key (client-side)│                          │
    │                             │                          │
    │──── WS: SendMessage ───────►│                          │
    │     { ciphertext, nonce,    │                          │
    │       ephemeral_key }       │                          │
    │                             │── 2. Save to DB ──►[DB]  │
    │                             │   (opaque blob)          │
    │                             │                          │
    │                             │  3. Is Bob online?       │
    │                             │     check Hub            │
    │                             │                          │
    │                             │──── WS: NewMessage ─────►│
    │                             │                          │
    │                             │◄─── WS: DeliveryAck ─────│
    │                             │                          │
    │◄── WS: Delivered ──────────│                          │
    │                             │── 4. Mark delivered ►[DB]│
```

If Bob is offline at step 3: message stays in DB. Next time Bob connects,
server flushes pending messages to him.

## Module Dependency Graph

```
cmd/api
   ├── config
   ├── api/http ──► internal/auth
   │            ──► internal/user
   ├── api/ws   ──► internal/messaging
   │            ──► internal/presence
   └── internal/
       ├── auth         ──► internal/storage
       ├── user         ──► internal/storage
       ├── messaging    ──► internal/storage
       │                ──► internal/user (interface only)
       ├── presence     ──► Redis directly
       ├── crypto       (pure functions, no deps)
       ├── notifications
       └── storage      ──► GORM + PostgreSQL
```

Key rule: `internal/*` packages interact with each other **only through interfaces**.
This keeps modules independently testable.

## Data Model

```
users
  id, username, password_hash, public_key, created_at

messages
  id, sender_id, recipient_id,
  ephemeral_key, nonce, ciphertext,  <- all opaque to server
  sent_at, delivered_at
```

Deliberately minimal. No message content, no decryptable fields.

## Scaling Path

For v1 (friends): Single Go binary + Postgres + Redis on one VPS. Handles ~10k concurrent WS connections easily.

For v2 (growth):
- Horizontal scaling with sticky sessions (or Redis pub/sub for Hub fan-out)
- Read replicas for Postgres
- CDN for media (encrypted blobs to S3)
- QUIC transport (HTTP/3) for mobile

## Adding New Features

Every new capability follows this checklist:
1. Add protobuf message type in `packages/proto/`
2. Create `internal/<module>/` with model, service interface, repository interface
3. Implement service + repository
4. Add HTTP or WS handler in `api/`
5. Wire in `cmd/api/main.go`
6. Add tests

Examples of planned modules:
- `internal/groups/` - group chat (Sender Keys protocol)
- `internal/media/` - video/voice messages (encrypted S3)
- `internal/payments/` - crypto transfers (blockchain adapter interface)
- `internal/calls/` - WebRTC signaling
