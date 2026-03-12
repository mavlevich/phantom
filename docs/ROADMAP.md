# Phantom Product Roadmap & Vision

Last updated: March 2026  
Status: Pre-alpha. Server boots. Auth in progress.

## What We Are Building

Phantom is a privacy-first, end-to-end encrypted messenger where:

- the server is a blind relay that stores and forwards ciphertext, never plaintext
- identity is username-only in v1, with no email or phone required
- the system is designed so transport can evolve over time without rewriting business logic
- trust comes from open code and reviewable architecture, not marketing promises

The long-term direction is bigger than "chat app": a communication platform that can become harder to censor over time through better transport options and stronger metadata protection. The alpha is not that full vision yet. The alpha is the smallest honest product that proves the core.

## Guiding Principles

- Ship thin vertical slices. A working register/login flow is worth more than half of three future systems.
- Security is not a feature. It is the foundation. Do not ship shortcuts that break the threat model.
- One PR, one capability. Keep branches narrow and CI meaningful.
- Cryptography stays client-side. The server never generates, stores, or touches private keys.
- Transport-agnostic from day one. Business logic should not care whether a message came through WebSocket, Tor, or something else later.
- Postpone native until the protocol is stable. A broken native app is worse than a good browser client.
- Pin critical tooling. "Latest" is not a strategy for CI or security-sensitive developer workflows.

## Current Status

- Monorepo structure: done
- CI / CD pipeline: done
- Security scanning: done
- Health endpoint: done
- PostgreSQL + Redis local dev: done
- Repository-managed hooks: done
- Auth module: in progress

## MVP Definition

The MVP is a private alpha for 5-20 trusted users who can exchange simple encrypted 1-to-1 text messages from:

- desktop browser
- iPhone Safari / PWA

The MVP is intentionally:

- invite-only
- single-device
- browser-first
- 1-to-1 text only

The MVP is explicitly not:

- native iOS
- groups
- media
- calls
- multi-device
- push-first
- "Signal-complete"

## Key Working Decisions for Alpha

These are the default assumptions until we deliberately change them:

- Client strategy: web-first PWA.
- Web crypto strategy: Web Crypto API first, hidden behind a `CryptoAdapter`.
- Registration strategy: invite-only.
- Invite model: admin-issued invites only in alpha.
- Identity: username-only in v1.
- Recovery: no full account recovery in alpha; losing local key material should be treated as account loss or forced reset.
- Device model: one account, one active device model for v1.
- Public key model: immutable in v1.
- Delivery states: implement `accepted` and `delivered`; postpone `read`.
- Message ordering: server-assigned `sequence_number` per conversation, not timestamp-only ordering.
- Token storage: access token in memory, refresh token in `HttpOnly` cookie.
- Native iOS: explicitly postponed until protocol and browser UX are stable.
- Push notifications: postponed until after live alpha usage validates demand.
- Payments and crypto features: fully out of scope until the core messenger works for real users.

## Architecture Guardrails

- Keep transport thin: HTTP and WebSocket handlers call services, services call repositories.
- Keep cryptography out of handlers, repositories, and database code.
- Store only ciphertext and delivery metadata on the server.
- Version API contracts from the start under `/api/v1/...`.
- Keep the web client PWA-ready so it works reasonably on iPhone before native exists.
- Prefer explicit module boundaries over clever abstractions.
- Add tests in the same branch as the feature.
- Never log message content.
- Never persist plaintext message content.

## Research Notes and Constraints

### Client Platform Notes

- Web-first is still the fastest and least risky path to alpha.
- A single responsive browser client is materially cheaper than splitting effort across web and SwiftUI during protocol churn.
- Web Push for Home Screen web apps exists on iOS/iPadOS 16.4+, so push can be added later without invalidating the web-first direction.

### Secure Context Notes

- Public deployment should assume HTTPS from day one.
- Web Crypto, Service Workers, Notifications, Push, and related browser APIs depend on secure-context rules.

### Browser Storage Notes

- Key material and durable encrypted client state should be designed around IndexedDB, not `localStorage`.
- IndexedDB leaves room for encrypted local cache, pending outbound queue, and future sync metadata.
- If multi-tab coordination becomes important later, Web Locks is the most likely browser-native primitive to build around.

### Cryptography Notes

- The current default is Web Crypto API for the web client.
- The implementation still has to sit behind a `CryptoAdapter` so it can be swapped later without touching UI components.
- The immediate goal is reliable client-side encryption for the alpha, not protocol perfection.

### Data Model Notes

- Single-device alpha is still the most sensible default.
- Conversation list behavior will matter early, so derive-from-messages is no longer the default direction.
- A `conversations` table should exist from the beginning of the messaging phase.
- Server-assigned `sequence_number` per conversation is the default ordering strategy.

### Delivery Semantics Notes

- Message lifecycle should be defined before transport details harden.
- MVP lifecycle should likely be:
- `sent` -> client created and attempted send
- `accepted` -> server validated and persisted ciphertext
- `delivered` -> recipient device explicitly acknowledged receipt
- `read` should stay out of v1.

### Operational Notes

- One repeatable deployment matters more than horizontal scale for alpha.
- One VPS with Go, PostgreSQL, Redis, TLS, and backups is enough for the first private alpha.
- Monorepo CI needs explicit `cache-dependency-path` and Node 24-compatible GitHub Actions versions to stay boring.

## Phase 0 - Foundation

Goal: establish a clean baseline that lets every later feature land safely.

- Monorepo skeleton
- GitHub Actions: test, lint, build, security scan
- Docker Compose for PostgreSQL and Redis
- Structured JSON logging with no plaintext content
- Graceful shutdown
- Health endpoint
- Architecture and security documentation
- Repository-managed hooks for pre-commit and pre-push

Status: done enough to move on.

## Phase 1 - Auth and Identity

Goal: users can register with an invite code, log in, and maintain a session.

PRs:

1. `feature/auth-register` - invite code model and migration, `auth.Repository`, `auth.Service`, Argon2id password hashing, public key storage, unit tests.
2. `feature/auth-login` - login, JWT access token, refresh token rotation, logout, account lockout, unit tests.
3. `feature/auth-http` - register/login/refresh/logout endpoints, JWT middleware, rate limiting, integration tests.

Key decisions for this phase:

- No email in v1.
- Invite-only registration with admin-issued invites only.
- Argon2id for password hashing.
- Single-device model in alpha.
- No account recovery in alpha.
- Public key is immutable in v1.

## Phase 2 - User Directory

Goal: users can discover each other and fetch public keys for encryption.

PR:

1. `feature/user-directory` - username lookup, public key lookup, immutability rules for keys in v1, tests.

Important rule:

- Public key should be treated as immutable in v1 unless we deliberately design rotation semantics.

## Phase 3 - Messaging Core

Goal: two users can exchange encrypted messages online, and offline users receive them on reconnect.

PRs:

1. `feature/ws-hub` - authenticated WebSocket upgrade, connection hub, graceful disconnect handling, concurrency tests.
2. `feature/message-send` - event envelope, ciphertext validation, persistence, fan-out to online recipient, delivery acknowledgment.
3. `feature/message-sync` - flush pending messages on reconnect, conversation list, paginated history, ordering rules.

Message lifecycle in MVP:

- `sent`
- `accepted`
- `delivered`

Key technical notes:

- Server validates structure, not meaning, of ciphertext payloads.
- Ordering does not rely on timestamps alone.
- `conversation_id + sequence_number` is the default ordering model.

## Phase 4 - Web Client MVP

Goal: two real users can chat from a browser, including iPhone Safari.

Baseline stack:

- React
- Vite
- TypeScript
- PWA-ready from the start

PRs:

1. `feature/web-client-shell` - app shell, routing, responsive layout, register/login screens, key generation boundary, durable storage boundary.
2. `feature/web-client-chat` - contact lookup, conversation list, chat screen, WebSocket lifecycle, encrypt before send, decrypt after receive, iPhone Safari QA.

Client rules:

- Crypto lives behind a `CryptoAdapter`.
- Key persistence uses IndexedDB.
- JWT access token stays in memory.
- Refresh token lives in an `HttpOnly` cookie.

## Phase 5 - Alpha Deployment

Goal: 5-20 trusted users can use Phantom in production.

PR:

1. `chore/alpha-deploy` - Dockerfile, reverse proxy, production compose, backups, monitoring, invite issuance, user disable / ban flow, repeatable deployment script.

Operational assumptions:

- One VPS is enough for alpha.
- Production should be repeatable from one documented deploy flow.
- Backups matter before scale matters.

## Definition of Done for Alpha

The alpha is ready when all of the following are true:

- two real users can register with invite codes and log in
- both can exchange encrypted text messages from browser and iPhone Safari
- messages arrive in real time when both are online
- offline messages are delivered on reconnect
- server logs contain zero plaintext content
- ciphertext survives server restarts
- deployment is repeatable from a single documented flow

## Phase 6 - Post-Alpha Hardening

After real users exist, priorities should follow actual pain, not imagined roadmap aesthetics.

Likely candidates:

- delivered and read receipt refinement
- typing indicators
- better contact management
- PWA install improvements
- basic account settings
- admin dashboard for invite management
- key export / import for backup

## Deferred - Near Term

These are real features, but they should not block shipping:

- native iOS app
- push notifications
- group chats
- media messages

Notes:

- Native iOS should wait until the protocol and browser UX are stable.
- Push should wait until there is evidence that alpha users actually need it.
- Group chats should wait until 1-to-1 semantics and key lifecycle are stable.
- Media should come after text, likely starting with the simplest encrypted upload path rather than full-blown rich media.

## Deferred - Long Term

These are directionally good, but they are not immediate product work:

- transport over Tor / I2P
- mesh / offline transport
- multi-device support
- stronger metadata protection
- any payment or premium system

Important notes:

- Transport abstraction should exist early even if only WebSocket is implemented now.
- Mesh networking is an architectural direction, not an alpha feature.
- Multi-device support is a key-management project, not just a sync feature.
- Payments are explicitly deferred until the core messenger is usable by real people.

## Security Roadmap

### v1

- TLS 1.3 transport
- blind relay server model
- client-side key generation
- password hashing with Argon2id
- JWT + refresh rotation
- rate limiting and account lockout

### v2

- stronger key lifecycle
- better session evolution
- forward-secrecy-oriented protocol improvements

### v3

- deeper metadata protection
- key transparency ideas
- third-party security audit

## Open Questions After Alpha

These are worth revisiting later, but they should not block the current auth and messaging slices:

- Should optional key export / import exist before a wider beta?
- Should push notifications land before native iOS, or only after native exists?
- Does optional recovery ever belong in the product, or should account loss stay the honest default?

## Rules for Ongoing Development

- One feature or fix per branch.
- One meaningful capability per PR.
- Tests ship in the same branch as the feature.
- `main` stays green.
- Ship a thin working slice over half-built infrastructure.
- Never log message content.
- Never store plaintext.

## Summary: What to Build When

Now:

- auth
- user directory
- WebSocket hub
- 1-to-1 messaging and delivery
- web client MVP
- alpha deployment and invites

Soon after alpha:

- better receipts
- typing indicators
- account settings
- key backup
- native iOS
- push notifications

Later:

- group chats
- media
- transport expansion
- stronger cryptographic session model
- multi-device
- anonymous payments

Never as a prerequisite for shipping alpha:

- custom blockchain
- full mesh transport
- speculative token economy

## Reference Notes

These references informed the roadmap and the platform constraints above:

- [WebKit: Web Push for Web Apps on iOS and iPadOS](https://webkit.org/blog/13878/web-push-for-web-apps-on-ios-and-ipados/)
- [WebKit: Safari 16.4 features](https://webkit.org/blog/13966/webkit-features-in-safari-16-4/)
- [MDN: Secure contexts](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Secure_Contexts)
- [MDN: IndexedDB API](https://developer.mozilla.org/en-US/docs/Web/API/IndexedDB_API)
- [MDN: WorkerGlobalScope.indexedDB](https://developer.mozilla.org/en-US/docs/Web/API/WorkerGlobalScope/indexedDB)
- [MDN: Web Locks API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Locks_API)
- [MDN: SubtleCrypto.generateKey()](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey)
- [MDN: SubtleCrypto.encrypt()](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt)
- [MDN: AesKeyGenParams](https://developer.mozilla.org/en-US/docs/Web/API/AesKeyGenParams)
- [GitHub Changelog: Deprecation of Node 20 on GitHub Actions runners](https://github.blog/changelog/2025-09-19-deprecation-of-node-20-on-github-actions-runners/)
