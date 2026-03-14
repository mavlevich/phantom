# Phantom Security Model

## Threat Model

**What we protect against:**
- Server compromise (zero-knowledge design)
- Network interception (TLS + E2E encryption)
- Metadata leakage (minimal server-side logging)
- Token theft (short JWT expiry, refresh rotation)
- Brute force (rate limiting, account lockout)

**What we do NOT protect against (v1):**
- Compromised client device
- Malicious app updates
- Forward secrecy (planned for v2 - Double Ratchet)

---

## Encryption Stack

```
Transport:   TLS 1.3 (server <-> client)
Key Exchange: X25519 (ECDH)
Encryption:  ChaCha20-Poly1305 (AEAD)
Key Derivation: HKDF-SHA256
Signing:     Ed25519
```

### Key Exchange Flow (X3DH simplified)

```
1. Alice registers -> publishes public key (IK_A) to server
2. Bob registers   -> publishes public key (IK_B) to server

3. Alice wants to message Bob:
   a. Fetches IK_B from server
   b. Generates ephemeral key pair (EK_A)
   c. DH1 = X25519(IK_A_private, IK_B)
   d. DH2 = X25519(EK_A_private, IK_B)
   e. SharedSecret = HKDF(DH1 || DH2)
   f. Encrypts message with ChaCha20-Poly1305(SharedSecret)
   g. Sends { ciphertext, EK_A_public } to server

4. Server relays { ciphertext, EK_A_public } to Bob
5. Bob reconstructs SharedSecret and decrypts
```

### Message Format (on wire)

```json
{
  "id": "uuid",
  "to": "user_id",
  "ephemeral_key": "base64(EK_A_public)",
  "nonce": "base64(12_random_bytes)",
  "ciphertext": "base64(encrypted_payload)",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

Server stores and forwards this blob. Cannot decrypt.

---

## Authentication

- **Registration:** username + password (Argon2id hashing, never stored plaintext)
- **Login:** returns `access_token` (JWT, 15min)
- **Credential privacy:** login returns generic credential errors and uses timing padding on unknown usernames to reduce account enumeration via response timing
- **Next auth slice:** refresh token rotation, revocation, rate limiting, and account lockout

### JWT Claims

```json
{
  "iss": "phantom",
  "sub": "user_uuid",
  "iat": 1234567890,
  "exp": 1234568790,
  "jti": "unique_token_id"
}
```

No user data in JWT. Server fetches user from DB on demand.

---

## Server-Side Privacy Rules

1. **No message content logging** - enforced at middleware level
2. **No plaintext storage** - only ciphertext blobs persisted
3. **Minimal metadata** - store: sender_id, recipient_id, timestamp, delivered_at
4. **Push notifications** - send only "new message" signal, never content
5. **IP addresses** - not stored in DB (can appear in server access logs, separate from app logs)

Important limitation for alpha:

- E2E encryption protects message content, but not the full social graph. The server can still know which account talks to which account, and group membership remains metadata unless later phases explicitly hide it.

---

## Planned for v2

- **Double Ratchet Algorithm** - Forward + Future Secrecy
- **Sealed Sender** - hide sender metadata from server
- **Key Transparency** - auditable key log to prevent MITM
- **Device verification** - safety numbers / QR code verification
