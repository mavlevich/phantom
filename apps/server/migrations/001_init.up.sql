-- 001_init.up.sql
-- Initial schema for Phantom

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username      VARCHAR(32) NOT NULL UNIQUE,
    password_hash TEXT        NOT NULL,
    public_key    TEXT        NOT NULL, -- base64 client-generated public key material
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_username ON users(username);

-- Messages: server stores only encrypted blobs
-- IMPORTANT: ciphertext is never decrypted server-side
CREATE TABLE messages (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sender_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id  UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ephemeral_key TEXT        NOT NULL, -- base64 X25519 ephemeral public key
    nonce         TEXT        NOT NULL, -- base64 12-byte nonce
    ciphertext    TEXT        NOT NULL, -- base64 ChaCha20-Poly1305 ciphertext
    sent_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at  TIMESTAMPTZ          -- NULL = pending delivery
);

CREATE INDEX idx_messages_recipient_pending
    ON messages(recipient_id)
    WHERE delivered_at IS NULL;

CREATE INDEX idx_messages_sender ON messages(sender_id);
