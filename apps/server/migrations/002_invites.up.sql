-- 002_invites.up.sql
-- Admin-issued invite codes for alpha registration

CREATE TABLE invites (
    code            VARCHAR(64) PRIMARY KEY,
    created_by      TEXT        NOT NULL DEFAULT 'admin',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,
    used_at         TIMESTAMPTZ,
    used_by_user_id UUID        REFERENCES users(id) ON DELETE SET NULL,
    CHECK (
        (used_at IS NULL AND used_by_user_id IS NULL) OR
        (used_at IS NOT NULL AND used_by_user_id IS NOT NULL)
    )
);

CREATE INDEX idx_invites_unused
    ON invites(code)
    WHERE used_at IS NULL;
