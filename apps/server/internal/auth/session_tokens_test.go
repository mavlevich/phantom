package auth

import (
	"testing"
	"time"
)

func TestNewRefreshTokenGeneratorSuccess(t *testing.T) {
	now := time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
	generate := newRefreshTokenGenerator(24 * time.Hour)

	token, tokenHash, expiresAt, err := generate(now)
	if err != nil {
		t.Fatalf("generate() error = %v", err)
	}
	if token == "" {
		t.Fatal("generate() token is empty")
	}
	if tokenHash == "" {
		t.Fatal("generate() token hash is empty")
	}
	if tokenHash != hashRefreshToken(token) {
		t.Fatalf("token hash = %q, want %q", tokenHash, hashRefreshToken(token))
	}
	if !expiresAt.Equal(now.Add(24 * time.Hour)) {
		t.Fatalf("expiresAt = %v, want %v", expiresAt, now.Add(24*time.Hour))
	}
}
