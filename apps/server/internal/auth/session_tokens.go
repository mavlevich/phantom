package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"
)

func newRefreshTokenGenerator(expiry time.Duration) func(time.Time) (string, string, time.Time, error) {
	if expiry <= 0 {
		expiry = 30 * 24 * time.Hour
	}

	return func(now time.Time) (string, string, time.Time, error) {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return "", "", time.Time{}, fmt.Errorf("read refresh token entropy: %w", err)
		}

		token := base64.RawURLEncoding.EncodeToString(raw)
		hash := sha256.Sum256([]byte(token))
		expiresAt := now.Add(expiry)

		return token, hex.EncodeToString(hash[:]), expiresAt, nil
	}
}

func hashRefreshToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
