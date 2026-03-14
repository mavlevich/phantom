package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const accessTokenIssuer = "phantom"

func newAccessTokenIssuer(secret string, expiry time.Duration, newTokenID func() uuid.UUID) func(*User, time.Time) (string, time.Time, error) {
	if expiry <= 0 {
		expiry = 15 * time.Minute
	}

	secretBytes := []byte(secret)

	return func(user *User, now time.Time) (string, time.Time, error) {
		if len(secretBytes) == 0 {
			return "", time.Time{}, fmt.Errorf("jwt secret is not configured")
		}

		expiresAt := now.Add(expiry)
		claims := jwt.RegisteredClaims{
			Issuer:    accessTokenIssuer,
			Subject:   user.ID.String(),
			ID:        newTokenID().String(),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signed, err := token.SignedString(secretBytes)
		if err != nil {
			return "", time.Time{}, fmt.Errorf("sign access token: %w", err)
		}

		return signed, expiresAt, nil
	}
}
