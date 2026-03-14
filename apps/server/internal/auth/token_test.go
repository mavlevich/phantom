package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestNewAccessTokenIssuerSuccess(t *testing.T) {
	now := time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC)
	userID := uuid.MustParse("33333333-3333-3333-3333-333333333333")
	tokenID := uuid.MustParse("44444444-4444-4444-4444-444444444444")
	user := &User{
		ID:       userID,
		Username: "alice123",
	}

	issuer := newAccessTokenIssuer("test-secret-key-minimum-32-chars-long", 15*time.Minute, func() uuid.UUID {
		return tokenID
	})

	tokenString, expiresAt, err := issuer(user, now)
	if err != nil {
		t.Fatalf("issuer() error = %v", err)
	}
	if !expiresAt.Equal(now.Add(15 * time.Minute)) {
		t.Fatalf("expiresAt = %v, want %v", expiresAt, now.Add(15*time.Minute))
	}

	parsed, err := jwt.Parse(
		tokenString,
		func(token *jwt.Token) (any, error) {
			return []byte("test-secret-key-minimum-32-chars-long"), nil
		},
		jwt.WithTimeFunc(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatalf("jwt.Parse() error = %v", err)
	}
	if !parsed.Valid {
		t.Fatal("parsed token is invalid")
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("claims type = %T, want jwt.MapClaims", parsed.Claims)
	}
	if claims["sub"] != userID.String() {
		t.Fatalf("sub = %v, want %v", claims["sub"], userID.String())
	}
	if claims["iss"] != accessTokenIssuer {
		t.Fatalf("iss = %v, want %v", claims["iss"], accessTokenIssuer)
	}
	if claims["jti"] != tokenID.String() {
		t.Fatalf("jti = %v, want %v", claims["jti"], tokenID.String())
	}
}

func TestNewAccessTokenIssuerRejectsMissingSecret(t *testing.T) {
	issuer := newAccessTokenIssuer("", 15*time.Minute, uuid.New)

	_, _, err := issuer(&User{ID: uuid.New()}, time.Now().UTC())
	if err == nil {
		t.Fatal("issuer() error = nil, want configuration error")
	}
}
