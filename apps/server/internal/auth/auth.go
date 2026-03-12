package auth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Sentinel errors - callers check these with errors.Is()
var (
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrTokenExpired       = errors.New("token expired")
	ErrTokenInvalid       = errors.New("token invalid")
	ErrAccountLocked      = errors.New("account temporarily locked")
)

// User represents the auth identity (not the full profile - that's in user package)
type User struct {
	ID           uuid.UUID
	Username     string
	PasswordHash string
	PublicKey    []byte // X25519 public key, base64-encoded, set on registration
	CreatedAt    time.Time
}

// Tokens returned after successful auth
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"` // seconds
}

// RegisterInput from client
type RegisterInput struct {
	Username  string `json:"username" validate:"required,min=3,max=32,alphanum"`
	Password  string `json:"password" validate:"required,min=12"`
	PublicKey string `json:"public_key" validate:"required"` // base64 X25519 public key
}

// LoginInput from client
type LoginInput struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}

// Service defines the auth business logic contract
// This interface makes it easy to mock in tests
type Service interface {
	Register(ctx context.Context, input RegisterInput) (*TokenPair, error)
	Login(ctx context.Context, input LoginInput) (*TokenPair, error)
	Refresh(ctx context.Context, refreshToken string) (*TokenPair, error)
	Logout(ctx context.Context, refreshToken string) error
	ValidateAccessToken(ctx context.Context, token string) (uuid.UUID, error)
}

// Repository defines the storage contract for auth
type Repository interface {
	CreateUser(ctx context.Context, user *User) error
	FindUserByUsername(ctx context.Context, username string) (*User, error)
	FindUserByID(ctx context.Context, id uuid.UUID) (*User, error)

	StoreRefreshToken(ctx context.Context, userID uuid.UUID, token string, expiry time.Duration) error
	ValidateRefreshToken(ctx context.Context, token string) (uuid.UUID, error)
	DeleteRefreshToken(ctx context.Context, token string) error
	DeleteAllUserTokens(ctx context.Context, userID uuid.UUID) error
}
