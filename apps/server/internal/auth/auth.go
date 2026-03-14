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
	ErrInviteNotFound     = errors.New("invite not found")
	ErrInviteAlreadyUsed  = errors.New("invite already used")
	ErrInviteExpired      = errors.New("invite expired")
	ErrInvalidUsername    = errors.New("invalid username")
	ErrWeakPassword       = errors.New("password does not meet minimum requirements")
	ErrInvalidPublicKey   = errors.New("invalid public key")
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
	PublicKey    string // Opaque client-generated public key material, normalized to canonical base64 before storage
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type Invite struct {
	Code         string
	CreatedBy    string
	CreatedAt    time.Time
	ExpiresAt    *time.Time
	UsedAt       *time.Time
	UsedByUserID *uuid.UUID
}

type ServiceConfig struct {
	JWTSecret string
	JWTExpiry time.Duration
}

type RegisterResult struct {
	UserID    uuid.UUID `json:"user_id"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
}

type LoginResult struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	ExpiresAt   time.Time `json:"expires_at"`
	UserID      uuid.UUID `json:"user_id"`
	Username    string    `json:"username"`
}

// RegisterInput from client
type RegisterInput struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	PublicKey  string `json:"public_key"`  // base64-encoded client public key material
	InviteCode string `json:"invite_code"` // single-use invite
}

type LoginInput struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Service defines the auth business logic contract
// This interface makes it easy to mock in tests
type Service interface {
	Register(ctx context.Context, input RegisterInput) (*RegisterResult, error)
	Login(ctx context.Context, input LoginInput) (*LoginResult, error)
}

// Repository defines the storage contract for auth
type Repository interface {
	FindUserByUsername(ctx context.Context, username string) (*User, error)
	FindInviteByCode(ctx context.Context, code string) (*Invite, error)
	CreateUserFromInvite(ctx context.Context, user *User, inviteCode string, usedAt time.Time) error
}
