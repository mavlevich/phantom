package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	minPasswordLength = 12
	minPublicKeyBytes = 32
	maxPublicKeyBytes = 512
)

var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9]{3,32}$`)

type service struct {
	repo             Repository
	now              func() time.Time
	newID            func() uuid.UUID
	hashPassword     func(string) (string, error)
	verifyPassword   func(string, string) (bool, error)
	issueAccessToken func(*User, time.Time) (string, time.Time, error)
}

func NewService(repo Repository, configs ...ServiceConfig) Service {
	cfg := ServiceConfig{}
	if len(configs) > 0 {
		cfg = configs[0]
	}

	return &service{
		repo:           repo,
		now:            func() time.Time { return time.Now().UTC() },
		newID:          uuid.New,
		hashPassword:   HashPassword,
		verifyPassword: VerifyPassword,
		issueAccessToken: newAccessTokenIssuer(
			cfg.JWTSecret,
			cfg.JWTExpiry,
			uuid.New,
		),
	}
}

func (s *service) Register(ctx context.Context, input RegisterInput) (*RegisterResult, error) {
	username, err := validateUsername(input.Username)
	if err != nil {
		return nil, err
	}
	if err := validatePassword(input.Password); err != nil {
		return nil, err
	}

	publicKey, err := validatePublicKey(input.PublicKey)
	if err != nil {
		return nil, err
	}

	inviteCode := strings.TrimSpace(input.InviteCode)
	if inviteCode == "" {
		return nil, ErrInviteNotFound
	}

	invite, err := s.repo.FindInviteByCode(ctx, inviteCode)
	if err != nil {
		if errors.Is(err, ErrInviteNotFound) {
			return nil, ErrInviteNotFound
		}
		return nil, fmt.Errorf("auth.Register: find invite by code: %w", err)
	}
	if invite == nil {
		return nil, ErrInviteNotFound
	}

	now := s.currentTime()
	if invite.UsedAt != nil {
		return nil, ErrInviteAlreadyUsed
	}
	if invite.ExpiresAt != nil && !invite.ExpiresAt.After(now) {
		return nil, ErrInviteExpired
	}

	existingUser, err := s.repo.FindUserByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("auth.Register: find user by username: %w", err)
	}
	if existingUser != nil {
		return nil, ErrUserAlreadyExists
	}

	passwordHash, err := s.passwordHasher()(input.Password)
	if err != nil {
		return nil, fmt.Errorf("auth.Register: hash password: %w", err)
	}

	user := &User{
		ID:           s.uuidGenerator()(),
		Username:     username,
		PasswordHash: passwordHash,
		PublicKey:    publicKey,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.repo.CreateUserFromInvite(ctx, user, inviteCode, now); err != nil {
		switch {
		case errors.Is(err, ErrUserAlreadyExists):
			return nil, ErrUserAlreadyExists
		case errors.Is(err, ErrInviteNotFound):
			return nil, ErrInviteNotFound
		case errors.Is(err, ErrInviteAlreadyUsed):
			return nil, ErrInviteAlreadyUsed
		case errors.Is(err, ErrInviteExpired):
			return nil, ErrInviteExpired
		default:
			return nil, fmt.Errorf("auth.Register: create user from invite: %w", err)
		}
	}

	return &RegisterResult{
		UserID:    user.ID,
		Username:  user.Username,
		CreatedAt: user.CreatedAt,
	}, nil
}

func (s *service) Login(ctx context.Context, input LoginInput) (*LoginResult, error) {
	username, err := normalizeLoginUsername(input.Username)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(input.Password) == "" {
		return nil, ErrInvalidCredentials
	}

	user, err := s.repo.FindUserByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("auth.Login: find user by username: %w", err)
	}
	if user == nil {
		if _, err := s.passwordVerifier()(input.Password, timingPaddingPasswordHash); err != nil {
			return nil, fmt.Errorf("auth.Login: verify timing padding password: %w", err)
		}
		return nil, ErrInvalidCredentials
	}

	ok, err := s.passwordVerifier()(input.Password, user.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("auth.Login: verify password: %w", err)
	}
	if !ok {
		return nil, ErrInvalidCredentials
	}

	now := s.currentTime()
	accessToken, expiresAt, err := s.accessTokenIssuer()(user, now)
	if err != nil {
		return nil, fmt.Errorf("auth.Login: issue access token: %w", err)
	}

	return &LoginResult{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresAt:   expiresAt,
		UserID:      user.ID,
		Username:    user.Username,
	}, nil
}

func validateUsername(username string) (string, error) {
	trimmed := strings.TrimSpace(username)
	if !usernamePattern.MatchString(trimmed) {
		return "", ErrInvalidUsername
	}
	return trimmed, nil
}

func validatePassword(password string) error {
	if len(password) < minPasswordLength {
		return ErrWeakPassword
	}
	return nil
}

func normalizeLoginUsername(username string) (string, error) {
	trimmed := strings.TrimSpace(username)
	if !usernamePattern.MatchString(trimmed) {
		return "", ErrInvalidCredentials
	}
	return trimmed, nil
}

func validatePublicKey(encoded string) (string, error) {
	candidate := strings.TrimSpace(encoded)
	if candidate == "" {
		return "", ErrInvalidPublicKey
	}

	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		decoded, err := enc.DecodeString(candidate)
		if err != nil {
			continue
		}
		if len(decoded) < minPublicKeyBytes || len(decoded) > maxPublicKeyBytes {
			return "", ErrInvalidPublicKey
		}
		return base64.RawStdEncoding.EncodeToString(decoded), nil
	}

	return "", ErrInvalidPublicKey
}

func (s *service) currentTime() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now().UTC()
}

func (s *service) uuidGenerator() func() uuid.UUID {
	if s.newID != nil {
		return s.newID
	}
	return uuid.New
}

func (s *service) passwordHasher() func(string) (string, error) {
	if s.hashPassword != nil {
		return s.hashPassword
	}
	return HashPassword
}

func (s *service) passwordVerifier() func(string, string) (bool, error) {
	if s.verifyPassword != nil {
		return s.verifyPassword
	}
	return VerifyPassword
}

func (s *service) accessTokenIssuer() func(*User, time.Time) (string, time.Time, error) {
	if s.issueAccessToken != nil {
		return s.issueAccessToken
	}
	return newAccessTokenIssuer("", 15*time.Minute, s.uuidGenerator())
}
