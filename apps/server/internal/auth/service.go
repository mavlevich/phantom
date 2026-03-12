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
	repo         Repository
	now          func() time.Time
	newID        func() uuid.UUID
	hashPassword func(string) (string, error)
}

func NewService(repo Repository) Service {
	return &service{
		repo:         repo,
		now:          func() time.Time { return time.Now().UTC() },
		newID:        uuid.New,
		hashPassword: HashPassword,
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

	now := s.now()
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

	passwordHash, err := s.hashPassword(input.Password)
	if err != nil {
		return nil, fmt.Errorf("auth.Register: hash password: %w", err)
	}

	user := &User{
		ID:           s.newID(),
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
