package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRegisterSuccess(t *testing.T) {
	now := time.Date(2026, 3, 12, 10, 0, 0, 0, time.UTC)
	userID := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	publicKey := mustPublicKey(t)

	repo := &registerRepoStub{
		invite: &Invite{
			Code:      "ALPHA-INVITE-001",
			CreatedBy: "admin",
			CreatedAt: now.Add(-time.Hour),
		},
	}

	svc := &service{
		repo:  repo,
		now:   func() time.Time { return now },
		newID: func() uuid.UUID { return userID },
		hashPassword: func(password string) (string, error) {
			if password != "strong-password-123" {
				t.Fatalf("hashPassword() received %q, want strong-password-123", password)
			}
			return "hashed-password", nil
		},
	}

	result, err := svc.Register(context.Background(), RegisterInput{
		Username:   "Alice123",
		Password:   "strong-password-123",
		PublicKey:  publicKey,
		InviteCode: "ALPHA-INVITE-001",
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	if result.UserID != userID {
		t.Fatalf("Register() user id = %v, want %v", result.UserID, userID)
	}
	if result.Username != "Alice123" {
		t.Fatalf("Register() username = %q, want Alice123", result.Username)
	}
	if !result.CreatedAt.Equal(now) {
		t.Fatalf("Register() created_at = %v, want %v", result.CreatedAt, now)
	}

	if repo.createdUser == nil {
		t.Fatal("CreateUserFromInvite() was not called")
	}
	if repo.createdUser.PasswordHash != "hashed-password" {
		t.Fatalf("created password hash = %q, want hashed-password", repo.createdUser.PasswordHash)
	}
	if repo.createdInviteCode != "ALPHA-INVITE-001" {
		t.Fatalf("created invite code = %q, want ALPHA-INVITE-001", repo.createdInviteCode)
	}
	if !repo.usedAt.Equal(now) {
		t.Fatalf("usedAt = %v, want %v", repo.usedAt, now)
	}
	if repo.createdUser.PublicKey != publicKey {
		t.Fatalf("public key = %q, want %q", repo.createdUser.PublicKey, publicKey)
	}
}

func TestRegisterRejectsDuplicateUsername(t *testing.T) {
	repo := &registerRepoStub{
		invite: &Invite{
			Code:      "ALPHA-INVITE-001",
			CreatedBy: "admin",
			CreatedAt: time.Now().UTC(),
		},
		user: &User{Username: "Alice123"},
	}

	svc := &service{
		repo:         repo,
		now:          func() time.Time { return time.Now().UTC() },
		newID:        uuid.New,
		hashPassword: func(password string) (string, error) { return "unused", nil },
	}

	_, err := svc.Register(context.Background(), RegisterInput{
		Username:   "Alice123",
		Password:   "strong-password-123",
		PublicKey:  mustPublicKey(t),
		InviteCode: "ALPHA-INVITE-001",
	})
	if !errors.Is(err, ErrUserAlreadyExists) {
		t.Fatalf("Register() error = %v, want %v", err, ErrUserAlreadyExists)
	}
}

func TestRegisterRejectsMissingInvite(t *testing.T) {
	repo := &registerRepoStub{}

	svc := &service{
		repo:         repo,
		now:          func() time.Time { return time.Now().UTC() },
		newID:        uuid.New,
		hashPassword: func(password string) (string, error) { return "unused", nil },
	}

	_, err := svc.Register(context.Background(), RegisterInput{
		Username:   "Alice123",
		Password:   "strong-password-123",
		PublicKey:  mustPublicKey(t),
		InviteCode: "UNKNOWN",
	})
	if !errors.Is(err, ErrInviteNotFound) {
		t.Fatalf("Register() error = %v, want %v", err, ErrInviteNotFound)
	}
	if repo.findUserCalls != 0 {
		t.Fatalf("FindUserByUsername() calls = %d, want 0 when invite is invalid", repo.findUserCalls)
	}
}

func TestRegisterRejectsNilInviteResult(t *testing.T) {
	repo := &registerRepoStub{}

	svc := &service{
		repo:         repo,
		now:          func() time.Time { return time.Now().UTC() },
		newID:        uuid.New,
		hashPassword: func(password string) (string, error) { return "unused", nil },
	}

	_, err := svc.Register(context.Background(), RegisterInput{
		Username:   "Alice123",
		Password:   "strong-password-123",
		PublicKey:  mustPublicKey(t),
		InviteCode: "ALPHA-INVITE-001",
	})
	if !errors.Is(err, ErrInviteNotFound) {
		t.Fatalf("Register() error = %v, want %v", err, ErrInviteNotFound)
	}
}

func TestRegisterRejectsUsedInvite(t *testing.T) {
	usedAt := time.Now().UTC()
	repo := &registerRepoStub{
		invite: &Invite{
			Code:   "ALPHA-INVITE-001",
			UsedAt: &usedAt,
		},
	}

	svc := &service{
		repo:         repo,
		now:          func() time.Time { return time.Now().UTC() },
		newID:        uuid.New,
		hashPassword: func(password string) (string, error) { return "unused", nil },
	}

	_, err := svc.Register(context.Background(), RegisterInput{
		Username:   "Alice123",
		Password:   "strong-password-123",
		PublicKey:  mustPublicKey(t),
		InviteCode: "ALPHA-INVITE-001",
	})
	if !errors.Is(err, ErrInviteAlreadyUsed) {
		t.Fatalf("Register() error = %v, want %v", err, ErrInviteAlreadyUsed)
	}
}

func TestRegisterRejectsExpiredInvite(t *testing.T) {
	now := time.Date(2026, 3, 12, 10, 0, 0, 0, time.UTC)
	expiresAt := now
	repo := &registerRepoStub{
		invite: &Invite{
			Code:      "ALPHA-INVITE-001",
			ExpiresAt: &expiresAt,
		},
	}

	svc := &service{
		repo:         repo,
		now:          func() time.Time { return now },
		newID:        uuid.New,
		hashPassword: func(password string) (string, error) { return "unused", nil },
	}

	_, err := svc.Register(context.Background(), RegisterInput{
		Username:   "Alice123",
		Password:   "strong-password-123",
		PublicKey:  mustPublicKey(t),
		InviteCode: "ALPHA-INVITE-001",
	})
	if !errors.Is(err, ErrInviteExpired) {
		t.Fatalf("Register() error = %v, want %v", err, ErrInviteExpired)
	}
}

func TestRegisterRejectsWeakPassword(t *testing.T) {
	repo := &registerRepoStub{}
	svc := &service{
		repo:         repo,
		now:          func() time.Time { return time.Now().UTC() },
		newID:        uuid.New,
		hashPassword: func(password string) (string, error) { return "unused", nil },
	}

	_, err := svc.Register(context.Background(), RegisterInput{
		Username:   "Alice123",
		Password:   "short",
		PublicKey:  mustPublicKey(t),
		InviteCode: "ALPHA-INVITE-001",
	})
	if !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("Register() error = %v, want %v", err, ErrWeakPassword)
	}
}

func TestRegisterRejectsInvalidPublicKey(t *testing.T) {
	repo := &registerRepoStub{}
	svc := &service{
		repo:         repo,
		now:          func() time.Time { return time.Now().UTC() },
		newID:        uuid.New,
		hashPassword: func(password string) (string, error) { return "unused", nil },
	}

	_, err := svc.Register(context.Background(), RegisterInput{
		Username:   "Alice123",
		Password:   "strong-password-123",
		PublicKey:  "not-base64",
		InviteCode: "ALPHA-INVITE-001",
	})
	if !errors.Is(err, ErrInvalidPublicKey) {
		t.Fatalf("Register() error = %v, want %v", err, ErrInvalidPublicKey)
	}
}

func TestRegisterAcceptsURLSafePublicKeyAndNormalizesIt(t *testing.T) {
	publicKeyBytes := make([]byte, 32)
	publicKeyBytes[0] = 0xfb
	publicKeyBytes[1] = 0xef
	publicKeyBytes[2] = 0xff
	for i := 3; i < len(publicKeyBytes); i++ {
		publicKeyBytes[i] = byte(i)
	}
	urlSafeKey := base64.RawURLEncoding.EncodeToString(publicKeyBytes)
	expectedKey := base64.RawStdEncoding.EncodeToString(publicKeyBytes)

	repo := &registerRepoStub{
		invite: &Invite{
			Code:      "ALPHA-INVITE-001",
			CreatedBy: "admin",
			CreatedAt: time.Now().UTC(),
		},
	}

	svc := &service{
		repo:  repo,
		now:   func() time.Time { return time.Now().UTC() },
		newID: uuid.New,
		hashPassword: func(password string) (string, error) {
			return "hashed-password", nil
		},
	}

	_, err := svc.Register(context.Background(), RegisterInput{
		Username:   "Alice123",
		Password:   "strong-password-123",
		PublicKey:  urlSafeKey,
		InviteCode: "ALPHA-INVITE-001",
	})
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if repo.createdUser == nil {
		t.Fatal("CreateUserFromInvite() was not called")
	}
	if repo.createdUser.PublicKey != expectedKey {
		t.Fatalf("stored public key = %q, want %q", repo.createdUser.PublicKey, expectedKey)
	}
}

func TestRegisterRejectsInvalidUsername(t *testing.T) {
	repo := &registerRepoStub{}
	svc := &service{
		repo:         repo,
		now:          func() time.Time { return time.Now().UTC() },
		newID:        uuid.New,
		hashPassword: func(password string) (string, error) { return "unused", nil },
	}

	_, err := svc.Register(context.Background(), RegisterInput{
		Username:   "not valid",
		Password:   "strong-password-123",
		PublicKey:  mustPublicKey(t),
		InviteCode: "ALPHA-INVITE-001",
	})
	if !errors.Is(err, ErrInvalidUsername) {
		t.Fatalf("Register() error = %v, want %v", err, ErrInvalidUsername)
	}
}

func TestRegisterWrapsRepositoryCreateError(t *testing.T) {
	repo := &registerRepoStub{
		invite: &Invite{
			Code:      "ALPHA-INVITE-001",
			CreatedBy: "admin",
			CreatedAt: time.Now().UTC(),
		},
		createErr: errors.New("db unavailable"),
	}

	svc := &service{
		repo:  repo,
		now:   func() time.Time { return time.Now().UTC() },
		newID: uuid.New,
		hashPassword: func(password string) (string, error) {
			return "hashed-password", nil
		},
	}

	_, err := svc.Register(context.Background(), RegisterInput{
		Username:   "Alice123",
		Password:   "strong-password-123",
		PublicKey:  mustPublicKey(t),
		InviteCode: "ALPHA-INVITE-001",
	})
	if err == nil {
		t.Fatal("Register() error = nil, want wrapped repository error")
	}
	if !errors.Is(err, repo.createErr) {
		t.Fatalf("Register() error = %v, want wrapped %v", err, repo.createErr)
	}
}

func TestRegisterWrapsPasswordHashFailure(t *testing.T) {
	hashErr := errors.New("argon2 unavailable")
	repo := &registerRepoStub{
		invite: &Invite{
			Code:      "ALPHA-INVITE-001",
			CreatedBy: "admin",
			CreatedAt: time.Now().UTC(),
		},
	}

	svc := &service{
		repo:  repo,
		now:   func() time.Time { return time.Now().UTC() },
		newID: uuid.New,
		hashPassword: func(password string) (string, error) {
			return "", hashErr
		},
	}

	_, err := svc.Register(context.Background(), RegisterInput{
		Username:   "Alice123",
		Password:   "strong-password-123",
		PublicKey:  mustPublicKey(t),
		InviteCode: "ALPHA-INVITE-001",
	})
	if err == nil {
		t.Fatal("Register() error = nil, want wrapped hash error")
	}
	if !errors.Is(err, hashErr) {
		t.Fatalf("Register() error = %v, want wrapped %v", err, hashErr)
	}
}

type registerRepoStub struct {
	user              *User
	invite            *Invite
	findUserErr       error
	findInviteErr     error
	createErr         error
	createdUser       *User
	createdInviteCode string
	usedAt            time.Time
	findUserCalls     int
}

func (r *registerRepoStub) FindUserByUsername(ctx context.Context, username string) (*User, error) {
	r.findUserCalls++
	return r.user, r.findUserErr
}

func (r *registerRepoStub) FindInviteByCode(ctx context.Context, code string) (*Invite, error) {
	if r.findInviteErr != nil {
		return nil, r.findInviteErr
	}
	return r.invite, nil
}

func (r *registerRepoStub) CreateUserFromInvite(ctx context.Context, user *User, inviteCode string, usedAt time.Time) error {
	if r.createErr != nil {
		return r.createErr
	}
	userCopy := *user
	r.createdUser = &userCopy
	r.createdInviteCode = inviteCode
	r.usedAt = usedAt
	return nil
}

func mustPublicKey(t *testing.T) string {
	t.Helper()

	key := make([]byte, 65)
	key[0] = 0x04
	for i := range key {
		if i == 0 {
			continue
		}
		key[i] = byte(i)
	}

	return base64.RawStdEncoding.EncodeToString(key)
}
