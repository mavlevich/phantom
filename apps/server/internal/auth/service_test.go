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

func TestLoginSuccess(t *testing.T) {
	now := time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC)
	userID := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	expiresAt := now.Add(15 * time.Minute)

	repo := &registerRepoStub{
		user: &User{
			ID:           userID,
			Username:     "Alice123",
			PasswordHash: "hashed-password",
		},
	}

	svc := &service{
		repo:         repo,
		now:          func() time.Time { return now },
		newID:        uuid.New,
		hashPassword: HashPassword,
		verifyPassword: func(password, hash string) (bool, error) {
			if password != "strong-password-123" || hash != "hashed-password" {
				t.Fatalf("verifyPassword() got (%q, %q)", password, hash)
			}
			return true, nil
		},
		issueAccessToken: func(user *User, issuedAt time.Time) (string, time.Time, error) {
			if user.ID != userID {
				t.Fatalf("issueAccessToken() user.ID = %v, want %v", user.ID, userID)
			}
			if !issuedAt.Equal(now) {
				t.Fatalf("issueAccessToken() issuedAt = %v, want %v", issuedAt, now)
			}
			return "access-token", expiresAt, nil
		},
	}

	result, err := svc.Login(context.Background(), LoginInput{
		Username: "Alice123",
		Password: "strong-password-123",
	})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if result.AccessToken != "access-token" {
		t.Fatalf("Login() access token = %q, want access-token", result.AccessToken)
	}
	if result.TokenType != "Bearer" {
		t.Fatalf("Login() token type = %q, want Bearer", result.TokenType)
	}
	if !result.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("Login() expires_at = %v, want %v", result.ExpiresAt, expiresAt)
	}
	if result.UserID != userID {
		t.Fatalf("Login() user id = %v, want %v", result.UserID, userID)
	}
}

func TestLoginRejectsUnknownUser(t *testing.T) {
	verifyCalls := 0
	svc := &service{
		repo: &registerRepoStub{},
		now:  func() time.Time { return time.Now().UTC() },
		verifyPassword: func(password, hash string) (bool, error) {
			verifyCalls++
			if password != "strong-password-123" {
				t.Fatalf("verifyPassword() password = %q, want strong-password-123", password)
			}
			if hash != timingPaddingPasswordHash {
				t.Fatalf("verifyPassword() hash = %q, want timing padding hash", hash)
			}
			return false, nil
		},
		issueAccessToken: func(user *User, issuedAt time.Time) (string, time.Time, error) {
			t.Fatal("issueAccessToken() should not be called")
			return "", time.Time{}, nil
		},
	}

	_, err := svc.Login(context.Background(), LoginInput{
		Username: "Alice123",
		Password: "strong-password-123",
	})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login() error = %v, want %v", err, ErrInvalidCredentials)
	}
	if verifyCalls != 1 {
		t.Fatalf("verifyPassword() calls = %d, want 1", verifyCalls)
	}
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	svc := &service{
		repo: &registerRepoStub{
			user: &User{
				ID:           uuid.New(),
				Username:     "Alice123",
				PasswordHash: "hashed-password",
			},
		},
		now: func() time.Time { return time.Now().UTC() },
		verifyPassword: func(password, hash string) (bool, error) {
			return false, nil
		},
		issueAccessToken: func(user *User, issuedAt time.Time) (string, time.Time, error) {
			t.Fatal("issueAccessToken() should not be called")
			return "", time.Time{}, nil
		},
	}

	_, err := svc.Login(context.Background(), LoginInput{
		Username: "Alice123",
		Password: "wrong-password",
	})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login() error = %v, want %v", err, ErrInvalidCredentials)
	}
}

func TestLoginRejectsMalformedUsername(t *testing.T) {
	svc := &service{repo: &registerRepoStub{}}

	_, err := svc.Login(context.Background(), LoginInput{
		Username: "not valid",
		Password: "strong-password-123",
	})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login() error = %v, want %v", err, ErrInvalidCredentials)
	}
}

func TestLoginRejectsEmptyPassword(t *testing.T) {
	svc := &service{repo: &registerRepoStub{}}

	_, err := svc.Login(context.Background(), LoginInput{
		Username: "Alice123",
		Password: "   ",
	})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("Login() error = %v, want %v", err, ErrInvalidCredentials)
	}
}

func TestLoginWrapsRepositoryError(t *testing.T) {
	repoErr := errors.New("db unavailable")
	svc := &service{
		repo: &registerRepoStub{
			findUserErr: repoErr,
		},
	}

	_, err := svc.Login(context.Background(), LoginInput{
		Username: "Alice123",
		Password: "strong-password-123",
	})
	if err == nil {
		t.Fatal("Login() error = nil, want wrapped repository error")
	}
	if !errors.Is(err, repoErr) {
		t.Fatalf("Login() error = %v, want wrapped %v", err, repoErr)
	}
}

func TestLoginWrapsVerifyPasswordFailure(t *testing.T) {
	verifyErr := errors.New("hash decode failed")
	svc := &service{
		repo: &registerRepoStub{
			user: &User{
				ID:           uuid.New(),
				Username:     "Alice123",
				PasswordHash: "hashed-password",
			},
		},
		verifyPassword: func(password, hash string) (bool, error) {
			return false, verifyErr
		},
	}

	_, err := svc.Login(context.Background(), LoginInput{
		Username: "Alice123",
		Password: "strong-password-123",
	})
	if err == nil {
		t.Fatal("Login() error = nil, want wrapped verify error")
	}
	if !errors.Is(err, verifyErr) {
		t.Fatalf("Login() error = %v, want wrapped %v", err, verifyErr)
	}
}

func TestLoginWrapsTimingPaddingVerifyFailure(t *testing.T) {
	verifyErr := errors.New("padding hash decode failed")
	svc := &service{
		repo: &registerRepoStub{},
		verifyPassword: func(password, hash string) (bool, error) {
			if hash != timingPaddingPasswordHash {
				t.Fatalf("verifyPassword() hash = %q, want timing padding hash", hash)
			}
			return false, verifyErr
		},
	}

	_, err := svc.Login(context.Background(), LoginInput{
		Username: "Alice123",
		Password: "strong-password-123",
	})
	if err == nil {
		t.Fatal("Login() error = nil, want wrapped verify error")
	}
	if !errors.Is(err, verifyErr) {
		t.Fatalf("Login() error = %v, want wrapped %v", err, verifyErr)
	}
}

func TestLoginWrapsAccessTokenFailure(t *testing.T) {
	issueErr := errors.New("jwt signer unavailable")
	svc := &service{
		repo: &registerRepoStub{
			user: &User{
				ID:           uuid.New(),
				Username:     "Alice123",
				PasswordHash: "hashed-password",
			},
		},
		verifyPassword: func(password, hash string) (bool, error) {
			return true, nil
		},
		issueAccessToken: func(user *User, issuedAt time.Time) (string, time.Time, error) {
			return "", time.Time{}, issueErr
		},
	}

	_, err := svc.Login(context.Background(), LoginInput{
		Username: "Alice123",
		Password: "strong-password-123",
	})
	if err == nil {
		t.Fatal("Login() error = nil, want wrapped token error")
	}
	if !errors.Is(err, issueErr) {
		t.Fatalf("Login() error = %v, want wrapped %v", err, issueErr)
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
