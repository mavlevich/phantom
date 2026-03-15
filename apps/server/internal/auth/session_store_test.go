package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	redismock "github.com/go-redis/redismock/v9"
	"github.com/google/uuid"
)

func TestRedisSessionStoreRefreshTokenLifecycle(t *testing.T) {
	store, mock := newTestRedisSessionStore(t)

	userID := uuid.New()
	expiresAt := time.Now().UTC().Add(time.Hour).Round(time.Second)
	ttl := time.Until(expiresAt).Round(time.Second)

	mock.ExpectSet(refreshTokenKey("refresh-hash"), userID.String(), ttl).SetVal("OK")
	if err := store.StoreRefreshToken(context.Background(), "refresh-hash", userID, expiresAt); err != nil {
		t.Fatalf("StoreRefreshToken() error = %v", err)
	}

	mock.ExpectGetDel(refreshTokenKey("refresh-hash")).SetVal(userID.String())
	session, err := store.ConsumeRefreshToken(context.Background(), "refresh-hash")
	if err != nil {
		t.Fatalf("ConsumeRefreshToken() error = %v", err)
	}
	if session == nil {
		t.Fatal("ConsumeRefreshToken() = nil, want session")
	}
	if session.UserID != userID {
		t.Fatalf("session.UserID = %v, want %v", session.UserID, userID)
	}

	mock.ExpectGetDel(refreshTokenKey("refresh-hash")).RedisNil()
	session, err = store.ConsumeRefreshToken(context.Background(), "refresh-hash")
	if err != nil {
		t.Fatalf("ConsumeRefreshToken() second call error = %v", err)
	}
	if session != nil {
		t.Fatalf("ConsumeRefreshToken() second call = %v, want nil", session)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations: %v", err)
	}
}

func TestRedisSessionStoreRejectsPastExpiry(t *testing.T) {
	store, mock := newTestRedisSessionStore(t)

	err := store.StoreRefreshToken(context.Background(), "refresh-hash", uuid.New(), time.Now().UTC().Add(-time.Second))
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("StoreRefreshToken() error = %v, want %v", err, ErrTokenExpired)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations: %v", err)
	}
}

func TestRedisSessionStoreLocksAccountAfterThreshold(t *testing.T) {
	store, mock := newTestRedisSessionStore(t)

	for i := int64(1); i < defaultFailedLoginLimit; i++ {
		next := i
		mock.ExpectIncr(failedLoginKey("alice123")).SetVal(next)
		if next == 1 {
			mock.ExpectExpire(failedLoginKey("alice123"), defaultFailedLoginWindow).SetVal(true)
		}
		locked, err := store.RegisterFailedLogin(context.Background(), "alice123", time.Now().UTC())
		if err != nil {
			t.Fatalf("RegisterFailedLogin() error = %v", err)
		}
		if locked {
			t.Fatal("RegisterFailedLogin() locked too early")
		}
	}

	mock.ExpectIncr(failedLoginKey("alice123")).SetVal(defaultFailedLoginLimit)
	mock.ExpectSet(accountLockKey("alice123"), "1", defaultLockoutDuration).SetVal("OK")
	mock.ExpectDel(failedLoginKey("alice123")).SetVal(1)
	locked, err := store.RegisterFailedLogin(context.Background(), "alice123", time.Now().UTC())
	if err != nil {
		t.Fatalf("RegisterFailedLogin() threshold error = %v", err)
	}
	if !locked {
		t.Fatal("RegisterFailedLogin() did not lock account at threshold")
	}

	mock.ExpectExists(accountLockKey("alice123")).SetVal(1)
	isLocked, err := store.IsAccountLocked(context.Background(), "alice123")
	if err != nil {
		t.Fatalf("IsAccountLocked() error = %v", err)
	}
	if !isLocked {
		t.Fatal("IsAccountLocked() = false, want true")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations: %v", err)
	}
}

func TestRedisSessionStoreAllowsRequestsWithinWindow(t *testing.T) {
	store, mock := newTestRedisSessionStore(t)

	for i := 1; i <= 3; i++ {
		mock.ExpectIncr(rateLimitKey("login:127.0.0.1")).SetVal(int64(i))
		if i == 1 {
			mock.ExpectExpire(rateLimitKey("login:127.0.0.1"), time.Minute).SetVal(true)
		}
		allowed, err := store.AllowRequest(context.Background(), "login:127.0.0.1", 3, time.Minute)
		if err != nil {
			t.Fatalf("AllowRequest() error = %v", err)
		}
		if !allowed {
			t.Fatalf("AllowRequest() = false on iteration %d, want true", i-1)
		}
	}

	mock.ExpectIncr(rateLimitKey("login:127.0.0.1")).SetVal(4)
	allowed, err := store.AllowRequest(context.Background(), "login:127.0.0.1", 3, time.Minute)
	if err != nil {
		t.Fatalf("AllowRequest() overflow error = %v", err)
	}
	if allowed {
		t.Fatal("AllowRequest() = true after limit, want false")
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("redis expectations: %v", err)
	}
}

func newTestRedisSessionStore(t *testing.T) (*redisSessionStore, redismock.ClientMock) {
	t.Helper()

	client, mock := redismock.NewClientMock()
	if client == nil {
		t.Fatal("redismock.NewClientMock() returned nil client")
	}

	return NewRedisSessionStore(client).(*redisSessionStore), mock
}
