package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	defaultFailedLoginLimit    = 5
	defaultLockoutDuration     = 15 * time.Minute
	defaultFailedLoginWindow   = 15 * time.Minute
	defaultAuthRateLimit       = 5
	defaultAuthRateLimitWindow = time.Minute
)

type redisSessionStore struct {
	client            *redis.Client
	failedLoginLimit  int64
	lockoutDuration   time.Duration
	failedLoginWindow time.Duration
}

func NewRedisSessionStore(client *redis.Client) SessionStore {
	return &redisSessionStore{
		client:            client,
		failedLoginLimit:  defaultFailedLoginLimit,
		lockoutDuration:   defaultLockoutDuration,
		failedLoginWindow: defaultFailedLoginWindow,
	}
}

func (s *redisSessionStore) StoreRefreshToken(ctx context.Context, tokenHash string, userID uuid.UUID, expiresAt time.Time) error {
	ttl := time.Until(expiresAt).Round(time.Second)
	if ttl <= 0 {
		return ErrTokenExpired
	}

	if err := s.client.Set(ctx, refreshTokenKey(tokenHash), userID.String(), ttl).Err(); err != nil {
		return fmt.Errorf("store refresh token: %w", err)
	}
	return nil
}

func (s *redisSessionStore) ConsumeRefreshToken(ctx context.Context, tokenHash string) (*RefreshSession, error) {
	value, err := s.client.GetDel(ctx, refreshTokenKey(tokenHash)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, fmt.Errorf("consume refresh token: %w", err)
	}

	userID, err := uuid.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("parse refresh token user id: %w", err)
	}

	return &RefreshSession{UserID: userID}, nil
}

func (s *redisSessionStore) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	if tokenHash == "" {
		return nil
	}
	if err := s.client.Del(ctx, refreshTokenKey(tokenHash)).Err(); err != nil {
		return fmt.Errorf("revoke refresh token: %w", err)
	}
	return nil
}

func (s *redisSessionStore) IsAccountLocked(ctx context.Context, username string) (bool, error) {
	locked, err := s.client.Exists(ctx, accountLockKey(username)).Result()
	if err != nil {
		return false, fmt.Errorf("check account lock: %w", err)
	}
	return locked > 0, nil
}

func (s *redisSessionStore) RegisterFailedLogin(ctx context.Context, username string, _ time.Time) (bool, error) {
	failures, err := s.client.Incr(ctx, failedLoginKey(username)).Result()
	if err != nil {
		return false, fmt.Errorf("increment failed login count: %w", err)
	}
	if failures == 1 {
		// Alpha keeps this as a simple INCR+EXPIRE sequence. If we see crashes or
		// contention around this path in production-like traffic, move it to a
		// single Redis script/pipeline so the TTL is attached atomically.
		if err := s.client.Expire(ctx, failedLoginKey(username), s.failedLoginWindow).Err(); err != nil {
			return false, fmt.Errorf("set failed login expiry: %w", err)
		}
	}
	if failures < s.failedLoginLimit {
		return false, nil
	}

	if err := s.client.Set(ctx, accountLockKey(username), "1", s.lockoutDuration).Err(); err != nil {
		return false, fmt.Errorf("set account lock: %w", err)
	}
	if err := s.client.Del(ctx, failedLoginKey(username)).Err(); err != nil {
		return false, fmt.Errorf("clear failed login count after lock: %w", err)
	}

	return true, nil
}

func (s *redisSessionStore) ClearFailedLogins(ctx context.Context, username string) error {
	if err := s.client.Del(ctx, failedLoginKey(username)).Err(); err != nil {
		return fmt.Errorf("clear failed login count: %w", err)
	}
	return nil
}

func (s *redisSessionStore) AllowRequest(ctx context.Context, bucket string, limit int, window time.Duration) (bool, error) {
	if limit <= 0 || window <= 0 {
		return true, nil
	}

	key := rateLimitKey(bucket)
	count, err := s.client.Incr(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("increment rate limit bucket: %w", err)
	}
	if count == 1 {
		if err := s.client.Expire(ctx, key, window).Err(); err != nil {
			return false, fmt.Errorf("set rate limit expiry: %w", err)
		}
	}

	return count <= int64(limit), nil
}

func refreshTokenKey(tokenHash string) string {
	return "auth:refresh:" + tokenHash
}

func failedLoginKey(username string) string {
	return "auth:failed-login:" + username
}

func accountLockKey(username string) string {
	return "auth:account-lock:" + username
}

func rateLimitKey(bucket string) string {
	return "auth:rate-limit:" + bucket
}
