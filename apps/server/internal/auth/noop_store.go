package auth

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type noopSessionStore struct{}

func (noopSessionStore) StoreRefreshToken(context.Context, string, uuid.UUID, time.Time) error {
	return nil
}

func (noopSessionStore) ConsumeRefreshToken(context.Context, string) (*RefreshSession, error) {
	return nil, nil
}

func (noopSessionStore) RevokeRefreshToken(context.Context, string) error {
	return nil
}

func (noopSessionStore) IsAccountLocked(context.Context, string) (bool, error) {
	return false, nil
}

func (noopSessionStore) RegisterFailedLogin(context.Context, string, time.Time) (bool, error) {
	return false, nil
}

func (noopSessionStore) ClearFailedLogins(context.Context, string) error {
	return nil
}

func (noopSessionStore) AllowRequest(context.Context, string, int, time.Duration) (bool, error) {
	return true, nil
}
