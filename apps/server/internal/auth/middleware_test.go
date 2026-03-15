package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

func TestAccessMiddlewareSuccess(t *testing.T) {
	userID := uuid.New()
	now := time.Now().UTC()
	issuer := newAccessTokenIssuer("test-secret-key-minimum-32-chars-long", 15*time.Minute, uuid.New)
	tokenString, _, err := issuer(&User{ID: userID}, now)
	if err != nil {
		t.Fatalf("issuer() error = %v", err)
	}

	repo := &registerRepoStub{
		userByID: &User{ID: userID, Username: "alice123"},
	}

	app := fiber.New()
	app.Get("/protected", NewAccessMiddleware("test-secret-key-minimum-32-chars-long", repo), func(c *fiber.Ctx) error {
		user := CurrentUser(c)
		if user == nil {
			t.Fatal("CurrentUser() = nil, want user")
		}
		return c.SendStatus(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set(fiber.HeaderAuthorization, "Bearer "+tokenString)

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status code = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
}

func TestAccessMiddlewareRejectsMissingToken(t *testing.T) {
	app := fiber.New()
	app.Get("/protected", NewAccessMiddleware("test-secret-key-minimum-32-chars-long", &registerRepoStub{}), func(c *fiber.Ctx) error {
		return c.SendStatus(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status code = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func TestAccessMiddlewareRejectsExpiredToken(t *testing.T) {
	userID := uuid.New()
	now := time.Now().UTC()
	issuer := newAccessTokenIssuer("test-secret-key-minimum-32-chars-long", 15*time.Minute, uuid.New)
	tokenString, _, err := issuer(&User{ID: userID}, now.Add(-20*time.Minute))
	if err != nil {
		t.Fatalf("issuer() error = %v", err)
	}

	app := fiber.New()
	app.Get("/protected", NewAccessMiddleware("test-secret-key-minimum-32-chars-long", &registerRepoStub{}), func(c *fiber.Ctx) error {
		return c.SendStatus(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set(fiber.HeaderAuthorization, "Bearer "+tokenString)

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status code = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func TestAccessMiddlewareRejectsMalformedBearer(t *testing.T) {
	app := fiber.New()
	app.Get("/protected", NewAccessMiddleware("test-secret-key-minimum-32-chars-long", &registerRepoStub{}), func(c *fiber.Ctx) error {
		return c.SendStatus(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set(fiber.HeaderAuthorization, "Token definitely-not-bearer")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status code = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func TestAuthRateLimiterBlocksAfterLimit(t *testing.T) {
	store := &rateLimiterStoreStub{}
	app := fiber.New()
	app.Get("/limited", NewAuthRateLimiter(store, "login", 1, time.Minute), func(c *fiber.Ctx) error {
		return c.SendStatus(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/limited", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status code = %d, want %d", resp.StatusCode, http.StatusTooManyRequests)
	}
}

func TestAuthRateLimiterPropagatesStoreError(t *testing.T) {
	store := &rateLimiterStoreStub{allowErr: errors.New("redis unavailable")}
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			return c.Status(http.StatusInternalServerError).SendString(err.Error())
		},
	})
	app.Get("/limited", NewAuthRateLimiter(store, "login", 1, time.Minute), func(c *fiber.Ctx) error {
		return c.SendStatus(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/limited", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status code = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}
}

type rateLimiterStoreStub struct {
	allowErr error
}

func (rateLimiterStoreStub) StoreRefreshToken(context.Context, string, uuid.UUID, time.Time) error {
	return nil
}

func (rateLimiterStoreStub) ConsumeRefreshToken(context.Context, string) (*RefreshSession, error) {
	return nil, nil
}

func (rateLimiterStoreStub) RevokeRefreshToken(context.Context, string) error {
	return nil
}

func (rateLimiterStoreStub) IsAccountLocked(context.Context, string) (bool, error) {
	return false, nil
}

func (rateLimiterStoreStub) RegisterFailedLogin(context.Context, string, time.Time) (bool, error) {
	return false, nil
}

func (rateLimiterStoreStub) ClearFailedLogins(context.Context, string) error {
	return nil
}

func (s rateLimiterStoreStub) AllowRequest(context.Context, string, int, time.Duration) (bool, error) {
	if s.allowErr != nil {
		return false, s.allowErr
	}
	return false, nil
}
