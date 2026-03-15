package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/mavlevich/phantom/server/internal/httpapi"
)

func TestRegisterHandlerSuccess(t *testing.T) {
	app := newTestApp(handlerServiceStub{
		registerResult: &RegisterResult{
			UserID:   uuid.MustParse("11111111-1111-1111-1111-111111111111"),
			Username: "Alice123",
		},
	})

	body := map[string]string{
		"username":    "Alice123",
		"password":    "strong-password-123",
		"public_key":  mustPublicKey(t),
		"invite_code": "ALPHA-INVITE-001",
	}

	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status code = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
}

func TestRegisterHandlerMapsKnownErrors(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
	}{
		{name: "duplicate username", err: ErrUserAlreadyExists, status: http.StatusConflict},
		{name: "invite missing", err: ErrInviteNotFound, status: http.StatusBadRequest},
		{name: "invite used", err: ErrInviteAlreadyUsed, status: http.StatusBadRequest},
		{name: "invite expired", err: ErrInviteExpired, status: http.StatusBadRequest},
		{name: "invalid username", err: ErrInvalidUsername, status: http.StatusBadRequest},
		{name: "weak password", err: ErrWeakPassword, status: http.StatusBadRequest},
		{name: "invalid public key", err: ErrInvalidPublicKey, status: http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := newTestApp(handlerServiceStub{registerErr: tt.err})

			body := map[string]string{
				"username":    "Alice123",
				"password":    "strong-password-123",
				"public_key":  mustPublicKey(t),
				"invite_code": "ALPHA-INVITE-001",
			}

			payload, err := json.Marshal(body)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}

			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(payload))
			req.Header.Set("Content-Type", "application/json")

			resp, err := app.Test(req)
			if err != nil {
				t.Fatalf("app.Test() error = %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.status {
				t.Fatalf("status code = %d, want %d", resp.StatusCode, tt.status)
			}
		})
	}
}

func TestRegisterHandlerUsesGenericInviteMessage(t *testing.T) {
	app := newTestApp(handlerServiceStub{registerErr: ErrInviteAlreadyUsed})

	body := map[string]string{
		"username":    "Alice123",
		"password":    "strong-password-123",
		"public_key":  mustPublicKey(t),
		"invite_code": "ALPHA-INVITE-001",
	}

	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test() error = %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll() error = %v", err)
	}

	var response apiResponse
	if err := json.Unmarshal(bodyBytes, &response); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	if response.Error != "invalid or unavailable invite code" {
		t.Fatalf("error message = %q, want generic invite error", response.Error)
	}
}

func TestRegisterHandlerRejectsInvalidJSON(t *testing.T) {
	app := newTestApp(handlerServiceStub{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader([]byte("{")))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status code = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestLoginHandlerSuccess(t *testing.T) {
	app := newTestApp(handlerServiceStub{
		loginResult: &LoginResult{
			AccessToken:      "access-token",
			TokenType:        "Bearer",
			UserID:           uuid.MustParse("22222222-2222-2222-2222-222222222222"),
			Username:         "Alice123",
			RefreshToken:     "refresh-token",
			RefreshExpiresAt: time.Now().UTC().Add(time.Hour),
		},
	})

	body := map[string]string{
		"username": "Alice123",
		"password": "strong-password-123",
	}

	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status code = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if cookie := resp.Header.Get("Set-Cookie"); !strings.Contains(cookie, refreshTokenCookieName+"=refresh-token") {
		t.Fatalf("Set-Cookie = %q, want refresh token cookie", cookie)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll() error = %v", err)
	}
	if strings.Contains(string(bodyBytes), "refresh_token") {
		t.Fatalf("response body leaked refresh_token field: %s", bodyBytes)
	}
	if strings.Contains(string(bodyBytes), "refresh-token") {
		t.Fatalf("response body leaked refresh token value: %s", bodyBytes)
	}
}

func TestLoginHandlerMapsKnownErrors(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
	}{
		{name: "invalid credentials", err: ErrInvalidCredentials, status: http.StatusUnauthorized},
		{name: "account locked", err: ErrAccountLocked, status: http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := newTestApp(handlerServiceStub{loginErr: tt.err})

			body := map[string]string{
				"username": "Alice123",
				"password": "strong-password-123",
			}

			payload, err := json.Marshal(body)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}

			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(payload))
			req.Header.Set("Content-Type", "application/json")

			resp, err := app.Test(req)
			if err != nil {
				t.Fatalf("app.Test() error = %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.status {
				t.Fatalf("status code = %d, want %d", resp.StatusCode, tt.status)
			}
		})
	}
}

func TestLoginHandlerRejectsInvalidJSON(t *testing.T) {
	app := newTestApp(handlerServiceStub{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader([]byte("{")))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status code = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestRefreshHandlerSuccess(t *testing.T) {
	app := newTestApp(handlerServiceStub{
		refreshResult: &LoginResult{
			AccessToken:      "rotated-access-token",
			TokenType:        "Bearer",
			UserID:           uuid.MustParse("33333333-3333-3333-3333-333333333333"),
			Username:         "Alice123",
			RefreshToken:     "rotated-refresh-token",
			RefreshExpiresAt: time.Now().UTC().Add(time.Hour),
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: refreshTokenCookieName, Value: "old-refresh-token"})

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status code = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if cookie := resp.Header.Get("Set-Cookie"); !strings.Contains(cookie, refreshTokenCookieName+"=rotated-refresh-token") {
		t.Fatalf("Set-Cookie = %q, want rotated refresh token cookie", cookie)
	}
}

func TestRefreshHandlerMapsKnownErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{name: "invalid token", err: ErrTokenInvalid},
		{name: "expired token", err: ErrTokenExpired},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := newTestApp(handlerServiceStub{refreshErr: tt.err})

			req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
			req.AddCookie(&http.Cookie{Name: refreshTokenCookieName, Value: "old-refresh-token"})

			resp, err := app.Test(req)
			if err != nil {
				t.Fatalf("app.Test() error = %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status code = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
			}
		})
	}
}

func TestLogoutHandlerClearsCookie(t *testing.T) {
	app := newTestApp(handlerServiceStub{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: refreshTokenCookieName, Value: "refresh-token"})

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status code = %d, want %d", resp.StatusCode, http.StatusNoContent)
	}
	if cookie := resp.Header.Get("Set-Cookie"); !strings.Contains(cookie, refreshTokenCookieName+"=") {
		t.Fatalf("Set-Cookie = %q, want cleared refresh token cookie", cookie)
	}
}

func TestMeHandlerRequiresConfiguredAccessMiddleware(t *testing.T) {
	userID := uuid.MustParse("44444444-4444-4444-4444-444444444444")
	app := newTestApp(handlerServiceStub{}, RouteConfig{
		AccessMiddleware: func(c *fiber.Ctx) error {
			c.Locals(currentUserContextKey, &User{
				ID:       userID,
				Username: "Alice123",
			})
			return c.Next()
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)

	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status code = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

type handlerServiceStub struct {
	registerResult *RegisterResult
	registerErr    error
	loginResult    *LoginResult
	loginErr       error
	refreshResult  *LoginResult
	refreshErr     error
	logoutErr      error
}

type apiResponse struct {
	Data  json.RawMessage `json:"data"`
	Error string          `json:"error"`
}

func newTestApp(service Service, configs ...RouteConfig) *fiber.App {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	app := fiber.New(fiber.Config{
		ErrorHandler: httpapi.ErrorHandler(logger, "test"),
	})
	RegisterRoutes(app.Group("/api/v1"), service, configs...)
	return app
}

func (s handlerServiceStub) Register(ctx context.Context, input RegisterInput) (*RegisterResult, error) {
	if s.registerErr != nil {
		return nil, s.registerErr
	}
	if s.registerResult == nil {
		return nil, errors.New("missing stub result")
	}
	return s.registerResult, nil
}

func (s handlerServiceStub) Login(ctx context.Context, input LoginInput) (*LoginResult, error) {
	if s.loginErr != nil {
		return nil, s.loginErr
	}
	if s.loginResult == nil {
		return nil, errors.New("missing stub login result")
	}
	return s.loginResult, nil
}

func (s handlerServiceStub) Refresh(ctx context.Context, input RefreshInput) (*LoginResult, error) {
	if s.refreshErr != nil {
		return nil, s.refreshErr
	}
	if s.refreshResult == nil {
		return nil, errors.New("missing stub refresh result")
	}
	return s.refreshResult, nil
}

func (s handlerServiceStub) Logout(ctx context.Context, input LogoutInput) error {
	return s.logoutErr
}
