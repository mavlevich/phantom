package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

func TestRegisterHandlerSuccess(t *testing.T) {
	app := fiber.New()
	RegisterRoutes(app.Group("/api/v1"), handlerServiceStub{
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
			app := fiber.New()
			RegisterRoutes(app.Group("/api/v1"), handlerServiceStub{registerErr: tt.err})

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
	app := fiber.New()
	RegisterRoutes(app.Group("/api/v1"), handlerServiceStub{registerErr: ErrInviteAlreadyUsed})

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

	if string(bodyBytes) != "invalid or unavailable invite code" {
		t.Fatalf("error message = %q, want generic invite error", string(bodyBytes))
	}
}

func TestRegisterHandlerRejectsInvalidJSON(t *testing.T) {
	app := fiber.New()
	RegisterRoutes(app.Group("/api/v1"), handlerServiceStub{})

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

type handlerServiceStub struct {
	registerResult *RegisterResult
	registerErr    error
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
