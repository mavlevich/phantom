package config

import (
	"testing"
	"time"
)

func TestLoadUsesDefaultsAndRequiredEnv(t *testing.T) {
	t.Setenv("APP_ENV", "")
	t.Setenv("SERVER_PORT", "")
	t.Setenv("DATABASE_URL", "postgres://phantom:phantom@localhost:5432/phantom_test?sslmode=disable")
	t.Setenv("REDIS_URL", "")
	t.Setenv("JWT_SECRET", "test-secret-key-minimum-32-chars-long")
	t.Setenv("JWT_EXPIRY", "")
	t.Setenv("REFRESH_TOKEN_EXPIRY", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Env != "development" {
		t.Fatalf("Env = %q, want development", cfg.Env)
	}
	if cfg.ServerPort != "8080" {
		t.Fatalf("ServerPort = %q, want 8080", cfg.ServerPort)
	}
	if cfg.RedisURL != "redis://localhost:6379" {
		t.Fatalf("RedisURL = %q, want redis://localhost:6379", cfg.RedisURL)
	}
	if cfg.JWTExpiry != 15*time.Minute {
		t.Fatalf("JWTExpiry = %v, want %v", cfg.JWTExpiry, 15*time.Minute)
	}
	if cfg.RefreshTokenExpiry != 30*24*time.Hour {
		t.Fatalf("RefreshTokenExpiry = %v, want %v", cfg.RefreshTokenExpiry, 30*24*time.Hour)
	}
	if cfg.IsProduction() {
		t.Fatal("IsProduction() = true, want false")
	}
}

func TestLoadUsesExplicitValues(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("SERVER_PORT", "9090")
	t.Setenv("DATABASE_URL", "postgres://example")
	t.Setenv("REDIS_URL", "redis://cache:6379")
	t.Setenv("JWT_SECRET", "another-test-secret-key-minimum-32")
	t.Setenv("JWT_EXPIRY", "30m")
	t.Setenv("REFRESH_TOKEN_EXPIRY", "48h")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.Env != "production" {
		t.Fatalf("Env = %q, want production", cfg.Env)
	}
	if !cfg.IsProduction() {
		t.Fatal("IsProduction() = false, want true")
	}
	if cfg.ServerPort != "9090" {
		t.Fatalf("ServerPort = %q, want 9090", cfg.ServerPort)
	}
	if cfg.JWTExpiry != 30*time.Minute {
		t.Fatalf("JWTExpiry = %v, want %v", cfg.JWTExpiry, 30*time.Minute)
	}
	if cfg.RefreshTokenExpiry != 48*time.Hour {
		t.Fatalf("RefreshTokenExpiry = %v, want %v", cfg.RefreshTokenExpiry, 48*time.Hour)
	}
}

func TestLoadRequiresJWTSecret(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://example")
	t.Setenv("JWT_SECRET", "")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() error = nil, want JWT_SECRET validation error")
	}
	if err.Error() != "JWT_SECRET is required" {
		t.Fatalf("Load() error = %q, want JWT_SECRET is required", err.Error())
	}
}

func TestLoadRequiresDatabaseURL(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	t.Setenv("JWT_SECRET", "test-secret-key-minimum-32-chars-long")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() error = nil, want DATABASE_URL validation error")
	}
	if err.Error() != "DATABASE_URL is required" {
		t.Fatalf("Load() error = %q, want DATABASE_URL is required", err.Error())
	}
}

func TestGetEnvFallsBack(t *testing.T) {
	t.Setenv("PHANTOM_TEST_ENV", "")

	got := getEnv("PHANTOM_TEST_ENV", "fallback")
	if got != "fallback" {
		t.Fatalf("getEnv() = %q, want fallback", got)
	}
}

func TestGetDurationEnvFallsBackOnInvalidValue(t *testing.T) {
	t.Setenv("PHANTOM_TEST_DURATION", "definitely-not-a-duration")

	got := getDurationEnv("PHANTOM_TEST_DURATION", time.Hour)
	if got != time.Hour {
		t.Fatalf("getDurationEnv() = %v, want %v", got, time.Hour)
	}
}
