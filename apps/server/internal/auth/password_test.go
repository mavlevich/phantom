package auth

import "testing"

func TestHashPasswordRoundTrip(t *testing.T) {
	password := "correct-horse-battery-staple"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	ok, err := VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("VerifyPassword() error = %v", err)
	}
	if !ok {
		t.Fatal("VerifyPassword() = false, want true")
	}
}

func TestVerifyPasswordRejectsWrongPassword(t *testing.T) {
	hash, err := HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}

	ok, err := VerifyPassword("wrong-password", hash)
	if err != nil {
		t.Fatalf("VerifyPassword() error = %v", err)
	}
	if ok {
		t.Fatal("VerifyPassword() = true, want false")
	}
}

func TestVerifyPasswordRejectsMalformedHash(t *testing.T) {
	ok, err := VerifyPassword("password", "not-a-valid-hash")
	if err == nil {
		t.Fatal("VerifyPassword() error = nil, want error")
	}
	if ok {
		t.Fatal("VerifyPassword() = true, want false")
	}
}
