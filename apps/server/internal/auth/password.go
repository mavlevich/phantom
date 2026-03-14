package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math"
	"strings"

	"golang.org/x/crypto/argon2"
)

type argon2IDParams struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

var defaultArgon2IDParams = argon2IDParams{
	memory:      64 * 1024,
	iterations:  3,
	parallelism: 2,
	saltLength:  16,
	keyLength:   32,
}

var timingPaddingPasswordHash = mustTimingPaddingPasswordHash()

func HashPassword(password string) (string, error) {
	return hashPasswordWithParams(password, defaultArgon2IDParams)
}

func VerifyPassword(password, encodedHash string) (bool, error) {
	params, salt, hash, err := decodePasswordHash(encodedHash)
	if err != nil {
		return false, err
	}
	keyLength, err := toUint32Length(len(hash))
	if err != nil {
		return false, err
	}

	otherHash := argon2.IDKey(
		[]byte(password),
		salt,
		params.iterations,
		params.memory,
		params.parallelism,
		keyLength,
	)

	return subtle.ConstantTimeCompare(hash, otherHash) == 1, nil
}

func mustTimingPaddingPasswordHash() string {
	hash, err := hashPasswordWithParams("phantom-login-timing-padding", defaultArgon2IDParams)
	if err != nil {
		panic(fmt.Sprintf("build timing padding hash: %v", err))
	}
	return hash
}

func hashPasswordWithParams(password string, params argon2IDParams) (string, error) {
	salt := make([]byte, params.saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("read salt: %w", err)
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		params.iterations,
		params.memory,
		params.parallelism,
		params.keyLength,
	)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		params.memory,
		params.iterations,
		params.parallelism,
		b64Salt,
		b64Hash,
	), nil
}

func decodePasswordHash(encodedHash string) (argon2IDParams, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return argon2IDParams{}, nil, nil, fmt.Errorf("invalid password hash format")
	}

	if parts[1] != "argon2id" {
		return argon2IDParams{}, nil, nil, fmt.Errorf("unsupported password hash algorithm")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return argon2IDParams{}, nil, nil, fmt.Errorf("parse password hash version: %w", err)
	}
	if version != argon2.Version {
		return argon2IDParams{}, nil, nil, fmt.Errorf("unsupported password hash version")
	}

	params := argon2IDParams{}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.memory, &params.iterations, &params.parallelism); err != nil {
		return argon2IDParams{}, nil, nil, fmt.Errorf("parse password hash params: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return argon2IDParams{}, nil, nil, fmt.Errorf("decode password hash salt: %w", err)
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return argon2IDParams{}, nil, nil, fmt.Errorf("decode password hash value: %w", err)
	}

	params.saltLength, err = toUint32Length(len(salt))
	if err != nil {
		return argon2IDParams{}, nil, nil, err
	}
	params.keyLength, err = toUint32Length(len(hash))
	if err != nil {
		return argon2IDParams{}, nil, nil, err
	}

	return params, salt, hash, nil
}

func toUint32Length(n int) (uint32, error) {
	if n < 0 || uint64(n) > math.MaxUint32 {
		return 0, fmt.Errorf("length out of range")
	}
	//nolint:gosec // Bounds check above guarantees the conversion is safe.
	return uint32(n), nil
}
