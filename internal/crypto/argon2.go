package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Params defines parameters for Argon2id key derivation
type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	KeyLength   uint32
}

var DefaultArgon2Params = Argon2Params{
	Memory:      64 * 1024, // 64 MB
	Iterations:  3,
	Parallelism: 4,
	KeyLength:   32,
}

// DeriveKeyArgon2id derives a cryptographic key using Argon2id
func DeriveKeyArgon2id(password, salt string, params *Argon2Params) []byte {
	if params == nil {
		params = &DefaultArgon2Params
	}
	return argon2.IDKey([]byte(password), []byte(salt), params.Iterations, params.Memory, params.Parallelism, params.KeyLength)
}

// HashPasswordArgon2id creates an Argon2id hash with a random 16-byte salt
func HashPasswordArgon2id(password string, params *Argon2Params) (string, error) {
	if params == nil {
		params = &DefaultArgon2Params
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, params.Memory, params.Iterations, params.Parallelism,
		hex.EncodeToString(salt), hex.EncodeToString(hash)), nil
}

// VerifyPasswordArgon2id verifies password against formatted hash
func VerifyPasswordArgon2id(password, encodedHash string) (bool, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("invalid argon2id hash format")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return false, errors.New("invalid argon2id version")
	}

	var memory, iterations uint32
	var parallelism uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism); err != nil {
		return false, errors.New("invalid argon2id params")
	}

	salt, err := hex.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	expectedHash, err := hex.DecodeString(parts[5])
	if err != nil {
		return false, err
	}

	computed := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(expectedHash)))
	return subtle.ConstantTimeCompare(computed, expectedHash) == 1, nil
}
