package crypto

import (
	"testing"
)

func TestSaltGeneration(t *testing.T) {
	s1 := GenerateSalt(16)
	s2 := GenerateSalt(16)
	if s1 == "" || s2 == "" {
		t.Fatalf("Generated salts must not be empty")
	}
	if s1 == s2 {
		t.Fatalf("Consecutive salts must be different")
	}
}

func TestAuthKeyHashing(t *testing.T) {
	authKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	salt := "random_test_salt_123"

	hash1, err := HashAuthKey(authKey, salt, 100_000)
	if err != nil {
		t.Fatalf("Failed to hash auth key: %v", err)
	}

	hash2, err := HashAuthKey(authKey, salt, 100_000)
	if err != nil {
		t.Fatalf("Failed to hash auth key 2nd time: %v", err)
	}

	if hash1 != hash2 {
		t.Errorf("Hashes must be deterministic")
	}

	if !VerifyAuthKey(authKey, salt, hash1) {
		t.Errorf("VerifyAuthKey failed on valid key")
	}

	if VerifyAuthKey("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", salt, hash1) {
		t.Errorf("VerifyAuthKey passed on invalid key")
	}
}

func TestPasskeyKeypair(t *testing.T) {
	keypair, err := GeneratePasskeyKeypair()
	if err != nil {
		t.Fatalf("GeneratePasskeyKeypair failed: %v", err)
	}

	if keypair.CredentialId == "" || keypair.PrivateKeyPem == "" || keypair.PublicKeyPem == "" {
		t.Errorf("Keypair fields must not be empty")
	}
}

func TestTOTPGenerationAndVerification(t *testing.T) {
	secret, err := GenerateTotpSecret()
	if err != nil {
		t.Fatalf("GenerateTotpSecret failed: %v", err)
	}

	code, rem, err := GenerateCurrentTotp(secret)
	if err != nil {
		t.Fatalf("GenerateCurrentTotp failed: %v", err)
	}

	if len(code) != 6 {
		t.Errorf("Expected 6-digit TOTP, got %s", code)
	}
	if rem < 0 || rem > 30 {
		t.Errorf("Invalid remaining seconds: %d", rem)
	}

	if !VerifyTotpCode(secret, code) {
		t.Errorf("VerifyTotpCode should succeed on freshly generated code")
	}

	if VerifyTotpCode(secret, "000000") && code != "000000" {
		t.Errorf("VerifyTotpCode should fail on wrong code")
	}
}
