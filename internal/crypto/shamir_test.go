package crypto

import (
	"bytes"
	"testing"
)

func TestShamirSecretSharing(t *testing.T) {
	secret := []byte("MasterEncryptionKeySuperSecret1234")
	totalParts := 5
	threshold := 3

	shares, err := SplitSecret(secret, totalParts, threshold)
	if err != nil {
		t.Fatalf("SplitSecret failed: %v", err)
	}

	if len(shares) != 5 {
		t.Fatalf("Expected 5 shares, got %d", len(shares))
	}

	// 1. Recover with shares [0, 2, 4]
	recovered, err := CombineShares([][]byte{shares[0], shares[2], shares[4]})
	if err != nil {
		t.Fatalf("CombineShares failed: %v", err)
	}

	if !bytes.Equal(recovered, secret) {
		t.Fatalf("Recovered secret does not match original: got %s, want %s", string(recovered), string(secret))
	}

	// 2. Recover with shares [1, 3, 4]
	recovered2, err := CombineShares([][]byte{shares[1], shares[3], shares[4]})
	if err != nil {
		t.Fatalf("CombineShares failed with different combination: %v", err)
	}
	if !bytes.Equal(recovered2, secret) {
		t.Fatalf("Recovered secret 2 mismatch")
	}

	// 3. Test Argon2id
	argonHash, err := HashPasswordArgon2id("MySecurePassword", nil)
	if err != nil {
		t.Fatalf("Argon2id hashing failed: %v", err)
	}
	valid, err := VerifyPasswordArgon2id("MySecurePassword", argonHash)
	if err != nil || !valid {
		t.Fatalf("Argon2id verification failed: valid=%v, err=%v", valid, err)
	}

	// 4. Test Ed25519
	pub, priv, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("Ed25519 gen failed: %v", err)
	}
	msg := []byte("hello ed25519")
	sig := SignEd25519(priv, msg)
	if !VerifyEd25519(pub, msg, sig) {
		t.Fatalf("Ed25519 verify failed")
	}
}
