package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// PostQuantumCipherSuite represents the hybrid KEM algorithm identifier
const (
	SuiteX25519Kyber768Draft00 = "X25519-ML-KEM-768"
)

// HybridKEMEnvelope defines a Post-Quantum ready hybrid envelope for zero-knowledge key exchange
type HybridKEMEnvelope struct {
	Version            string `json:"version"`              // e.g. "pq-1.0"
	CipherSuite        string `json:"suite"`                // e.g. "X25519-ML-KEM-768"
	ClassicalCiphertext string `json:"classical_ct"`        // Hex-encoded X25519 ephemeral public key
	PQKyberCiphertext   string `json:"pq_kyber_ct"`          // Hex-encoded ML-KEM-768 encapsulated ciphertext
	CombinedKeyHash     string `json:"combined_key_hash"`    // SHA-256 fingerprint of shared secret
	PayloadIV          string `json:"iv"`                   // 12-byte AES-GCM IV
	EncryptedPayload   string `json:"data"`                 // AES-256-GCM encrypted ciphertext
}

// CombineSharedSecrets combines a classical shared secret and post-quantum shared secret via HKDF / dual SHA-256
func CombineSharedSecrets(classicalSecret, pqSecret []byte) []byte {
	h := sha256.New()
	h.Write([]byte("SentinelBit-PQ-Hybrid-KEM-v1"))
	h.Write(classicalSecret)
	h.Write(pqSecret)
	return h.Sum(nil)
}

// GenerateHybridKEMEnvelope creates a structured hybrid post-quantum envelope for data protection
func GenerateHybridKEMEnvelope(data []byte, classicalEphemeralPub, pqCiphertext []byte, combinedSecret []byte) (*HybridKEMEnvelope, error) {
	if len(combinedSecret) < 32 {
		return nil, errors.New("combined secret must be at least 32 bytes")
	}

	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	// Encrypt payload with combined secret
	encJSON, err := EncryptVaultPayload(string(data), combinedSecret[:32])
	if err != nil {
		return nil, err
	}

	var rawEnc struct {
		IV   string `json:"iv"`
		Data string `json:"data"`
	}
	_ = json.Unmarshal([]byte(encJSON), &rawEnc)

	h := sha256.Sum256(combinedSecret[:32])

	return &HybridKEMEnvelope{
		Version:             "pq-1.0",
		CipherSuite:         SuiteX25519Kyber768Draft00,
		ClassicalCiphertext: fmt.Sprintf("%x", classicalEphemeralPub),
		PQKyberCiphertext:   fmt.Sprintf("%x", pqCiphertext),
		CombinedKeyHash:     fmt.Sprintf("%x", h[:]),
		PayloadIV:          rawEnc.IV,
		EncryptedPayload:   rawEnc.Data,
	}, nil
}
