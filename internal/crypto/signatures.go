package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
)

// GenerateEd25519KeyPair generates a modern Ed25519 public/private keypair
func GenerateEd25519KeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// SignEd25519 signs message with Ed25519 private key
func SignEd25519(priv ed25519.PrivateKey, message []byte) []byte {
	return ed25519.Sign(priv, message)
}

// VerifyEd25519 verifies Ed25519 signature
func VerifyEd25519(pub ed25519.PublicKey, message, signature []byte) bool {
	return ed25519.Verify(pub, message, signature)
}

// GenerateP384KeyPair generates a high-security NIST P-384 keypair
func GenerateP384KeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
}

// SignP384 signs message with P-384 ECDSA key using SHA-384
func SignP384(priv *ecdsa.PrivateKey, message []byte) ([]byte, error) {
	digest := sha512.Sum384(message)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
	if err != nil {
		return nil, err
	}
	return marshalECDSASignature(r, s)
}

// VerifyP384 verifies P-384 ECDSA signature with SHA-384
func VerifyP384(pub *ecdsa.PublicKey, message, sigDER []byte) bool {
	digest := sha512.Sum384(message)
	r, s, err := parseECDSASignature(sigDER)
	if err != nil {
		return false
	}
	return ecdsa.Verify(pub, digest[:], r, s)
}

func parseECDSASignature(sigDER []byte) (*big.Int, *big.Int, error) {
	if len(sigDER) < 8 || sigDER[0] != 0x30 {
		return nil, nil, errors.New("invalid DER sequence")
	}
	seqLen := int(sigDER[1])
	if len(sigDER) < seqLen+2 {
		return nil, nil, errors.New("truncated DER signature")
	}

	offset := 2
	if sigDER[offset] != 0x02 {
		return nil, nil, errors.New("expected INTEGER tag for R")
	}
	rLen := int(sigDER[offset+1])
	offset += 2
	rBytes := sigDER[offset : offset+rLen]
	offset += rLen

	if sigDER[offset] != 0x02 {
		return nil, nil, errors.New("expected INTEGER tag for S")
	}
	sLen := int(sigDER[offset+1])
	offset += 2
	sBytes := sigDER[offset : offset+sLen]

	r := new(big.Int).SetBytes(rBytes)
	s := new(big.Int).SetBytes(sBytes)
	return r, s, nil
}

// ExportP384PrivateKeyPEM exports P-384 private key as PEM string
func ExportP384PrivateKeyPEM(priv *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", err
	}
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}
	return string(pem.EncodeToMemory(block)), nil
}

// ExportEd25519PrivateKeyHex exports Ed25519 key as hex string
func ExportEd25519PrivateKeyHex(priv ed25519.PrivateKey) string {
	return hex.EncodeToString(priv)
}
