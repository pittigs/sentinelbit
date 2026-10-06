package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/crypto/pbkdf2"
)

// GenerateSalt returns cryptographically secure base64url salt
func GenerateSalt(length int) string {
	b := make([]byte, length)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// HashAuthKey computes PBKDF2-HMAC-SHA256 with 100,000 iterations (identical to Python hashlib.pbkdf2_hmac)
func HashAuthKey(clientAuthKeyHex, serverSalt string, iterations int) (string, error) {
	keyBytes, err := hex.DecodeString(clientAuthKeyHex)
	if err != nil {
		return "", errors.New("invalid hex for client auth key")
	}
	saltBytes := []byte(serverSalt)
	derived := pbkdf2.Key(keyBytes, saltBytes, iterations, 32, sha256.New)
	return hex.EncodeToString(derived), nil
}

// VerifyAuthKey verifies auth key in constant time
func VerifyAuthKey(clientAuthKeyHex, serverSalt, storedHash string) bool {
	computed, err := HashAuthKey(clientAuthKeyHex, serverSalt, 100_000)
	if err != nil {
		return false
	}
	return hmac.Equal([]byte(computed), []byte(storedHash))
}

// TOTP helpers
func GenerateTotpSecret() (string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "sentinelbit",
		AccountName: "user",
	})
	if err != nil {
		return "", err
	}
	return key.Secret(), nil
}

func GetTotpURI(secret, username, issuer string) string {
	if issuer == "" {
		issuer = "sentinelbit"
	}
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		issuer, username, secret, issuer)
}

func GenerateTotpQRBase64(provisioningURI string) (string, error) {
	png, err := qrcode.Encode(provisioningURI, qrcode.Medium, 256)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(png), nil
}

func VerifyTotpCode(secret, code string) bool {
	if secret == "" || code == "" {
		return false
	}
	code = strings.TrimSpace(code)
	valid, err := totp.ValidateCustom(code, secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return err == nil && valid
}

func GenerateCurrentTotp(secret string) (string, int, error) {
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		return "", 0, err
	}
	rem := 30 - (time.Now().Unix() % 30)
	return code, int(rem), nil
}

// GenerateRecoveryCodes generates 8 alphanumeric codes of length 8
func GenerateRecoveryCodes(count int) []string {
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		var sb strings.Builder
		for _, byteVal := range b {
			sb.WriteByte(charset[int(byteVal)%len(charset)])
		}
		codes[i] = sb.String()
	}
	return codes
}

// WebAuthn / Passkeys helpers (P-256 / ES256)
type PasskeyKeypairResult struct {
	CredentialId  string `json:"credential_id"`
	PrivateKeyPem string `json:"private_key_pem"`
	PublicKeyPem  string `json:"public_key_pem"`
	PublicKeyCose string `json:"cose_key"`
	X             string `json:"x"`
	Y             string `json:"y"`
}

func GeneratePasskeyKeypair() (*PasskeyKeypairResult, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	privPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	})

	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	pubPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	// Pad X and Y to 32 bytes
	xBytes := priv.PublicKey.X.Bytes()
	yBytes := priv.PublicKey.Y.Bytes()
	xPadded := make([]byte, 32)
	yPadded := make([]byte, 32)
	copy(xPadded[32-len(xBytes):], xBytes)
	copy(yPadded[32-len(yBytes):], yBytes)

	credIdBytes := make([]byte, 32)
	_, _ = rand.Read(credIdBytes)
	credIdB64 := base64.RawURLEncoding.EncodeToString(credIdBytes)

	coseMap := map[string]interface{}{
		"kty": 2,  // EC2
		"alg": -7, // ES256
		"crv": 1,  // P-256
		"x":   base64.RawURLEncoding.EncodeToString(xPadded),
		"y":   base64.RawURLEncoding.EncodeToString(yPadded),
	}
	coseJson, _ := json.Marshal(coseMap)

	return &PasskeyKeypairResult{
		CredentialId:  credIdB64,
		PrivateKeyPem: string(privPem),
		PublicKeyPem:  string(pubPem),
		PublicKeyCose: string(coseJson),
		X:             coseMap["x"].(string),
		Y:             coseMap["y"].(string),
	}, nil
}

type SignAssertionResult struct {
	SignatureB64   string `json:"signature_b64"`
	SignatureHex   string `json:"signature_hex"`
	ClientDataHash string `json:"client_data_hash"`
	DataSignedHex  string `json:"data_signed_hex"`
}

func SignWebAuthnAssertion(privateKeyPem, clientDataJson, authDataHex string) (*SignAssertionResult, error) {
	block, _ := pem.Decode([]byte(privateKeyPem))
	if block == nil {
		return nil, errors.New("failed to decode private key PEM")
	}

	rawKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// try EC private key
		rawKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
	}

	privKey, ok := rawKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an ECDSA private key")
	}

	clientDataHash := sha256.Sum256([]byte(clientDataJson))
	authDataBytes, err := hex.DecodeString(authDataHex)
	if err != nil {
		return nil, errors.New("invalid auth_data_hex")
	}

	dataToSign := append(authDataBytes, clientDataHash[:]...)
	digest := sha256.Sum256(dataToSign)

	r, s, err := ecdsa.Sign(rand.Reader, privKey, digest[:])
	if err != nil {
		return nil, err
	}

	derBytes, err := marshalECDSASignature(r, s)
	if err != nil {
		return nil, err
	}

	return &SignAssertionResult{
		SignatureB64:   base64.RawURLEncoding.EncodeToString(derBytes),
		SignatureHex:   hex.EncodeToString(derBytes),
		ClientDataHash: hex.EncodeToString(clientDataHash[:]),
		DataSignedHex:  hex.EncodeToString(dataToSign),
	}, nil
}

func marshalECDSASignature(r, s *big.Int) ([]byte, error) {
	// Simple ASN.1 DER SEQUENCE of two INTEGERs
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	if len(rBytes) > 0 && rBytes[0]&0x80 != 0 {
		rBytes = append([]byte{0x00}, rBytes...)
	}
	if len(sBytes) > 0 && sBytes[0]&0x80 != 0 {
		sBytes = append([]byte{0x00}, sBytes...)
	}
	length := 2 + len(rBytes) + 2 + len(sBytes)
	out := []byte{0x30, byte(length), 0x02, byte(len(rBytes))}
	out = append(out, rBytes...)
	out = append(out, 0x02, byte(len(sBytes)))
	out = append(out, sBytes...)
	return out, nil
}

// Server Secret handling
var cachedServerSecret []byte

func GetServerSecret(dataDir string) []byte {
	if cachedServerSecret != nil {
		return cachedServerSecret
	}
	secretPath := filepath.Join(dataDir, ".server_secret")
	data, err := os.ReadFile(secretPath)
	if err == nil && len(data) >= 32 {
		cachedServerSecret = data
		return data
	}

	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	_ = os.WriteFile(secretPath, secret, 0600)
	cachedServerSecret = secret
	return secret
}

func GenerateDummySalts(serverSecret []byte, username string) (string, string) {
	h1 := hmac.New(sha256.New, serverSecret)
	h1.Write([]byte(username))
	d1 := h1.Sum(nil)

	h2 := hmac.New(sha256.New, serverSecret)
	h2.Write([]byte("srv:" + username))
	d2 := h2.Sum(nil)

	h3 := hmac.New(sha256.New, serverSecret)
	h3.Write([]byte("enc:" + username))
	d3 := h3.Sum(nil)

	clientSalt := hex.EncodeToString(d1[:16])
	serverSalt := base64.RawURLEncoding.EncodeToString(d2)
	encSalt := hex.EncodeToString(d3[:16])

	return fmt.Sprintf("%s:%s", clientSalt, serverSalt), encSalt
}

