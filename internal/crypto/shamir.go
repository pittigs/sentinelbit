package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
)

// GF(256) implementation with irreducible polynomial 0x11B (AES/standard Rijndael field)
var (
	gfExp [512]byte
	gfLog [256]byte
)

func init() {
	var x byte = 1
	for i := 0; i < 255; i++ {
		gfExp[i] = x
		gfExp[i+255] = x
		gfLog[x] = byte(i)
		// Multiply x by generator 3: (x * 2) ^ x
		x2 := x << 1
		if x&0x80 != 0 {
			x2 ^= 0x1b
		}
		x = x2 ^ x
	}
	for i := 510; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
	gfLog[0] = 0 // undefined mathematically, safe sentinel
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

func gfDiv(a, b byte) byte {
	if b == 0 {
		panic("division by zero in GF(256)")
	}
	if a == 0 {
		return 0
	}
	diff := int(gfLog[a]) - int(gfLog[b])
	if diff < 0 {
		diff += 255
	}
	return gfExp[diff]
}

// Share format: byte 0 = X coordinate (1..255), bytes 1..len = Y coordinates
type ShamirShare []byte

// SplitSecret splits a secret into N shares with threshold K (any K can recover)
func SplitSecret(secret []byte, totalParts, threshold int) ([][]byte, error) {
	if threshold < 2 {
		return nil, errors.New("threshold must be at least 2")
	}
	if totalParts < threshold {
		return nil, errors.New("total parts must be >= threshold")
	}
	if totalParts > 255 {
		return nil, errors.New("maximum parts in GF(256) is 255")
	}
	if len(secret) == 0 {
		return nil, errors.New("secret cannot be empty")
	}

	shares := make([][]byte, totalParts)
	for i := 0; i < totalParts; i++ {
		shares[i] = make([]byte, len(secret)+1)
		shares[i][0] = byte(i + 1) // x coordinate != 0
	}

	for byteIdx, secretByte := range secret {
		// Polynomial coefficients: a_0 = secretByte, a_1..a_{k-1} = random bytes
		poly := make([]byte, threshold)
		poly[0] = secretByte
		if _, err := rand.Read(poly[1:]); err != nil {
			return nil, fmt.Errorf("failed to generate random coefficients: %w", err)
		}

		// Evaluate polynomial at each x
		for i := 0; i < totalParts; i++ {
			x := shares[i][0]
			var y byte = poly[0]
			var xPow byte = 1
			for c := 1; c < threshold; c++ {
				xPow = gfMul(xPow, x)
				term := gfMul(poly[c], xPow)
				y ^= term
			}
			shares[i][byteIdx+1] = y
		}
	}

	return shares, nil
}

// CombineShares reconstructs the secret using Lagrange interpolation at x=0
func CombineShares(shares [][]byte) ([]byte, error) {
	if len(shares) < 2 {
		return nil, errors.New("at least 2 shares required")
	}

	shareLen := len(shares[0])
	if shareLen < 2 {
		return nil, errors.New("invalid share format")
	}

	for _, s := range shares {
		if len(s) != shareLen {
			return nil, errors.New("mismatched share lengths")
		}
	}

	k := len(shares)
	secretLen := shareLen - 1
	secret := make([]byte, secretLen)

	xVals := make([]byte, k)
	for i, s := range shares {
		xVals[i] = s[0]
	}

	// Lagrange interpolation for each byte at x = 0:
	// L_i(0) = \prod_{j != i} (0 - x_j) / (x_i - x_j) = \prod_{j != i} x_j / (x_i ^ x_j)
	for byteIdx := 0; byteIdx < secretLen; byteIdx++ {
		var secretByte byte = 0
		for i := 0; i < k; i++ {
			xi := xVals[i]
			yi := shares[i][byteIdx+1]

			var li byte = 1
			for j := 0; j < k; j++ {
				if i == j {
					continue
				}
				xj := xVals[j]
				num := xj
				den := xi ^ xj // in GF(2^8) subtraction is XOR
				term := gfDiv(num, den)
				li = gfMul(li, term)
			}

			secretByte ^= gfMul(yi, li)
		}
		secret[byteIdx] = secretByte
	}

	return secret, nil
}
