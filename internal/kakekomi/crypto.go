package kakekomi

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"strings"

	"filippo.io/age"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/argon2"
)

// argon2id parameters for code hashing.
// Moderate cost; the per-case verification path runs sequentially so this is OK.
const (
	argonTime    = 2
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 2
	argonKeyLen  = 32
)

// GenerateAgeKey returns (publicKey, secretKey) in age string format.
func GenerateAgeKey() (publicKey, secretKey string, err error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return "", "", err
	}
	return id.Recipient().String(), id.String(), nil
}

// GenerateCode returns 7 random words from the BIP39 English wordlist.
// 7 × log2(2048) ≈ 77 bits of entropy — sufficient given argon2id verification.
func GenerateCode() (string, error) {
	words := bip39.GetWordList()
	if len(words) != 2048 {
		return "", errors.New("unexpected wordlist size")
	}
	out := make([]string, 7)
	for i := range out {
		var buf [2]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return "", err
		}
		// 65536 / 2048 = 32 exactly, so modulo is unbiased.
		idx := (int(buf[0])<<8 | int(buf[1])) & 0x07FF
		out[i] = words[idx]
	}
	return strings.Join(out, " "), nil
}

// HashCode derives an argon2id hash of code with the given salt.
func HashCode(code string, salt []byte) []byte {
	return argon2.IDKey([]byte(code), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
}

// VerifyCode does a constant-time compare of HashCode(code, salt) against expected.
func VerifyCode(code string, salt, expected []byte) bool {
	got := HashCode(code, salt)
	return subtle.ConstantTimeCompare(got, expected) == 1
}

// NewSalt returns 16 random bytes.
func NewSalt() ([]byte, error) {
	s := make([]byte, 16)
	if _, err := rand.Read(s); err != nil {
		return nil, err
	}
	return s, nil
}

// NewID returns a 16-hex-char case ID (8 random bytes).
func NewID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// Encrypt produces an age-encrypted blob for the given recipient public key.
func Encrypt(publicKey string, plaintext []byte) ([]byte, error) {
	rcpt, err := age.ParseX25519Recipient(publicKey)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, rcpt)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(w, bytes.NewReader(plaintext)); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
