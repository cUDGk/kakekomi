package kakekomi

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"strings"

	"filippo.io/age"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Argon2id parameters.
//
//   - Code hash (per-case): moderate cost. Sequential verify uses it.
//   - Master key (passphrase KDF): heavy cost. Done once per `run` startup.
const (
	argonTime    = 2
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32

	masterArgonTime    = 4
	masterArgonMemory  = 256 * 1024 // 256 MiB — heavier; once per startup
	masterArgonThreads = 4
	masterArgonKeyLen  = 32
)

// Domain-separation labels for HKDF / HMAC derivations.
// HARDENING.md §L0.1: every derived key gets a unique versioned label.
const (
	HKDFReplyKey       = "kakekomi/v1/reply-key"
	HKDFMasterAge      = "kakekomi/v1/master-age-identity"
	HKDFCSRFKey        = "kakekomi/v1/csrf-key"
	HKDFSessionKey     = "kakekomi/v1/session-key"
	HKDFPoWKey         = "kakekomi/v1/pow-challenge"
	HMACCaseCodeLookup = "kakekomi/v1/case-code-lookup"
)

// Envelope header (versioned blob format, HARDENING.md §L0.3).
//
//	| "KKK1" (4B) | version (2B BE) | reserved (2B 0x0000) | payload ... |
//
// Phase 1 uses version=1 (age envelope payload).
const (
	envelopeMagic   = "KKK1"
	envelopeVersion = uint16(1)
)

// GenerateAgeKey returns (publicKey, secretKey) in age string format.
func GenerateAgeKey() (publicKey, secretKey string, err error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return "", "", err
	}
	return id.Recipient().String(), id.String(), nil
}

// GenerateCode returns 7 random BIP39 English words (~77 bits entropy).
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
		idx := (int(buf[0])<<8 | int(buf[1])) & 0x07FF // 65536/2048=32 exactly: unbiased
		out[i] = words[idx]
	}
	return strings.Join(out, " "), nil
}

// CaseCodeLookup is a fast HMAC of the case code with a server-secret key.
// It's stored in the DB and indexed so /reply lookups are O(1) instead of
// O(N) over all cases with argon2id. Offline brute-force against this hash
// requires the LookupKey (32 random bytes in secrets.age).
func CaseCodeLookup(lookupKey []byte, code string) []byte {
	mac := hmac.New(sha256.New, lookupKey)
	mac.Write([]byte(HMACCaseCodeLookup))
	mac.Write([]byte(code))
	return mac.Sum(nil)
}

// HashCode derives an argon2id hash of code with the given salt (per-case verification).
func HashCode(code string, salt []byte) []byte {
	return argon2.IDKey([]byte(code), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
}

// VerifyCode constant-time-compares HashCode(code, salt) against expected.
func VerifyCode(code string, salt, expected []byte) bool {
	got := HashCode(code, salt)
	return subtle.ConstantTimeCompare(got, expected) == 1
}

// DeriveMasterKey turns a passphrase into a 32-byte master key (heavy argon2id).
func DeriveMasterKey(passphrase string, salt []byte) []byte {
	return argon2.IDKey(
		[]byte(passphrase), salt,
		masterArgonTime, masterArgonMemory, masterArgonThreads, masterArgonKeyLen,
	)
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

// HKDFKey derives a fixed-length key using HKDF-SHA256 with a versioned info label.
// All derivations in kakekomi MUST go through this with a label from HKDF*Key constants.
func HKDFKey(secret, salt []byte, info string, length int) ([]byte, error) {
	r := hkdf.New(sha256.New, secret, salt, []byte(info))
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// EncryptToReceiver wraps age (X25519 recipient) with the kakekomi envelope header.
func EncryptToReceiver(publicKey string, plaintext []byte) ([]byte, error) {
	rcpt, err := age.ParseX25519Recipient(publicKey)
	if err != nil {
		return nil, err
	}
	var inner bytes.Buffer
	w, err := age.Encrypt(&inner, rcpt)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(w, bytes.NewReader(plaintext)); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return wrapEnvelope(envelopeVersion, inner.Bytes()), nil
}

// DecryptFromReceiver opens an envelope blob with the given age identity (used by viewer).
func DecryptFromReceiver(secretKey string, blob []byte) ([]byte, error) {
	id, err := age.ParseX25519Identity(secretKey)
	if err != nil {
		return nil, err
	}
	version, payload, err := unwrapEnvelope(blob)
	if err != nil {
		return nil, err
	}
	if version != envelopeVersion {
		return nil, errOnlyV1
	}
	r, err := age.Decrypt(bytes.NewReader(payload), id)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// EncryptSymmetric encrypts plaintext with a 32-byte key using ChaCha20-Poly1305 (XChaCha20).
// Output: nonce(24) || ciphertext.
// Wrapped in the kakekomi envelope.
func EncryptSymmetric(key []byte, plaintext []byte) ([]byte, error) {
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, a.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := a.Seal(nil, nonce, plaintext, nil)
	payload := append(nonce, ct...)
	return wrapEnvelope(envelopeVersion, payload), nil
}

// DecryptSymmetric reverses EncryptSymmetric.
func DecryptSymmetric(key []byte, blob []byte) ([]byte, error) {
	version, payload, err := unwrapEnvelope(blob)
	if err != nil {
		return nil, err
	}
	if version != envelopeVersion {
		return nil, errOnlyV1
	}
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(payload) < a.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := payload[:a.NonceSize()], payload[a.NonceSize():]
	return a.Open(nil, nonce, ct, nil)
}

var errOnlyV1 = errors.New("envelope version unsupported (only v1 in this build)")

func wrapEnvelope(version uint16, payload []byte) []byte {
	out := make([]byte, 8+len(payload))
	copy(out[0:4], envelopeMagic)
	binary.BigEndian.PutUint16(out[4:6], version)
	// reserved 6:8 = 0
	copy(out[8:], payload)
	return out
}

func unwrapEnvelope(blob []byte) (version uint16, payload []byte, err error) {
	if len(blob) < 8 {
		return 0, nil, errors.New("blob too short")
	}
	if string(blob[0:4]) != envelopeMagic {
		return 0, nil, errors.New("bad envelope magic")
	}
	version = binary.BigEndian.Uint16(blob[4:6])
	payload = blob[8:]
	return version, payload, nil
}

// PubkeyFingerprint returns the SHA-256 hex of the (string-form) public key,
// used by pubkey.lock (HARDENING §L4 / SPEC F-16).
func PubkeyFingerprint(publicKey string) string {
	sum := sha256.Sum256([]byte(publicKey))
	return hex.EncodeToString(sum[:])
}
