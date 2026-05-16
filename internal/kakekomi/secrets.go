package kakekomi

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/argon2"
)

// Secrets are the persistent receiver-side runtime keys: TOTP, admin password
// hash, optional Tor control auth. They live in <data>/config/secrets.age,
// encrypted with master_key derived from a receiver passphrase (argon2id).
//
// At rest:
//
//	secrets.age = envelope(version=1, ChaCha20-Poly1305(master_key, secretsPayload))
type Secrets struct {
	// argon2id salt for master_key derivation (16 B).
	MasterSalt []byte `json:"master_salt"`

	AdminPasswordHash []byte `json:"admin_password_hash"`
	AdminPasswordSalt []byte `json:"admin_password_salt"`

	TOTPSecret       string `json:"totp_secret"`
	TOTPSecretDuress string `json:"totp_secret_duress"`

	CSRFKey       []byte `json:"csrf_key"`
	SessionMACKey []byte `json:"session_mac_key"`

	// LookupKey is the HMAC key used to compute the indexed code lookup hash.
	// Stays in memory only after secrets.age decrypt; never written separately.
	LookupKey []byte `json:"lookup_key"`
}

func secretsPath(dataDir string) string {
	return filepath.Join(dataDir, "config", "secrets.age")
}

func saltPath(dataDir string) string {
	return filepath.Join(dataDir, "config", "secrets.salt")
}

// NewSecrets generates a fresh secrets set with random TOTP, salts, MAC keys.
func NewSecrets() (*Secrets, error) {
	s := &Secrets{}
	var err error
	if s.MasterSalt, err = randomBytes(16); err != nil {
		return nil, err
	}
	if s.AdminPasswordSalt, err = randomBytes(16); err != nil {
		return nil, err
	}
	if s.CSRFKey, err = randomBytes(32); err != nil {
		return nil, err
	}
	if s.SessionMACKey, err = randomBytes(32); err != nil {
		return nil, err
	}
	if s.LookupKey, err = randomBytes(32); err != nil {
		return nil, err
	}
	return s, nil
}

// SetAdminPassword updates the password hash (argon2id) from a plain string.
func (s *Secrets) SetAdminPassword(pw string) {
	s.AdminPasswordHash = argon2.IDKey([]byte(pw), s.AdminPasswordSalt,
		argonTime, argonMemory, argonThreads, argonKeyLen)
}

// CheckAdminPassword constant-time-compares an attempted password.
func (s *Secrets) CheckAdminPassword(pw string) bool {
	got := argon2.IDKey([]byte(pw), s.AdminPasswordSalt,
		argonTime, argonMemory, argonThreads, argonKeyLen)
	return subtle.ConstantTimeCompare(got, s.AdminPasswordHash) == 1
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// SaveSecrets serializes Secrets, derives a master_key from passphrase, encrypts,
// and writes secrets.age + secrets.salt (the salt is duplicated to make
// startup faster — we read salt without parsing the encrypted blob).
func SaveSecrets(dataDir, passphrase string, s *Secrets) error {
	body, err := json.Marshal(s)
	if err != nil {
		return err
	}
	// M7 fix: body contains plaintext secrets — zero after encryption.
	defer zero(body)
	master := DeriveMasterKey(passphrase, s.MasterSalt)
	defer zero(master)
	blob, err := EncryptSymmetric(master, body)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(secretsPath(dataDir)), 0700); err != nil {
		return err
	}
	if err := os.WriteFile(secretsPath(dataDir), blob, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(saltPath(dataDir), s.MasterSalt, 0600); err != nil {
		return err
	}
	return nil
}

// LoadSecrets reads salt, derives master_key from passphrase, decrypts secrets.age.
func LoadSecrets(dataDir, passphrase string) (*Secrets, error) {
	salt, err := os.ReadFile(saltPath(dataDir))
	if err != nil {
		return nil, fmt.Errorf("read salt: %w", err)
	}
	blob, err := os.ReadFile(secretsPath(dataDir))
	if err != nil {
		return nil, fmt.Errorf("read secrets.age: %w", err)
	}
	master := DeriveMasterKey(passphrase, salt)
	defer zero(master)
	body, err := DecryptSymmetric(master, blob)
	if err != nil {
		return nil, errors.New("secrets decrypt failed — wrong passphrase or corrupted secrets.age")
	}
	// M7 fix: zero the plaintext JSON after Unmarshal copies its byte fields.
	defer zero(body)
	var s Secrets
	if err := json.Unmarshal(body, &s); err != nil {
		return nil, fmt.Errorf("parse secrets: %w", err)
	}
	return &s, nil
}

// zero overwrites a byte slice. Best-effort: Go can't truly guarantee against
// compiler/GC behavior, hence the memguard wrappers are used at API boundaries.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// SecureBuffer locks a sensitive byte slice in memory (mlock/VirtualLock via
// memguard) and provides explicit Destroy.
func SecureBuffer(data []byte) *memguard.LockedBuffer {
	return memguard.NewBufferFromBytes(data)
}
