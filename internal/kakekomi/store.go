package kakekomi

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db      *sql.DB
	dataDir string
}

const schema = `
CREATE TABLE IF NOT EXISTS cases (
    id            TEXT PRIMARY KEY,
    code_lookup   BLOB NOT NULL,           -- HMAC(server_lookup_key, code) for O(1) /reply
    code_hash     BLOB NOT NULL,
    code_salt     BLOB NOT NULL,
    created_at    INTEGER NOT NULL,        -- rounded to hour (SPEC F-73)
    expires_at    INTEGER NOT NULL,
    read_flag     INTEGER NOT NULL DEFAULT 0,
    has_reply     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_cases_expires_at ON cases(expires_at);
CREATE INDEX IF NOT EXISTS idx_cases_code_lookup ON cases(code_lookup);
`

func OpenStore(dataDir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dataDir, "blob"), 0700); err != nil {
		return nil, err
	}
	dsn := filepath.Join(dataDir, "kakekomi.db") + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return &Store{db: db, dataDir: dataDir}, nil
}

func (s *Store) Close() error { return s.db.Close() }

type Case struct {
	ID        string
	CreatedAt time.Time
	ExpiresAt time.Time
	Read      bool
	HasReply  bool
	Size      int64
}

func (s *Store) caseDir(id string) string {
	return filepath.Join(s.dataDir, "blob", id)
}
func (s *Store) blobPath(id string) string {
	return filepath.Join(s.caseDir(id), "case-data.tar.age")
}
func (s *Store) replyPath(id string) string {
	return filepath.Join(s.caseDir(id), "reply.bin")
}

func isUniqueErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "UNIQUE") || strings.Contains(s, "PRIMARY KEY")
}

// CreateCase inserts case metadata with a fresh ID (with collision retry),
// then writes the encrypted submission blob to <data>/blob/<id>/case-data.tar.age.
// Returns the case ID used.
//
// codeLookup is a server-secret HMAC of the code (see CaseCodeLookup) that
// the receiver-side keeps in memory only. It enables O(1) /reply lookup.
func (s *Store) CreateCase(codeLookup, codeHash, codeSalt []byte, ttl time.Duration, blob []byte) (string, error) {
	const maxRetries = 5
	// SPEC F-73: timestamp rounded to hour.
	now := time.Now().UTC().Truncate(time.Hour)
	expires := now.Add(ttl).Unix()

	for i := 0; i < maxRetries; i++ {
		id, err := NewID()
		if err != nil {
			return "", err
		}
		_, err = s.db.Exec(
			`INSERT INTO cases (id, code_lookup, code_hash, code_salt, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)`,
			id, codeLookup, codeHash, codeSalt, now.Unix(), expires,
		)
		if err == nil {
			if mkerr := os.MkdirAll(s.caseDir(id), 0700); mkerr != nil {
				_, _ = s.db.Exec(`DELETE FROM cases WHERE id = ?`, id)
				return "", fmt.Errorf("mkdir case: %w", mkerr)
			}
			if werr := os.WriteFile(s.blobPath(id), blob, 0600); werr != nil {
				_ = os.RemoveAll(s.caseDir(id))
				_, _ = s.db.Exec(`DELETE FROM cases WHERE id = ?`, id)
				return "", fmt.Errorf("write blob: %w", werr)
			}
			return id, nil
		}
		if !isUniqueErr(err) {
			return "", fmt.Errorf("insert case: %w", err)
		}
	}
	return "", errors.New("case_id collision retries exhausted")
}

func (s *Store) ListCases() ([]Case, error) {
	rows, err := s.db.Query(
		`SELECT id, created_at, expires_at, read_flag, has_reply FROM cases ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Case
	for rows.Next() {
		var c Case
		var created, expires int64
		var read, hasReply int
		if err := rows.Scan(&c.ID, &created, &expires, &read, &hasReply); err != nil {
			return nil, err
		}
		c.CreatedAt = time.Unix(created, 0)
		c.ExpiresAt = time.Unix(expires, 0)
		c.Read = read == 1
		c.HasReply = hasReply == 1
		if fi, err := os.Stat(s.blobPath(c.ID)); err == nil {
			c.Size = fi.Size()
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) GetCase(id string) (*Case, error) {
	row := s.db.QueryRow(
		`SELECT id, created_at, expires_at, read_flag, has_reply FROM cases WHERE id = ?`, id,
	)
	var c Case
	var created, expires int64
	var read, hasReply int
	if err := row.Scan(&c.ID, &created, &expires, &read, &hasReply); err != nil {
		return nil, err
	}
	c.CreatedAt = time.Unix(created, 0)
	c.ExpiresAt = time.Unix(expires, 0)
	c.Read = read == 1
	c.HasReply = hasReply == 1
	if fi, err := os.Stat(s.blobPath(c.ID)); err == nil {
		c.Size = fi.Size()
	}
	return &c, nil
}

func (s *Store) ReadBlob(id string) ([]byte, error) {
	return os.ReadFile(s.blobPath(id))
}

func (s *Store) MarkRead(id string) error {
	_, err := s.db.Exec(`UPDATE cases SET read_flag = 1 WHERE id = ?`, id)
	return err
}

// WriteReply persists an encrypted reply blob and flips has_reply=1.
func (s *Store) WriteReply(id string, blob []byte) error {
	if _, err := s.GetCase(id); err != nil {
		return err
	}
	if err := os.WriteFile(s.replyPath(id), blob, 0600); err != nil {
		return err
	}
	_, err := s.db.Exec(`UPDATE cases SET has_reply = 1 WHERE id = ?`, id)
	return err
}

func (s *Store) ReadReply(id string) ([]byte, error) {
	return os.ReadFile(s.replyPath(id))
}

// FindCaseByCode looks up by the indexed HMAC, then runs ONE argon2id verify.
// Total time is independent of case count: a SELECT returning 0-or-1 rows plus
// exactly one argon2id evaluation (with a dummy salt if no row matches).
//
// codeLookup is HMAC(secrets.LookupKey, code) — the caller computes it.
func (s *Store) FindCaseByCode(code string, codeLookup []byte) (string, error) {
	row := s.db.QueryRow(
		`SELECT id, code_salt, code_hash FROM cases WHERE code_lookup = ? LIMIT 1`,
		codeLookup,
	)
	var id string
	var salt, hash []byte
	err := row.Scan(&id, &salt, &hash)
	switch {
	case err == sql.ErrNoRows:
		// Run a dummy argon2id verify to keep wall-time independent of presence.
		dummy := make([]byte, 16)
		_ = HashCode(code, dummy)
		return "", errors.New("code not found")
	case err != nil:
		return "", err
	}
	if VerifyCode(code, salt, hash) {
		return id, nil
	}
	return "", errors.New("code not found")
}

// GC deletes expired cases (DB row + blob dir).
func (s *Store) GC() (int, error) {
	rows, err := s.db.Query(`SELECT id FROM cases WHERE expires_at < ?`, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	var expired []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		expired = append(expired, id)
	}
	rows.Close()

	n := 0
	for _, id := range expired {
		if err := shredDir(s.caseDir(id)); err != nil && !os.IsNotExist(err) {
			return n, err
		}
		if _, err := s.db.Exec(`DELETE FROM cases WHERE id = ?`, id); err != nil {
			return n, err
		}
		n++
	}
	// Compact SQLite to remove tombstones (HARDENING §L2.2).
	_, _ = s.db.Exec(`VACUUM`)
	return n, nil
}

// shredDir best-effort overwrites each file with zeros before unlinking,
// then removes the directory. On SSD this is not a true secure erase but it
// removes cold cache / page cache traces in volatile layers.
func shredDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if e.IsDir() {
			if err := shredDir(p); err != nil {
				return err
			}
			continue
		}
		fi, err := os.Stat(p)
		if err != nil {
			return err
		}
		zeros := make([]byte, fi.Size())
		_ = os.WriteFile(p, zeros, 0600)
		_ = os.Remove(p)
	}
	return os.Remove(dir)
}

// Wipe is the duress-mode emergency wipe: drops ALL cases (DB + blobs).
func (s *Store) Wipe() error {
	dir := filepath.Join(s.dataDir, "blob")
	entries, err := os.ReadDir(dir)
	if err == nil {
		for _, e := range entries {
			_ = shredDir(filepath.Join(dir, e.Name()))
		}
	}
	if _, err := s.db.Exec(`DELETE FROM cases`); err != nil {
		return err
	}
	_, _ = s.db.Exec(`VACUUM`)
	return nil
}
