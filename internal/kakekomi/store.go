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
    id         TEXT PRIMARY KEY,
    code_hash  BLOB NOT NULL,
    code_salt  BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    read_flag  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_cases_expires_at ON cases(expires_at);
`

func OpenStore(dataDir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dataDir, "blob"), 0700); err != nil {
		return nil, err
	}
	dsn := filepath.Join(dataDir, "kakekomi.db")
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
	Size      int64
}

func (s *Store) blobPath(id string) string {
	return filepath.Join(s.dataDir, "blob", id+".age")
}

// isUniqueErr detects SQLite UNIQUE / PRIMARY KEY constraint violations.
// modernc.org/sqlite surfaces these via the error string.
func isUniqueErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "UNIQUE") || strings.Contains(s, "PRIMARY KEY")
}

// CreateCase generates a unique case_id, inserts the metadata row, then writes
// the encrypted blob. Returns the case ID used. The INSERT is performed first
// so uniqueness is atomic; on UNIQUE collision a new ID is tried (up to 5x).
func (s *Store) CreateCase(codeHash, codeSalt []byte, ttl time.Duration, blob []byte) (string, error) {
	const maxRetries = 5
	now := time.Now()
	expires := now.Add(ttl).Unix()

	for i := 0; i < maxRetries; i++ {
		id, err := NewID()
		if err != nil {
			return "", err
		}
		_, err = s.db.Exec(
			`INSERT INTO cases (id, code_hash, code_salt, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
			id, codeHash, codeSalt, now.Unix(), expires,
		)
		if err == nil {
			if werr := os.WriteFile(s.blobPath(id), blob, 0600); werr != nil {
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
		`SELECT id, created_at, expires_at, read_flag FROM cases ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Case
	for rows.Next() {
		var c Case
		var created, expires int64
		var read int
		if err := rows.Scan(&c.ID, &created, &expires, &read); err != nil {
			return nil, err
		}
		c.CreatedAt = time.Unix(created, 0)
		c.ExpiresAt = time.Unix(expires, 0)
		c.Read = read == 1
		if fi, err := os.Stat(s.blobPath(c.ID)); err == nil {
			c.Size = fi.Size()
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) ReadBlob(id string) ([]byte, error) {
	return os.ReadFile(s.blobPath(id))
}

func (s *Store) MarkRead(id string) error {
	_, err := s.db.Exec(`UPDATE cases SET read_flag = 1 WHERE id = ?`, id)
	return err
}

// FindCaseByCode walks every case, verifying argon2id(code, salt) against the
// stored hash. The loop intentionally does NOT short-circuit on match: total
// time depends only on case count, not on which row matched.
//
// Phase 1 residual leak: total time scales with N (number of cases). When N
// grows large, /reply timing observable to a remote attacker can leak the
// approximate case count. Phase 5+ should split into indexed lookup + verify.
func (s *Store) FindCaseByCode(code string) (string, error) {
	rows, err := s.db.Query(`SELECT id, code_salt, code_hash FROM cases`)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	var foundID string
	var found int
	for rows.Next() {
		var id string
		var salt, hash []byte
		if err := rows.Scan(&id, &salt, &hash); err != nil {
			return "", err
		}
		if VerifyCode(code, salt, hash) && found == 0 {
			foundID = id
			found = 1
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if found == 0 {
		return "", errors.New("code not found")
	}
	return foundID, nil
}

// GC deletes expired cases (DB row + blob file) and returns the removed count.
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
		if err := os.Remove(s.blobPath(id)); err != nil && !os.IsNotExist(err) {
			return n, err
		}
		if _, err := s.db.Exec(`DELETE FROM cases WHERE id = ?`, id); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
