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

// CreateCase writes blob and inserts metadata. On metadata failure the blob is removed.
func (s *Store) CreateCase(id string, codeHash, codeSalt []byte, ttl time.Duration, blob []byte) error {
	if strings.ContainsAny(id, `/\.`) || id == "" {
		return errors.New("invalid case id")
	}
	now := time.Now()
	path := s.blobPath(id)
	if err := os.WriteFile(path, blob, 0600); err != nil {
		return fmt.Errorf("write blob: %w", err)
	}
	_, err := s.db.Exec(
		`INSERT INTO cases (id, code_hash, code_salt, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
		id, codeHash, codeSalt, now.Unix(), now.Add(ttl).Unix(),
	)
	if err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("insert case: %w", err)
	}
	return nil
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

// FindCaseByCode walks all cases verifying argon2id(code, salt) against the stored hash.
// O(n) is acceptable for Phase 1; revisit when n is large.
func (s *Store) FindCaseByCode(code string) (string, error) {
	rows, err := s.db.Query(`SELECT id, code_salt, code_hash FROM cases`)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	for rows.Next() {
		var id string
		var salt, hash []byte
		if err := rows.Scan(&id, &salt, &hash); err != nil {
			return "", err
		}
		if VerifyCode(code, salt, hash) {
			return id, nil
		}
	}
	return "", errors.New("code not found")
}
