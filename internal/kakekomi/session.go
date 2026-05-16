package kakekomi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"
)

// In-memory session store for the receiver admin dashboard.
// HARDENING §L4.7: HttpOnly / Secure / SameSite=Strict / Path=/admin /
// 15 min idle / store in memory only / wiped on restart.

const (
	SessionCookie   = "kakekomi_admin"
	CSRFFormField   = "_csrf"
	CSRFHeaderField = "X-CSRF-Token"
	idleTimeout     = 15 * time.Minute
)

type Session struct {
	Token     string
	CreatedAt time.Time
	LastSeen  time.Time
}

type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]*Session
	csrfKey  []byte
}

func NewSessionStore(csrfKey []byte) *SessionStore {
	return &SessionStore{
		sessions: make(map[string]*Session),
		csrfKey:  append([]byte(nil), csrfKey...),
	}
}

func (s *SessionStore) New() (*Session, error) {
	var b [32]byte
	if _, err := readRandom(b[:]); err != nil {
		return nil, err
	}
	tok := hex.EncodeToString(b[:])
	now := time.Now()
	sess := &Session{Token: tok, CreatedAt: now, LastSeen: now}
	s.mu.Lock()
	s.sessions[tok] = sess
	s.mu.Unlock()
	return sess, nil
}

// Touch validates a token and refreshes LastSeen. Returns nil if invalid/expired.
func (s *SessionStore) Touch(token string) *Session {
	if token == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[token]
	if !ok {
		return nil
	}
	if time.Since(sess.LastSeen) > idleTimeout {
		delete(s.sessions, token)
		return nil
	}
	sess.LastSeen = time.Now()
	return sess
}

func (s *SessionStore) Destroy(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

// CSRFToken returns the per-session CSRF token derived from the master CSRF key.
// Bound to the session token so it can't be reused across sessions.
func (s *SessionStore) CSRFToken(sessionToken string) string {
	mac := hmac.New(sha256.New, s.csrfKey)
	mac.Write([]byte("kakekomi/v1/csrf"))
	mac.Write([]byte(sessionToken))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyCSRF checks that the form-supplied token matches the expected token
// for the current session.
func (s *SessionStore) VerifyCSRF(sessionToken, formToken string) bool {
	want := s.CSRFToken(sessionToken)
	return hmac.Equal([]byte(want), []byte(strings.TrimSpace(formToken)))
}

// AnonCSRFCookie is the cookie name for unauthenticated form CSRF tokens.
// Uses the double-submit cookie pattern: on GET we set a random value as
// both a cookie and an embedded form field; on POST we constant-time compare
// the two. SameSite=Strict + HttpOnly prevent cross-origin reading or sending.
const AnonCSRFCookie = "kakekomi_anon_csrf"

// NewAnonCSRFToken returns 32 random bytes hex-encoded.
func (s *SessionStore) NewAnonCSRFToken() (string, error) {
	var b [32]byte
	if _, err := readRandom(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// VerifyAnonCSRF constant-time-compares cookie vs form value.
func (s *SessionStore) VerifyAnonCSRF(cookieValue, formValue string) bool {
	if cookieValue == "" || formValue == "" {
		return false
	}
	return hmac.Equal([]byte(strings.TrimSpace(cookieValue)), []byte(strings.TrimSpace(formValue)))
}

func setAnonCSRFCookie(w http.ResponseWriter, r *http.Request, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     AnonCSRFCookie,
		Value:    value,
		Path:     "/submit",
		HttpOnly: true,
		Secure:   secureContext(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   600, // 10 min; form must be filled within this window
	})
}

func readAnonCSRFCookie(r *http.Request) string {
	c, err := r.Cookie(AnonCSRFCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

// secureContext: HTTPS, .onion, or localhost-with-allowance.
// Tor onion services are confidentially-transported even without TLS,
// so Tor browser accepts Secure cookies on .onion. Localhost is allowed
// only for development/testing.
func secureContext(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	host := r.Host
	if i := indexOfColon(host); i >= 0 {
		host = host[:i]
	}
	return endsWith(host, ".onion")
}

func indexOfColon(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return i
		}
	}
	return -1
}

func endsWith(s, suffix string) bool {
	if len(s) < len(suffix) {
		return false
	}
	return s[len(s)-len(suffix):] == suffix
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    token,
		Path:     "/admin",
		HttpOnly: true,
		Secure:   secureContext(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(idleTimeout.Seconds()),
	})
}

func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    "",
		Path:     "/admin",
		HttpOnly: true,
		Secure:   secureContext(r),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

func readSessionCookie(r *http.Request) string {
	c, err := r.Cookie(SessionCookie)
	if err != nil {
		return ""
	}
	return c.Value
}
