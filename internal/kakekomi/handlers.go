package kakekomi

import (
	"fmt"
	"html/template"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
)

type App struct {
	Config    *Config
	Store     *Store
	Secrets   *Secrets
	Sessions  *SessionStore
	Templates map[string]*template.Template
}

func (a *App) Routes(mux *http.ServeMux) {
	mux.HandleFunc("/", a.handleIndex)
	mux.HandleFunc("/submit", a.handleSubmit)
	mux.HandleFunc("/reply", a.handleReply)

	mux.HandleFunc("/admin", a.handleAdminRoot)
	mux.HandleFunc("/admin/login", a.handleAdminLogin)
	mux.HandleFunc("/admin/logout", a.requireAuth(a.handleAdminLogout))
	mux.HandleFunc("/admin/inbox", a.requireAuth(a.handleAdminInbox))
	mux.HandleFunc("/admin/case/", a.requireAuth(a.handleAdminCase))
	mux.HandleFunc("/admin/reply/", a.requireAuth(a.handleAdminReply))
	mux.HandleFunc("/admin/download/", a.requireAuth(a.handleAdminDownload))
}

type pageData struct {
	SiteTitle string
	SiteIntro string
	CSRF      string
	PoWToken  string
	Honeypot  bool
	Data      any
}

func (a *App) render(w http.ResponseWriter, r *http.Request, name string, data any) {
	t, ok := a.Templates[name]
	if !ok {
		http.Error(w, "template not found: "+name, http.StatusInternalServerError)
		return
	}
	pd := pageData{
		SiteTitle: a.Config.Site.Title,
		SiteIntro: a.Config.Site.Intro,
		Honeypot:  a.Config.Security.Honeypot,
		Data:      data,
	}
	if sessTok := readSessionCookie(r); sessTok != "" {
		pd.CSRF = a.Sessions.CSRFToken(sessTok)
	}
	pw := NewPaddedWriter(w)
	pw.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(pw, "layout", pd); err != nil {
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}
	_ = pw.Flush()
}

// renderPublic is like render but uses an anonymous-CSRF tied to a PoW token.
func (a *App) renderPublic(w http.ResponseWriter, name string, data any, powToken string) {
	t, ok := a.Templates[name]
	if !ok {
		http.Error(w, "template not found: "+name, http.StatusInternalServerError)
		return
	}
	pd := pageData{
		SiteTitle: a.Config.Site.Title,
		SiteIntro: a.Config.Site.Intro,
		Honeypot:  a.Config.Security.Honeypot,
		PoWToken:  powToken,
		Data:      data,
	}
	if powToken != "" {
		pd.CSRF = a.Sessions.AnonCSRFToken(powToken)
	}
	pw := NewPaddedWriter(w)
	pw.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(pw, "layout", pd); err != nil {
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}
	_ = pw.Flush()
}

// ─── public side ─────────────────────────────────────────────

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	a.renderPublic(w, "index", nil, "")
}

type submitForm struct {
	Fields      []Field
	Attachments AttachmentsConfig
}

func (a *App) handleSubmit(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		tok := IssuePoWToken(a.Secrets.SessionMACKey)
		a.renderPublic(w, "submit", submitForm{Fields: a.Config.Fields, Attachments: a.Config.Attachments}, tok)
	case http.MethodPost:
		a.processSubmit(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *App) processSubmit(w http.ResponseWriter, r *http.Request) {
	// Fixed total wait floor (timing normalization).
	deadline := time.Now().Add(2 * time.Second)
	defer func() { FixedWaitUntil(deadline) }()

	// Body cap = max attachment total + 1 MiB headroom.
	maxBody := int64(a.Config.Attachments.MaxTotalSizeMB)*1024*1024 + 1<<20
	if maxBody < 2<<20 {
		maxBody = 2 << 20
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)

	if err := r.ParseMultipartForm(maxBody); err != nil {
		if err2 := r.ParseForm(); err2 != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
	}

	// Honeypot.
	if a.Config.Security.Honeypot && strings.TrimSpace(r.FormValue("hp_name")) != "" {
		// Pretend success but discard.
		a.renderPublic(w, "done", "honeypot triggered", "")
		return
	}

	// PoW + CSRF.
	powTok := r.FormValue("_pow")
	if a.Config.Security.PoW.Enabled {
		if err := VerifyPoWToken(a.Secrets.SessionMACKey, powTok); err != nil {
			http.Error(w, "PoW token invalid or expired", http.StatusForbidden)
			return
		}
	}
	if !a.Sessions.VerifyAnonCSRF(powTok, r.FormValue(CSRFFormField)) {
		http.Error(w, "CSRF token invalid", http.StatusForbidden)
		return
	}
	if a.Config.Security.PoW.Enabled {
		PoWWork(powTok, a.Config.Security.PoW.HashChainCost)
	}

	// Collect text fields.
	values := make(map[string]string, len(a.Config.Fields))
	for _, f := range a.Config.Fields {
		v := strings.TrimSpace(r.FormValue(f.ID))
		if f.Required && v == "" {
			http.Error(w, "required field missing: "+f.ID, http.StatusBadRequest)
			return
		}
		if f.MaxLength > 0 && len(v) > f.MaxLength {
			http.Error(w, "field too long: "+f.ID, http.StatusBadRequest)
			return
		}
		if v != "" {
			values[f.ID] = v
		}
	}

	// Collect attachments.
	var atts []Attachment
	if a.Config.Attachments.Enabled && r.MultipartForm != nil {
		files := r.MultipartForm.File["attachments"]
		if len(files) > a.Config.Attachments.MaxFiles {
			http.Error(w, "too many attachments", http.StatusBadRequest)
			return
		}
		totalSize := 0
		for _, fh := range files {
			if int(fh.Size) > a.Config.Attachments.MaxSizeMBPerFile*1024*1024 {
				http.Error(w, "attachment too large", http.StatusBadRequest)
				return
			}
			totalSize += int(fh.Size)
			if totalSize > a.Config.Attachments.MaxTotalSizeMB*1024*1024 {
				http.Error(w, "total attachment size exceeds limit", http.StatusBadRequest)
				return
			}
			f, err := fh.Open()
			if err != nil {
				http.Error(w, "open attachment", http.StatusBadRequest)
				return
			}
			data, err := io.ReadAll(f)
			f.Close()
			if err != nil {
				http.Error(w, "read attachment", http.StatusBadRequest)
				return
			}
			mt, err := VerifyAttachment(data, a.Config.Attachments.AllowedMIME)
			if err != nil {
				http.Error(w, "attachment rejected: "+err.Error(), http.StatusUnsupportedMediaType)
				return
			}
			if a.Config.Attachments.StripMetadata && strings.HasPrefix(mt, "image/") {
				stripped, newMT, serr := StripImageMetadata(data)
				if serr != nil {
					http.Error(w, "image strip failed", http.StatusBadRequest)
					return
				}
				data, mt = stripped, newMT
			}
			atts = append(atts, Attachment{OriginalName: fh.Filename, MIME: mt, Data: data})
		}
	}

	// Generate code first so it can travel inside the envelope.
	code, err := GenerateCode()
	if err != nil {
		http.Error(w, "code error", http.StatusInternalServerError)
		return
	}
	salt, err := NewSalt()
	if err != nil {
		http.Error(w, "salt error", http.StatusInternalServerError)
		return
	}
	hash := HashCode(code, salt)

	// Pack + encrypt.
	env := SubmissionEnvelope{
		Code:        code,
		Fields:      values,
		Attachments: atts,
		ReceivedAt:  time.Now(),
	}
	tarBlob, err := PackSubmission(env)
	if err != nil {
		http.Error(w, "pack error", http.StatusInternalServerError)
		return
	}
	ciphertext, err := EncryptToReceiver(a.Config.Receiver.PublicKey, tarBlob)
	if err != nil {
		http.Error(w, "encrypt error", http.StatusInternalServerError)
		return
	}

	ttl := time.Duration(a.Config.Retention.DefaultTTLDays) * 24 * time.Hour
	if ttl <= 0 {
		ttl = 90 * 24 * time.Hour
	}
	if _, err := a.Store.CreateCase(hash, salt, ttl, ciphertext); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}

	a.renderPublic(w, "done", code, "")
}

// ─── public reply (visitor) ─────────────────────────────────

func (a *App) handleReply(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.renderPublic(w, "reply", nil, "")
	case http.MethodPost:
		deadline := time.Now().Add(1500 * time.Millisecond)
		defer func() { FixedWaitUntil(deadline) }()

		code := strings.TrimSpace(r.FormValue("code"))
		if code == "" {
			http.Error(w, "code required", http.StatusBadRequest)
			return
		}
		id, err := a.Store.FindCaseByCode(code)
		if err != nil {
			a.renderPublic(w, "reply", replyView{Status: "no-match"}, "")
			return
		}
		// Read reply blob (if any) and decrypt with HKDF(code).
		view := replyView{Status: "verified", CaseID: id}
		rb, rerr := a.Store.ReadReply(id)
		if rerr == nil {
			c, derr := a.GetCase(id)
			if derr == nil {
				key, kerr := HKDFKey([]byte(code), []byte(c.ID), HKDFReplyKey, 32)
				if kerr == nil {
					plaintext, derr2 := DecryptSymmetric(key, rb)
					zero(key)
					if derr2 == nil {
						view.ReplyText = string(plaintext)
						view.Status = "has-reply"
					}
				}
			}
		}
		a.renderPublic(w, "reply", view, "")
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

type replyView struct {
	Status    string
	CaseID    string
	ReplyText string
}

// GetCase exposes the store's case lookup so handlers/template can read it.
func (a *App) GetCase(id string) (*Case, error) { return a.Store.GetCase(id) }

// ─── admin auth ─────────────────────────────────────────────

func (a *App) handleAdminRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/admin" {
		http.NotFound(w, r)
		return
	}
	if sess := a.Sessions.Touch(readSessionCookie(r)); sess != nil {
		http.Redirect(w, r, "/admin/inbox", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

func (a *App) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.renderPublic(w, "admin_login", nil, "")
	case http.MethodPost:
		deadline := time.Now().Add(2 * time.Second)
		defer func() { FixedWaitUntil(deadline) }()

		pw := r.FormValue("password")
		code := r.FormValue("totp")
		if pw == "" || code == "" {
			a.renderPublic(w, "admin_login", "認証に失敗しました。", "")
			return
		}
		// Duress TOTP — wipe everything and pretend to fail.
		if a.Secrets.TOTPSecretDuress != "" && totp.Validate(code, a.Secrets.TOTPSecretDuress) {
			_ = a.Store.Wipe()
			a.renderPublic(w, "admin_login", "認証に失敗しました。", "")
			return
		}
		if !a.Secrets.CheckAdminPassword(pw) || !totp.Validate(code, a.Secrets.TOTPSecret) {
			a.renderPublic(w, "admin_login", "認証に失敗しました。", "")
			return
		}
		sess, err := a.Sessions.New()
		if err != nil {
			http.Error(w, "session error", http.StatusInternalServerError)
			return
		}
		setSessionCookie(w, r, sess.Token)
		http.Redirect(w, r, "/admin/inbox", http.StatusSeeOther)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *App) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := a.Sessions.Touch(readSessionCookie(r))
		if sess == nil {
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}
		// CSRF check on state-changing methods.
		if r.Method == http.MethodPost || r.Method == http.MethodDelete {
			if !a.Sessions.VerifyCSRF(sess.Token, r.FormValue(CSRFFormField)) {
				http.Error(w, "CSRF token invalid", http.StatusForbidden)
				return
			}
		}
		next(w, r)
	}
}

func (a *App) handleAdminLogout(w http.ResponseWriter, r *http.Request) {
	if tok := readSessionCookie(r); tok != "" {
		a.Sessions.Destroy(tok)
	}
	clearSessionCookie(w, r)
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

type inboxView struct {
	Cases []inboxItem
}
type inboxItem struct {
	ID        string
	CreatedAt time.Time
	Bucket    string
	Read      bool
	HasReply  bool
}

func (a *App) handleAdminInbox(w http.ResponseWriter, r *http.Request) {
	cases, err := a.Store.ListCases()
	if err != nil {
		http.Error(w, "list error", http.StatusInternalServerError)
		return
	}
	items := make([]inboxItem, 0, len(cases))
	for _, c := range cases {
		items = append(items, inboxItem{
			ID: c.ID, CreatedAt: c.CreatedAt, Bucket: SizeBucket(c.Size),
			Read: c.Read, HasReply: c.HasReply,
		})
	}
	a.render(w, r, "admin_inbox", inboxView{Cases: items})
}

type caseView struct {
	ID       string
	Created  time.Time
	Expires  time.Time
	Bucket   string
	HasReply bool
}

func (a *App) handleAdminCase(w http.ResponseWriter, r *http.Request) {
	id := path.Base(strings.TrimPrefix(r.URL.Path, "/admin/case/"))
	if !validCaseID(id) {
		http.NotFound(w, r)
		return
	}
	c, err := a.Store.GetCase(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	a.render(w, r, "admin_case", caseView{
		ID: c.ID, Created: c.CreatedAt, Expires: c.ExpiresAt,
		Bucket: SizeBucket(c.Size), HasReply: c.HasReply,
	})
}

func (a *App) handleAdminDownload(w http.ResponseWriter, r *http.Request) {
	id := path.Base(strings.TrimPrefix(r.URL.Path, "/admin/download/"))
	if !validCaseID(id) {
		http.NotFound(w, r)
		return
	}
	blob, err := a.Store.ReadBlob(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	_ = a.Store.MarkRead(id)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.tar.age.kkk"`, id))
	_, _ = w.Write(blob)
}

// /admin/reply/<id> — receiver enters case code + reply text. Server derives
// HKDF(code, case_id) → ChaCha20-Poly1305, persists reply.bin.
type replyAdminView struct {
	ID       string
	Status   string
	HasReply bool
}

func (a *App) handleAdminReply(w http.ResponseWriter, r *http.Request) {
	id := path.Base(strings.TrimPrefix(r.URL.Path, "/admin/reply/"))
	if !validCaseID(id) {
		http.NotFound(w, r)
		return
	}
	c, err := a.Store.GetCase(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		a.render(w, r, "admin_reply", replyAdminView{ID: c.ID, HasReply: c.HasReply})
	case http.MethodPost:
		code := strings.TrimSpace(r.FormValue("case_code"))
		body := strings.TrimSpace(r.FormValue("reply_body"))
		if code == "" || body == "" {
			a.render(w, r, "admin_reply", replyAdminView{ID: c.ID, Status: "コードと本文は必須", HasReply: c.HasReply})
			return
		}
		// Verify code belongs to this case (constant-time-ish via FindCaseByCode).
		matchedID, err := a.Store.FindCaseByCode(code)
		if err != nil || matchedID != c.ID {
			a.render(w, r, "admin_reply", replyAdminView{ID: c.ID, Status: "コードが一致しません", HasReply: c.HasReply})
			return
		}
		key, kerr := HKDFKey([]byte(code), []byte(c.ID), HKDFReplyKey, 32)
		if kerr != nil {
			http.Error(w, "kdf error", http.StatusInternalServerError)
			return
		}
		blob, encErr := EncryptSymmetric(key, []byte(body))
		zero(key)
		if encErr != nil {
			http.Error(w, "encrypt error", http.StatusInternalServerError)
			return
		}
		if err := a.Store.WriteReply(c.ID, blob); err != nil {
			http.Error(w, "write reply error", http.StatusInternalServerError)
			return
		}
		a.render(w, r, "admin_reply", replyAdminView{ID: c.ID, Status: "返信を保存しました。", HasReply: true})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func validCaseID(id string) bool {
	if len(id) != 16 {
		return false
	}
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
