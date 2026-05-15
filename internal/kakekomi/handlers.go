package kakekomi

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"path"
	"strings"
	"time"
)

type App struct {
	Config    *Config
	Store     *Store
	Templates map[string]*template.Template
}

func (a *App) Routes(mux *http.ServeMux) {
	mux.HandleFunc("/", a.handleIndex)
	mux.HandleFunc("/submit", a.handleSubmit)
	mux.HandleFunc("/reply", a.handleReply)
	mux.HandleFunc("/admin", a.handleAdminInbox)
	mux.HandleFunc("/admin/case/", a.handleAdminCase)
}

type pageData struct {
	SiteTitle string
	SiteIntro string
	Data      any
}

func (a *App) render(w http.ResponseWriter, name string, data any) {
	t, ok := a.Templates[name]
	if !ok {
		http.Error(w, "template not found: "+name, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	pd := pageData{
		SiteTitle: a.Config.Site.Title,
		SiteIntro: a.Config.Site.Intro,
		Data:      data,
	}
	if err := t.ExecuteTemplate(w, "layout", pd); err != nil {
		// Headers may already be written; just log on the server side in real impl.
		http.Error(w, "render error", http.StatusInternalServerError)
	}
}

// ─── public side ─────────────────────────────────────────────

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	a.render(w, "index", nil)
}

func (a *App) handleSubmit(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.render(w, "submit", a.Config.Fields)
	case http.MethodPost:
		a.processSubmit(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *App) processSubmit(w http.ResponseWriter, r *http.Request) {
	// Phase 1: text only, 1 MiB body cap.
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

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

	plaintext, err := json.MarshalIndent(values, "", "  ")
	if err != nil {
		http.Error(w, "encode error", http.StatusInternalServerError)
		return
	}
	blob, err := Encrypt(a.Config.Receiver.PublicKey, plaintext)
	if err != nil {
		http.Error(w, "encrypt error", http.StatusInternalServerError)
		return
	}

	id, err := NewID()
	if err != nil {
		http.Error(w, "id error", http.StatusInternalServerError)
		return
	}
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

	ttl := time.Duration(a.Config.Retention.DefaultTTLDays) * 24 * time.Hour
	if ttl <= 0 {
		ttl = 90 * 24 * time.Hour
	}
	if err := a.Store.CreateCase(id, hash, salt, ttl, blob); err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}

	a.render(w, "done", code)
}

func (a *App) handleReply(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.render(w, "reply", nil)
	case http.MethodPost:
		code := strings.TrimSpace(r.FormValue("code"))
		if code == "" {
			http.Error(w, "code required", http.StatusBadRequest)
			return
		}
		// Constant minimum wait to blunt timing oracles (Phase 1 placeholder).
		start := time.Now()
		_, err := a.Store.FindCaseByCode(code)
		const minWait = 500 * time.Millisecond
		if elapsed := time.Since(start); elapsed < minWait {
			time.Sleep(minWait - elapsed)
		}
		if err != nil {
			a.render(w, "reply", "コードが一致しません。")
			return
		}
		a.render(w, "reply", "コードを確認しました。(Phase 5 で返信表示を実装予定)")
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ─── receiver side (localhost-only in Phase 1) ──────────────

func (a *App) handleAdminInbox(w http.ResponseWriter, r *http.Request) {
	if !isLocalhost(r) {
		http.Error(w, "admin is localhost-only in Phase 1", http.StatusForbidden)
		return
	}
	cases, err := a.Store.ListCases()
	if err != nil {
		http.Error(w, "list error", http.StatusInternalServerError)
		return
	}
	a.render(w, "admin_inbox", cases)
}

func (a *App) handleAdminCase(w http.ResponseWriter, r *http.Request) {
	if !isLocalhost(r) {
		http.Error(w, "admin is localhost-only in Phase 1", http.StatusForbidden)
		return
	}
	id := path.Base(strings.TrimPrefix(r.URL.Path, "/admin/case/"))
	if id == "" || id == "." || id == "/" {
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
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.age"`, id))
	_, _ = w.Write(blob)
}

func isLocalhost(r *http.Request) bool {
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	host = strings.Trim(host, "[]")
	switch host {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return false
}
