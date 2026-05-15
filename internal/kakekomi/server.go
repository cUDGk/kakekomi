package kakekomi

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Run loads config, opens the store, and serves HTTP until interrupted.
// Phase 1: localhost only, no Tor, no admin auth.
func Run(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	dataDir := fs.String("data-dir", "./data", "data directory")
	addr := fs.String("addr", "127.0.0.1:8080", "listen address (localhost only in Phase 1)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := LoadConfig(*dataDir)
	if err != nil {
		return err
	}
	store, err := OpenStore(*dataDir)
	if err != nil {
		return err
	}
	defer store.Close()

	app := &App{
		Config:    cfg,
		Store:     store,
		Templates: loadTemplates(),
	}

	mux := http.NewServeMux()
	app.Routes(mux)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           withSecurityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       1 * time.Second,
		MaxHeaderBytes:    8 * 1024,
	}
	srv.SetKeepAlivesEnabled(false)

	log.Printf("kakekomi listening on http://%s  (data: %s)", *addr, *dataDir)
	log.Printf("EXPERIMENTAL — NOT YET AUDITED")

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return err
	case <-sigCh:
		log.Println("shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	}
}

// withSecurityHeaders applies the minimal SPEC §3.8 security headers.
func withSecurityHeaders(h http.Handler) http.Handler {
	const csp = "default-src 'none'; img-src 'self'; style-src 'self' 'unsafe-inline'; " +
		"form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h2 := w.Header()
		h2.Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		h2.Set("Pragma", "no-cache")
		h2.Set("Content-Security-Policy", csp)
		h2.Set("X-Content-Type-Options", "nosniff")
		h2.Set("X-Frame-Options", "DENY")
		h2.Set("Referrer-Policy", "no-referrer")
		h2.Set("X-Robots-Tag", "noindex, nofollow, noarchive")
		h2.Set("Connection", "close")
		h.ServeHTTP(w, r)
	})
}
