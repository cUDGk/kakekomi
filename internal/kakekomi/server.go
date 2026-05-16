package kakekomi

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Run loads config + secrets (after passphrase prompt) and serves HTTP until
// interrupted. Optionally registers a Tor v3 hidden service via tor control.
func Run(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	dataDir := fs.String("data-dir", "./data", "data directory")
	addr := fs.String("addr", "127.0.0.1:8080", "listen address")
	noTor := fs.Bool("no-tor", false, "force disable Tor even if config.tor.enabled=true")
	if err := fs.Parse(args); err != nil {
		return err
	}

	hardenProcess()

	// Disable Go's default HTTP transport — kakekomi never makes outbound HTTP.
	http.DefaultTransport = nil
	http.DefaultClient.Transport = nil

	// 1. Load config (verifies pubkey.lock).
	cfg, err := LoadConfig(*dataDir)
	if err != nil {
		return err
	}

	// 2. Prompt for passphrase; derive master_key; decrypt secrets.age.
	passphrase, err := readPassphrase("Receiver passphrase: ")
	if err != nil {
		return err
	}
	secrets, err := LoadSecrets(*dataDir, passphrase)
	zero([]byte(passphrase))
	if err != nil {
		return err
	}

	// 3. Open store.
	store, err := OpenStore(*dataDir)
	if err != nil {
		return err
	}
	defer store.Close()

	// 4. Startup GC + periodic sweep.
	if n, err := store.GC(); err != nil {
		log.Printf("startup gc: %v", err)
	} else if n > 0 {
		log.Printf("startup gc: removed %d expired case(s)", n)
	}
	gcCtx, gcCancel := context.WithCancel(context.Background())
	defer gcCancel()
	go runGCLoop(gcCtx, store, 1*time.Hour)

	// 5. App + routes.
	app := &App{
		Config:    cfg,
		Store:     store,
		Secrets:   secrets,
		Sessions:  NewSessionStore(secrets.CSRFKey),
		Templates: loadTemplates(),
	}
	mux := http.NewServeMux()
	app.Routes(mux)

	srv := &http.Server{
		Addr:              *addr,
		Handler:           withSecurityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       60 * time.Second, // attachments may take time over Tor
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       1 * time.Second,
		MaxHeaderBytes:    8 * 1024,
		// HTTP/2 disabled (HARDENING §L3.7).
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	srv.SetKeepAlivesEnabled(false)

	// 6. Tor (optional).
	var torTearDown func()
	if cfg.Tor.Enabled && !*noTor {
		td, err := setupTor(cfg, *dataDir, *addr)
		if err != nil {
			log.Printf("tor setup failed: %v (continuing without Tor)", err)
		} else {
			torTearDown = td
			log.Printf("Tor ingress: %s.onion", cfg.Tor.IngressOnionAddr)
			if cfg.Tor.AdminOnionAddr != "" {
				log.Printf("Tor admin   : %s.onion (Client Auth required)", cfg.Tor.AdminOnionAddr)
			}
		}
	}
	if torTearDown != nil {
		defer torTearDown()
	}

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

// setupTor connects to a running tor's control port and registers an onion
// pointing at our local addr. Returns a function to tear down the onion(s).
func setupTor(cfg *Config, dataDir, localAddr string) (func(), error) {
	tc, err := DialTorControl(cfg.Tor.ControlAddr)
	if err != nil {
		return nil, err
	}
	if err := tc.AuthenticateAuto(cfg.Tor.CookieAuthFile, cfg.Tor.ControlPassword); err != nil {
		tc.Close()
		return nil, fmt.Errorf("tor auth: %w", err)
	}

	keyPath := filepath.Join(dataDir, "tor", "ingress.key")
	_ = os.MkdirAll(filepath.Dir(keyPath), 0700)
	priv, _ := os.ReadFile(keyPath)

	var serviceID string
	if len(priv) > 0 {
		serviceID, err = tc.AddOnionExistingKey(strings.TrimSpace(string(priv)), localAddr, nil)
		if err != nil {
			tc.Close()
			return nil, err
		}
	} else {
		var newKey string
		serviceID, newKey, err = tc.AddOnionV3(localAddr, nil)
		if err != nil {
			tc.Close()
			return nil, err
		}
		if err := os.WriteFile(keyPath, []byte(newKey), 0600); err != nil {
			tc.Close()
			return nil, err
		}
	}
	cfg.Tor.IngressOnionAddr = serviceID
	// Persist back to config so the receiver can share the .onion.
	_ = persistOnionAddrs(dataDir, cfg)

	return func() {
		_ = tc.DelOnion(serviceID)
		_ = tc.Close()
	}, nil
}

func persistOnionAddrs(dataDir string, cfg *Config) error {
	p := filepath.Join(dataDir, "tor", "addresses.txt")
	body := fmt.Sprintf("ingress: %s.onion\nadmin: %s.onion\n",
		cfg.Tor.IngressOnionAddr, cfg.Tor.AdminOnionAddr)
	return os.WriteFile(p, []byte(body), 0644)
}

// readPassphrase reads a single line from stdin.
// (Echo suppression skipped to avoid an extra dep; over Tor / SSH the operator
// must use the systemd-creds path or pipe stdin from an encrypted file.)
func readPassphrase(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	line, err := stdinReader().ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// withSecurityHeaders applies SPEC §3.8 + HARDENING §L4.1 headers.
func withSecurityHeaders(h http.Handler) http.Handler {
	const csp = "default-src 'none'; img-src 'self'; style-src 'self'; " +
		"form-action 'self'; frame-ancestors 'none'; base-uri 'none'; " +
		"require-trusted-types-for 'script'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h2 := w.Header()
		h2.Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		h2.Set("Pragma", "no-cache")
		h2.Set("Expires", "0")
		h2.Set("Content-Security-Policy", csp)
		h2.Set("X-Content-Type-Options", "nosniff")
		h2.Set("X-Frame-Options", "DENY")
		h2.Set("Referrer-Policy", "no-referrer")
		h2.Set("Permissions-Policy",
			"interest-cohort=(), camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=()")
		h2.Set("Cross-Origin-Opener-Policy", "same-origin")
		h2.Set("Cross-Origin-Resource-Policy", "same-origin")
		h2.Set("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet")
		h2.Set("Connection", "close")
		// `Server` header is not set by net/http by default.
		h.ServeHTTP(w, r)
	})
}
