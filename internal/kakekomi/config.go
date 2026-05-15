package kakekomi

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Site struct {
		Title string `yaml:"title"`
		Intro string `yaml:"intro"`
	} `yaml:"site"`

	Receiver struct {
		PublicKey   string `yaml:"public_key"`
		DisplayName string `yaml:"display_name"`
	} `yaml:"receiver"`

	Fields []Field `yaml:"fields"`

	Attachments AttachmentsConfig `yaml:"attachments"`

	Tor TorConfig `yaml:"tor"`

	Security SecurityConfig `yaml:"security"`

	Retention struct {
		DefaultTTLDays int `yaml:"default_ttl_days"`
	} `yaml:"retention"`
}

type Field struct {
	ID          string   `yaml:"id"`
	Label       string   `yaml:"label"`
	Type        string   `yaml:"type"`
	Required    bool     `yaml:"required"`
	MaxLength   int      `yaml:"max_length,omitempty"`
	Placeholder string   `yaml:"placeholder,omitempty"`
	Options     []string `yaml:"options,omitempty"`
}

type AttachmentsConfig struct {
	Enabled          bool     `yaml:"enabled"`
	MaxFiles         int      `yaml:"max_files"`
	MaxSizeMBPerFile int      `yaml:"max_size_mb_per_file"`
	MaxTotalSizeMB   int      `yaml:"max_total_size_mb"`
	AllowedMIME      []string `yaml:"allowed_mime"`
	StripMetadata    bool     `yaml:"strip_metadata"`
}

type TorConfig struct {
	Enabled            bool     `yaml:"enabled"`
	Mode               string   `yaml:"mode"` // "external" | "off"
	ControlAddr        string   `yaml:"control_addr"`
	ControlPassword    string   `yaml:"control_password,omitempty"` // optional; cookie auth preferred
	CookieAuthFile     string   `yaml:"cookie_auth_file,omitempty"`
	IngressOnionAddr   string   `yaml:"ingress_onion_addr,omitempty"` // populated by `init`
	AdminOnionAddr     string   `yaml:"admin_onion_addr,omitempty"`   // populated by `init`
	AdminClientPubKeys []string `yaml:"admin_client_pubkeys,omitempty"`
}

type SecurityConfig struct {
	Profile    string    `yaml:"profile"`
	PoW        PoWConfig `yaml:"pow"`
	Honeypot   bool      `yaml:"honeypot_field"`
	PubkeyLock string    `yaml:"pubkey_lock"`
}

type PoWConfig struct {
	Enabled       bool `yaml:"enabled"`
	HashChainCost int  `yaml:"hash_chain_cost"` // SHA-256 iterations server-side per submit
}

func configPath(dataDir string) string {
	return filepath.Join(dataDir, "config", "kakekomi.yaml")
}

func pubkeyLockPath(dataDir string) string {
	return filepath.Join(dataDir, "config", "pubkey.lock")
}

// LoadConfig reads, validates, and pins-checks the config.
func LoadConfig(dataDir string) (*Config, error) {
	b, err := os.ReadFile(configPath(dataDir))
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := c.semanticValidate(); err != nil {
		return nil, err
	}
	if err := c.verifyPubkeyLock(dataDir); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) semanticValidate() error {
	if c.Receiver.PublicKey == "" {
		return errors.New("receiver.public_key is empty (run `kakekomi init` first)")
	}
	if len(c.Fields) == 0 {
		return errors.New("no fields defined in config")
	}
	if c.Security.Profile != "" && c.Security.Profile != "paranoid" {
		return fmt.Errorf("security.profile %q unsupported in v1 (paranoid only)", c.Security.Profile)
	}
	for _, f := range c.Fields {
		switch f.Type {
		case "", "text", "textarea", "select", "date", "checkbox", "number":
		default:
			return fmt.Errorf("field %q: unsupported type %q", f.ID, f.Type)
		}
	}
	if c.Attachments.Enabled {
		for _, m := range c.Attachments.AllowedMIME {
			if !mimeIsSafe(m) {
				return fmt.Errorf("attachments.allowed_mime: %q is forbidden in v1 (only image/* and text/plain)", m)
			}
		}
	}
	return nil
}

func (c *Config) verifyPubkeyLock(dataDir string) error {
	lockPath := c.Security.PubkeyLock
	if lockPath == "" {
		lockPath = pubkeyLockPath(dataDir)
	}
	want, err := os.ReadFile(lockPath)
	if err != nil {
		if os.IsNotExist(err) {
			// First run after init writes the lock; tolerate via init flow only.
			return fmt.Errorf("pubkey.lock missing at %s — re-run `kakekomi init` or restore", lockPath)
		}
		return fmt.Errorf("read pubkey.lock: %w", err)
	}
	got := sha256.Sum256([]byte(c.Receiver.PublicKey))
	if strings.TrimSpace(string(want)) != hex.EncodeToString(got[:]) {
		return errors.New("pubkey.lock mismatch — config.receiver.public_key was changed; possible tampering")
	}
	return nil
}

func writePubkeyLock(dataDir, publicKey string) error {
	sum := sha256.Sum256([]byte(publicKey))
	return os.WriteFile(pubkeyLockPath(dataDir), []byte(hex.EncodeToString(sum[:])+"\n"), 0600)
}

// DefaultConfig returns the secure default written by `kakekomi init`.
func DefaultConfig() *Config {
	c := &Config{}
	c.Site.Title = "通報窓口"
	c.Site.Intro = "安全に情報をお寄せください。身元の入力は不要です。"
	c.Retention.DefaultTTLDays = 90
	c.Fields = []Field{
		{ID: "body", Label: "通報内容", Type: "textarea", Required: true, MaxLength: 50000},
		{ID: "subject", Label: "件名 (任意)", Type: "text", Required: false, MaxLength: 200},
		{ID: "when", Label: "事案の時期 (任意)", Type: "text", Required: false, Placeholder: "例: 2025年秋頃"},
	}
	c.Attachments = AttachmentsConfig{
		Enabled:          true,
		MaxFiles:         10,
		MaxSizeMBPerFile: 50,
		MaxTotalSizeMB:   200,
		AllowedMIME: []string{
			"image/jpeg", "image/png", "image/webp", "image/gif",
			"text/plain",
		},
		StripMetadata: true,
	}
	c.Tor = TorConfig{
		Enabled:     false, // off by default; `init --enable-tor` flips it
		Mode:        "external",
		ControlAddr: "127.0.0.1:9051",
	}
	c.Security = SecurityConfig{
		Profile: "paranoid",
		PoW: PoWConfig{
			Enabled:       true,
			HashChainCost: 1 << 16, // ~65k SHA-256 iterations
		},
		Honeypot:   true,
		PubkeyLock: "", // resolved to <data-dir>/config/pubkey.lock by default
	}
	return c
}
