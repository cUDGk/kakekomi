package kakekomi

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

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

func configPath(dataDir string) string {
	return filepath.Join(dataDir, "config", "kakekomi.yaml")
}

func LoadConfig(dataDir string) (*Config, error) {
	b, err := os.ReadFile(configPath(dataDir))
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if c.Receiver.PublicKey == "" {
		return nil, errors.New("receiver.public_key is empty (run `kakekomi init` first)")
	}
	if len(c.Fields) == 0 {
		return nil, errors.New("no fields defined in config")
	}
	return &c, nil
}

// DefaultConfig returns the minimal config that `kakekomi init` writes.
// Only `body` is required; everything else is optional.
func DefaultConfig() *Config {
	c := &Config{}
	c.Site.Title = "通報窓口"
	c.Site.Intro = "安全に情報をお寄せください。身元の入力は不要です。"
	c.Retention.DefaultTTLDays = 90
	c.Fields = []Field{
		{
			ID:        "body",
			Label:     "通報内容",
			Type:      "textarea",
			Required:  true,
			MaxLength: 50000,
		},
		{
			ID:        "subject",
			Label:     "件名 (任意)",
			Type:      "text",
			Required:  false,
			MaxLength: 200,
		},
		{
			ID:          "when",
			Label:       "事案の時期 (任意)",
			Type:        "text",
			Required:    false,
			Placeholder: "例: 2025年秋頃",
		},
	}
	return c
}
