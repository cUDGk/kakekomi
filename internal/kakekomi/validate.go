package kakekomi

import (
	"flag"
	"fmt"
)

func ValidateConfig(args []string) error {
	fs := flag.NewFlagSet("config validate", flag.ExitOnError)
	dataDir := fs.String("data-dir", "./data", "data directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := LoadConfig(*dataDir)
	if err != nil {
		return err
	}
	fmt.Println("✓ config OK")
	fmt.Println("  profile      :", cfg.Security.Profile)
	fmt.Println("  fields       :", len(cfg.Fields))
	fmt.Println("  attachments  :", cfg.Attachments.Enabled, "(allowed:", cfg.Attachments.AllowedMIME, ")")
	fmt.Println("  tor.enabled  :", cfg.Tor.Enabled)
	fmt.Println("  retention.ttl:", cfg.Retention.DefaultTTLDays, "days")
	return nil
}
