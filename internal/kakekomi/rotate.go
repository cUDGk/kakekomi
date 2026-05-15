package kakekomi

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// RotateKey generates a new receiver age key pair. Old blob/<id>/*.tar.age
// remain encrypted to the OLD key and must be decrypted with the old secret
// (which the receiver presumably still holds in offline storage).
//
// We:
//  1. Generate new pub/sec.
//  2. Archive current receiver.pub → receiver-<unix>.pub.archived
//  3. Update config.yaml + receiver.pub + pubkey.lock.
//  4. Print new secret once.
func RotateKey(args []string) error {
	fs := flag.NewFlagSet("rotate-key", flag.ExitOnError)
	dataDir := fs.String("data-dir", "./data", "data directory")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := LoadConfig(*dataDir)
	if err != nil {
		return err
	}

	newPub, newSec, err := GenerateAgeKey()
	if err != nil {
		return err
	}

	// Archive old pubkey for forensic record.
	oldPubPath := filepath.Join(*dataDir, "config", "receiver.pub")
	if old, err := os.ReadFile(oldPubPath); err == nil {
		archivePath := filepath.Join(*dataDir, "config",
			fmt.Sprintf("receiver-%d.pub.archived", time.Now().Unix()))
		_ = os.WriteFile(archivePath, old, 0600)
	}

	cfg.Receiver.PublicKey = newPub
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := os.WriteFile(configPath(*dataDir), out, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(oldPubPath, []byte(newPub+"\n"), 0644); err != nil {
		return err
	}
	if err := writePubkeyLock(*dataDir, newPub); err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "✓ key rotated")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "New receiver pubkey:", newPub)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "★ NEW age secret (display once, then wipe from terminal):")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "    "+newSec)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "⚠ The OLD secret is still required to decrypt past submissions.")
	fmt.Fprintln(os.Stderr, "  Keep it in archived offline storage.")
	return nil
}
