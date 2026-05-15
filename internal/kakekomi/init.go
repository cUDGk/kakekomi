package kakekomi

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Init generates an age key pair, writes the default config, and prints the
// secret key once for the receiver to copy. The secret is NOT persisted.
func Init(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dataDir := fs.String("data-dir", "./data", "data directory")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfgDir := filepath.Join(*dataDir, "config")
	if err := os.MkdirAll(cfgDir, 0700); err != nil {
		return err
	}
	cfgPath := filepath.Join(cfgDir, "kakekomi.yaml")
	if _, err := os.Stat(cfgPath); err == nil {
		return fmt.Errorf("config already exists at %s — refusing to overwrite", cfgPath)
	}

	pub, sec, err := GenerateAgeKey()
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	c := DefaultConfig()
	c.Receiver.PublicKey = pub

	out, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	if err := os.WriteFile(cfgPath, out, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "receiver.pub"), []byte(pub+"\n"), 0644); err != nil {
		return err
	}

	fmt.Println("✓ kakekomi initialized")
	fmt.Println()
	fmt.Println("Data dir   :", *dataDir)
	fmt.Println("Config     :", cfgPath)
	fmt.Println("Public key :", pub)
	fmt.Println()
	fmt.Println("★ 受信者の秘密鍵 (この場で 1 度だけ表示されます。サーバには保存されません):")
	fmt.Println()
	fmt.Println("    " + sec)
	fmt.Println()
	fmt.Println("⚠ この秘密鍵を紛失すると通報を復号できなくなります。")
	fmt.Println("  USB / 暗号化ボリューム等にコピーし、サーバから物理的に持ち出してください。")
	fmt.Println("  バックアップを別ストレージに 1 つ以上取ってください。")
	return nil
}
