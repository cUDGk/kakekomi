package kakekomi

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/pquerna/otp/totp"
	"gopkg.in/yaml.v3"
)

// Init creates the data dir, generates the receiver age key pair, derives a
// passphrase-protected master_key, sets up TOTP (normal + duress), seeds the
// admin password, writes config + pubkey.lock + secrets.age.
//
// Everything sensitive is printed to stderr ONCE — receiver must save it
// (secret age key, TOTP secrets, etc.) and remove from terminal history.
func Init(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dataDir := fs.String("data-dir", "./data", "data directory")
	enableTor := fs.Bool("enable-tor", false, "enable Tor in the generated config")
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

	// 1. Receiver age keypair.
	pub, sec, err := GenerateAgeKey()
	if err != nil {
		return fmt.Errorf("generate age key: %w", err)
	}

	// 2. Passphrase for master_key (secrets.age protection).
	passphrase, err := promptPassphrase()
	if err != nil {
		return err
	}

	// 3. Admin password (for /admin login).
	adminPassword, err := promptOnce("Admin (receiver) login password: ")
	if err != nil {
		return err
	}
	if len(adminPassword) < 12 {
		return errors.New("admin password must be at least 12 chars")
	}

	// 4. TOTP normal + duress.
	totpKey, err := totp.Generate(totp.GenerateOpts{Issuer: "kakekomi", AccountName: "receiver"})
	if err != nil {
		return err
	}
	totpDuressKey, err := totp.Generate(totp.GenerateOpts{Issuer: "kakekomi", AccountName: "receiver (duress)"})
	if err != nil {
		return err
	}

	// 5. Secrets struct.
	secrets, err := NewSecrets()
	if err != nil {
		return err
	}
	secrets.TOTPSecret = totpKey.Secret()
	secrets.TOTPSecretDuress = totpDuressKey.Secret()
	secrets.SetAdminPassword(adminPassword)
	zero([]byte(adminPassword))

	// 6. Persist config, pubkey.lock, secrets.age.
	c := DefaultConfig()
	c.Receiver.PublicKey = pub
	c.Tor.Enabled = *enableTor
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
	if err := writePubkeyLock(*dataDir, pub); err != nil {
		return err
	}
	if err := SaveSecrets(*dataDir, passphrase, secrets); err != nil {
		return err
	}
	zero([]byte(passphrase))

	// 7. One-time disclosure to receiver.
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "✓ kakekomi initialized")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Data dir       :", *dataDir)
	fmt.Fprintln(os.Stderr, "Config         :", cfgPath)
	fmt.Fprintln(os.Stderr, "Receiver pubkey:", pub)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "★ 受信者の age 秘密鍵 (この場で 1 度だけ表示。サーバには保存されません):")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "    "+sec)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "★ TOTP (通常ログイン用) — 認証アプリに登録してください:")
	fmt.Fprintln(os.Stderr, "    Secret:", totpKey.Secret())
	fmt.Fprintln(os.Stderr, "    URL   :", totpKey.URL())
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "★ TOTP (Duress=強制開示用) — 別の認証アプリ枠 / 別の機器に登録してください:")
	fmt.Fprintln(os.Stderr, "    強制された時にこちらの TOTP でログインすると、")
	fmt.Fprintln(os.Stderr, "    全通報を即時 shred 削除して認証失敗を装います。")
	fmt.Fprintln(os.Stderr, "    Secret:", totpDuressKey.Secret())
	fmt.Fprintln(os.Stderr, "    URL   :", totpDuressKey.URL())
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "⚠ age 秘密鍵を紛失すると通報を復号できません。")
	fmt.Fprintln(os.Stderr, "⚠ パスフレーズを紛失すると secrets.age を復号できません = ダッシュボードに入れません。")
	fmt.Fprintln(os.Stderr, "⚠ 上の出力は履歴/スクロールバックから即時消去してください。")
	return nil
}

func promptPassphrase() (string, error) {
	for {
		p1, err := promptOnce("Receiver passphrase (12+ chars): ")
		if err != nil {
			return "", err
		}
		if len(p1) < 12 {
			fmt.Fprintln(os.Stderr, "  too short, try again")
			continue
		}
		p2, err := promptOnce("Confirm passphrase: ")
		if err != nil {
			return "", err
		}
		if p1 != p2 {
			fmt.Fprintln(os.Stderr, "  mismatch, try again")
			continue
		}
		return p1, nil
	}
}

var (
	stdinOnce sync.Once
	stdinRdr  *bufio.Reader
)

func stdinReader() *bufio.Reader {
	stdinOnce.Do(func() { stdinRdr = bufio.NewReader(os.Stdin) })
	return stdinRdr
}

func promptOnce(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	line, err := stdinReader().ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
