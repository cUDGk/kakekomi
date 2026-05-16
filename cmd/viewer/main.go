// kakekomi-viewer: air-gap decryption tool.
//
// Build with `-tags airgap` so the `net` package is excluded by build tags.
// This binary has NO network code and is intended to be run on an offline
// machine (Qubes DispVM / Tails amnesic / disconnected laptop) for opening
// downloaded .tar.age.kkk blobs.
//
// Usage:
//
//	kakekomi-viewer decrypt --identity SECRET_KEY_FILE --in BLOB --out OUTDIR
package main

import (
	"archive/tar"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"filippo.io/age"
)

const version = "0.2.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	var err error
	switch cmd {
	case "decrypt":
		err = decrypt(args)
	case "version", "-v", "--version":
		fmt.Println("kakekomi-viewer", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, cmd+":", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`kakekomi-viewer — air-gap decryption tool

Usage:
  kakekomi-viewer decrypt --identity SECRET_KEY_FILE --in BLOB --out OUTDIR
        Decrypt a kakekomi blob (.tar.age.kkk) using the receiver's age secret,
        extract the tar to OUTDIR/.

  kakekomi-viewer version`)
}

func decrypt(args []string) error {
	fs := flag.NewFlagSet("decrypt", flag.ExitOnError)
	idFile := fs.String("identity", "", "path to age secret key file (one line)")
	inPath := fs.String("in", "", "input blob (.tar.age.kkk)")
	outDir := fs.String("out", "", "output directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *idFile == "" || *inPath == "" || *outDir == "" {
		return errors.New("--identity, --in, --out required")
	}

	idBytes, err := os.ReadFile(*idFile)
	if err != nil {
		return fmt.Errorf("read identity: %w", err)
	}
	id, err := age.ParseX25519Identity(strings.TrimSpace(string(idBytes)))
	if err != nil {
		return fmt.Errorf("parse identity: %w", err)
	}

	blob, err := os.ReadFile(*inPath)
	if err != nil {
		return err
	}
	version, payload, err := unwrapEnvelope(blob)
	if err != nil {
		return err
	}
	if version != 1 {
		return fmt.Errorf("unsupported envelope version %d", version)
	}
	r, err := age.Decrypt(bytes.NewReader(payload), id)
	if err != nil {
		return fmt.Errorf("age decrypt: %w", err)
	}
	tarBytes, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*outDir, 0700); err != nil {
		return err
	}
	return extractTar(tarBytes, *outDir)
}

func unwrapEnvelope(blob []byte) (version uint16, payload []byte, err error) {
	if len(blob) < 8 || string(blob[0:4]) != "KKK1" {
		return 0, nil, errors.New("bad envelope")
	}
	version = binary.BigEndian.Uint16(blob[4:6])
	payload = blob[8:]
	return
}

func extractTar(data []byte, dir string) error {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		// C3 fix: reject anything that smells like an escape:
		//   - absolute paths (Unix-style)
		//   - Windows drive letters or UNC paths
		//   - any segment that is ".."
		//   - control bytes / NUL
		if !safeTarName(h.Name) {
			return fmt.Errorf("refusing unsafe path: %q", h.Name)
		}
		cleaned := filepath.Clean(filepath.FromSlash(h.Name))
		target := filepath.Join(absDir, cleaned)
		// Double-check after Clean+Join that we stayed inside absDir.
		if !strings.HasPrefix(target+string(filepath.Separator), absDir+string(filepath.Separator)) && target != absDir {
			return fmt.Errorf("path escapes output dir: %q", h.Name)
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0700); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
			if h.Name == "meta.json" {
				prettyPrintMeta(target)
			}
		case tar.TypeSymlink, tar.TypeLink:
			// C3 fix: refuse, never materialize. A subsequent regular file write
			// could otherwise follow the symlink and escape outDir.
			return fmt.Errorf("refusing symlink/hardlink in archive: %q", h.Name)
		default:
			return fmt.Errorf("refusing unknown tar entry type %c for %q", h.Typeflag, h.Name)
		}
	}
}

func safeTarName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		if c == 0 || c == '\r' || c == '\n' {
			return false
		}
	}
	// Reject Windows drive letters and UNC.
	if len(name) >= 2 && name[1] == ':' {
		return false
	}
	if strings.HasPrefix(name, `\\`) || strings.HasPrefix(name, "//") {
		return false
	}
	if strings.HasPrefix(name, "/") {
		return false
	}
	// Reject any segment equal to ".." (catches "foo/../bar" too).
	parts := strings.Split(strings.ReplaceAll(name, `\`, `/`), `/`)
	for _, p := range parts {
		if p == ".." {
			return false
		}
	}
	return true
}

func prettyPrintMeta(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var pretty bytes.Buffer
	if json.Indent(&pretty, b, "", "  ") == nil {
		fmt.Println(pretty.String())
	}
}
