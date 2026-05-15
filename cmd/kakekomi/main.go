// kakekomi: anonymous tipline (EXPERIMENTAL — NOT YET AUDITED).
package main

import (
	"fmt"
	"os"

	"github.com/cUDGk/kakekomi/internal/kakekomi"
)

const version = "0.2.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "init":
		err = kakekomi.Init(args)
	case "run":
		err = kakekomi.Run(args)
	case "gc":
		err = kakekomi.Gc(args)
	case "rotate-key":
		err = kakekomi.RotateKey(args)
	case "config":
		if len(args) > 0 && args[0] == "validate" {
			err = kakekomi.ValidateConfig(args[1:])
		} else {
			fmt.Fprintln(os.Stderr, "usage: kakekomi config validate")
			os.Exit(2)
		}
	case "version", "-v", "--version":
		fmt.Println("kakekomi", version)
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
	fmt.Println(`kakekomi — anonymous tipline (EXPERIMENTAL — NOT YET AUDITED)

Usage:
  kakekomi init [--data-dir DIR] [--enable-tor]
        Generate age key, set passphrase + admin password + TOTP (normal+duress),
        write config + pubkey.lock + secrets.age.

  kakekomi run [--data-dir DIR] [--addr HOST:PORT] [--no-tor]
        Read passphrase from stdin, decrypt secrets, start HTTP server.

  kakekomi gc [--data-dir DIR]
        Remove expired cases (TTL sweep).

  kakekomi rotate-key [--data-dir DIR]
        Generate a new receiver age key pair (old key still required to decrypt
        past submissions; archive it offline).

  kakekomi config validate [--data-dir DIR]
        Parse + semantically validate kakekomi.yaml.

  kakekomi version
  kakekomi help`)
}
