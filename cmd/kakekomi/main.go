// kakekomi: anonymous tipline (EXPERIMENTAL — NOT YET AUDITED).
package main

import (
	"fmt"
	"os"

	"github.com/cUDGk/kakekomi/internal/kakekomi"
)

const version = "0.1.0"

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
  kakekomi init [--data-dir DIR]
        Generate age key pair and write default config.

  kakekomi run [--data-dir DIR] [--addr HOST:PORT]
        Start HTTP server (Phase 1: localhost only, no Tor).

  kakekomi version
  kakekomi help`)
}
