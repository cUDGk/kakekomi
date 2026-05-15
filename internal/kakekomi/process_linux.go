//go:build linux

package kakekomi

import (
	"log"

	"golang.org/x/sys/unix"
)

func hardenProcess() {
	// Disable core dumps (also blocks ptrace by side effect).
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		log.Printf("prctl(PR_SET_DUMPABLE,0): %v", err)
	}
	// Disable new privileges (defense-in-depth even if systemd unit also sets it).
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		log.Printf("prctl(PR_SET_NO_NEW_PRIVS,1): %v", err)
	}
}
