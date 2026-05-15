package kakekomi

// hardenProcess applies per-OS hardening: disable core dumps, ptrace, etc.
// Best-effort; failures are logged but not fatal.
//
// Implementation lives in process_linux.go / process_other.go.
