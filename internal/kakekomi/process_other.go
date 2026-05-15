//go:build !linux

package kakekomi

// hardenProcess is a no-op on non-Linux platforms. Hardening on Windows/macOS
// relies on caller-side facilities (Job Objects / ulimit / `launchctl`).
func hardenProcess() {}
