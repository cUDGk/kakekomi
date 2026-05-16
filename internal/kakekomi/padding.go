package kakekomi

import (
	"net/http"
	"strings"
	"time"
)

// padToBlock pads a response to the next 4 KiB boundary by appending an HTML
// comment with random-ish filler. SPEC F-51. The pad is appended to the
// already-rendered HTML before flush.
const blockSize = 4096

// PaddedWriter wraps http.ResponseWriter to buffer + pad on close.
type PaddedWriter struct {
	inner http.ResponseWriter
	buf   strings.Builder
	wrote bool
}

func NewPaddedWriter(w http.ResponseWriter) *PaddedWriter {
	return &PaddedWriter{inner: w}
}

func (p *PaddedWriter) Header() http.Header { return p.inner.Header() }

func (p *PaddedWriter) WriteHeader(code int) { p.inner.WriteHeader(code) }

func (p *PaddedWriter) Write(b []byte) (int, error) {
	p.buf.Write(b)
	p.wrote = true
	return len(b), nil
}

// Flush writes the buffered body plus pad. Caller must call this once.
func (p *PaddedWriter) Flush() error {
	body := p.buf.String()
	pad := neededPad(len(body))
	if pad > 0 {
		const prefix = "\n<!-- pad:"
		const suffix = " -->"
		body += prefix
		body += strings.Repeat("x", pad-len(prefix)-len(suffix))
		body += suffix
	}
	_, err := p.inner.Write([]byte(body))
	return err
}

// neededPad returns the bytes to add so the body lands on a blockSize boundary.
// L4 fix: ensure the result is at least 14 bytes so the HTML-comment wrapper
// (10 + 4 = 14 chars) fits without strings.Repeat receiving a negative count.
func neededPad(n int) int {
	r := n % blockSize
	if r == 0 {
		return 0
	}
	p := blockSize - r
	const minPad = 14
	if p < minPad {
		// Overshoot to the next block. Slightly worse padding hygiene but
		// avoids a runtime panic on a degenerate body length.
		p += blockSize
	}
	return p
}

// FixedWaitUntil sleeps until deadline. If now >= deadline, returns immediately.
// Used to normalize response timing (SPEC F-50/F-51).
func FixedWaitUntil(deadline time.Time) {
	if d := time.Until(deadline); d > 0 {
		time.Sleep(d)
	}
}

// SizeBucket returns a coarse human label per SPEC F-53.
func SizeBucket(n int64) string {
	switch {
	case n < 100*1024:
		return "小 (<100KB)"
	case n < 1024*1024:
		return "中 (100KB-1MB)"
	case n < 10*1024*1024:
		return "大 (1-10MB)"
	default:
		return "特大 (>10MB)"
	}
}
