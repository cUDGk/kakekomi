package kakekomi

import (
	"bytes"
	"errors"
	"net/http"
	"strings"
)

// safeMIMEs are the only MIME types accepted in v1. PDF/Office/SVG/video/audio
// are rejected wholesale because their metadata-removal is non-trivial.
//
// HEIC was previously listed but is now rejected: pure-Go decoders do not
// exist, and accepting HEIC without re-encoding would pass camera-side metadata
// through unchanged. iPhone users should convert to JPEG/PNG before uploading.
var safeMIMEs = map[string]bool{
	"image/jpeg": true,
	"image/png":  true,
	"image/webp": true,
	"image/gif":  true,
	"text/plain": true,
}

func mimeIsSafe(m string) bool { return safeMIMEs[m] }

// SniffMIME detects MIME from the first 512 bytes (HTTP magic-byte heuristic).
// Refuses to trust the client-provided Content-Type — F-75.
func SniffMIME(data []byte) string {
	if len(data) > 512 {
		data = data[:512]
	}
	return strings.ToLower(strings.SplitN(http.DetectContentType(data), ";", 2)[0])
}

// VerifyAttachment checks both magic-byte MIME and against the allow-list.
func VerifyAttachment(data []byte, allowed []string) (string, error) {
	mt := SniffMIME(data)
	if !mimeIsSafe(mt) {
		return mt, errAttachmentUnsupported
	}
	if !contains(allowed, mt) && len(allowed) > 0 {
		return mt, errAttachmentDisallowed
	}
	// Extra: text/plain must actually be UTF-8 text (avoid binary smuggled in).
	if mt == "text/plain" && !looksLikeText(data) {
		return mt, errAttachmentNotPlainText
	}
	return mt, nil
}

var (
	errAttachmentUnsupported  = errors.New("attachment MIME unsupported (only image/* and text/plain)")
	errAttachmentDisallowed   = errors.New("attachment MIME not in config allowed list")
	errAttachmentNotPlainText = errors.New("attachment claims text/plain but contains binary bytes")
)

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// looksLikeText: at most 1% NUL bytes in the buffer.
func looksLikeText(b []byte) bool {
	if bytes.Contains(b, []byte{0xFF, 0xFE}) || bytes.Contains(b, []byte{0xFE, 0xFF}) {
		// UTF-16 BOM — refuse, we only want UTF-8 text/plain
		return false
	}
	nul := 0
	for _, c := range b {
		if c == 0 {
			nul++
		}
	}
	return float64(nul)/float64(len(b)+1) < 0.01
}
