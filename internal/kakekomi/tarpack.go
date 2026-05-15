package kakekomi

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// SubmissionEnvelope is the in-tar layout for one received case.
//
//	meta.json
//	attachments/001-<safe-name>.<ext>
//	attachments/002-<safe-name>.<ext>
//	...
//
// The whole tar is then wrapped in an age envelope.
type SubmissionEnvelope struct {
	Code        string // BIP39 case code — needed by receiver to encrypt replies
	Fields      map[string]string
	Attachments []Attachment
	ReceivedAt  time.Time
}

type Attachment struct {
	OriginalName string
	MIME         string
	Data         []byte
}

type meta struct {
	Version    int               `json:"version"`
	Code       string            `json:"code"` // for receiver→submitter reply encryption
	Fields     map[string]string `json:"fields"`
	Files      []metaFile        `json:"files"`
	ReceivedAt int64             `json:"received_at_rounded_hour"`
}

type metaFile struct {
	Index        int    `json:"index"`
	OriginalName string `json:"original_name"`
	MIME         string `json:"mime"`
	Bytes        int    `json:"bytes"`
}

// PackSubmission writes a tar archive containing meta.json + attachments/.
// Tar mtimes are zeroed so created times don't leak.
// Tar is then padded with random bytes to the next 64 KiB boundary (envelope
// of padding) so encrypted size buckets cleanly.
func PackSubmission(s SubmissionEnvelope) ([]byte, error) {
	m := meta{
		Version:    1,
		Code:       s.Code,
		Fields:     s.Fields,
		ReceivedAt: s.ReceivedAt.UTC().Truncate(time.Hour).Unix(),
	}
	files := []tarFile{}
	for i, a := range s.Attachments {
		idx := i + 1
		name := fmt.Sprintf("%03d-%s", idx, safeFilename(a.OriginalName, a.MIME))
		m.Files = append(m.Files, metaFile{Index: idx, OriginalName: a.OriginalName, MIME: a.MIME, Bytes: len(a.Data)})
		files = append(files, tarFile{Name: "attachments/" + name, Data: a.Data})
	}
	metaJSON, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	files = append([]tarFile{{Name: "meta.json", Data: metaJSON}}, files...)

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range files {
		hdr := &tar.Header{
			Name:    f.Name,
			Mode:    0600,
			Size:    int64(len(f.Data)),
			ModTime: time.Unix(0, 0).UTC(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(f.Data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}

	// PKCS#7-style block padding to 64 KiB boundary.
	const blockSize = 64 * 1024
	rem := blockSize - (buf.Len() % blockSize)
	padding := make([]byte, rem)
	// Fill with the rem-as-byte to emulate PKCS#7; the value isn't security-
	// relevant since the tar header has Size and unpack reads only Size bytes.
	for i := range padding {
		padding[i] = byte(rem & 0xff)
	}
	buf.Write(padding)
	return buf.Bytes(), nil
}

type tarFile struct {
	Name string
	Data []byte
}

func safeFilename(orig, mime string) string {
	// Strip directory parts, control bytes, non-ASCII; pin extension by MIME.
	clean := make([]byte, 0, len(orig))
	for i := 0; i < len(orig); i++ {
		c := orig[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '-' {
			clean = append(clean, c)
		} else if c == '.' && i < len(orig)-4 {
			// Drop original extension entirely; we re-append a MIME-canonical one.
			break
		}
	}
	if len(clean) == 0 {
		clean = []byte("file")
	}
	if len(clean) > 60 {
		clean = clean[:60]
	}
	return string(clean) + extForMIME(mime)
}

func extForMIME(m string) string {
	switch m {
	case "image/jpeg":
		return ".jpg"
	case "image/png":
		return ".png"
	case "image/gif":
		return ".gif"
	case "image/webp":
		return ".webp"
	case "text/plain":
		return ".txt"
	}
	return ".bin"
}
