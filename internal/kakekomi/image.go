package kakekomi

import (
	"bytes"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"

	// register decoders for sniff/auto-detect
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"

	"golang.org/x/image/webp" // pure-Go WEBP decoder
)

// StripImageMetadata decodes an image and re-encodes it. This drops EXIF/XMP/
// ICC and most camera-side metadata. It does NOT fully neutralize PRNU sensor
// noise (which is in the pixel data itself) but a fresh encode does perturb
// pixel-level statistics enough to defeat naive identification.
//
// Output MIME: same family as input where possible (jpeg→jpeg, png→png, gif→gif,
// webp→png — pure-Go has no webp encoder).
func StripImageMetadata(input []byte) (out []byte, outMIME string, err error) {
	mt := SniffMIME(input)
	switch mt {
	case "image/jpeg":
		img, err := jpeg.Decode(bytes.NewReader(input))
		if err != nil {
			return nil, "", err
		}
		var buf bytes.Buffer
		if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 90}); err != nil {
			return nil, "", err
		}
		return buf.Bytes(), "image/jpeg", nil

	case "image/png":
		img, err := png.Decode(bytes.NewReader(input))
		if err != nil {
			return nil, "", err
		}
		var buf bytes.Buffer
		enc := png.Encoder{CompressionLevel: png.DefaultCompression}
		if err := enc.Encode(&buf, img); err != nil {
			return nil, "", err
		}
		return buf.Bytes(), "image/png", nil

	case "image/gif":
		img, err := gif.DecodeAll(bytes.NewReader(input))
		if err != nil {
			return nil, "", err
		}
		var buf bytes.Buffer
		if err := gif.EncodeAll(&buf, img); err != nil {
			return nil, "", err
		}
		return buf.Bytes(), "image/gif", nil

	case "image/webp":
		img, err := webp.Decode(bytes.NewReader(input))
		if err != nil {
			return nil, "", err
		}
		// Re-encode as PNG (no pure-Go webp encoder).
		var buf bytes.Buffer
		if err := png.Encode(&buf, img); err != nil {
			return nil, "", err
		}
		return buf.Bytes(), "image/png", nil

	default:
		// Should not be reached: caller already filtered via VerifyAttachment.
		_ = image.Black
		return input, mt, nil
	}
}
