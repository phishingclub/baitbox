package service

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"net/http"

	// register the decoders image.DecodeConfig uses to read dimensions.
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
)

// MaxPreviewBytes caps one preview image. Previews are loaded by every
// Phishing Club install that browses the Library, so they stay small.
const MaxPreviewBytes = 2 << 20

// MaxPreviewSide caps the width and height of a preview image in pixels, so a
// small file cannot unpack into a huge image when it is drawn.
const MaxPreviewSide = 4096

// ErrPreviewImage is wrapped by every preview image rejection.
var ErrPreviewImage = errors.New("invalid preview image")

// checkPreviewImage reads the real type from the bytes, requires a raster type
// we allow, and enforces the byte and pixel limits. It returns the detected
// media type, which is what gets stored and served.
func checkPreviewImage(data []byte) (string, error) {
	if len(data) > MaxPreviewBytes {
		return "", fmt.Errorf("%w: larger than %d MB", ErrPreviewImage, MaxPreviewBytes>>20)
	}
	mediaType := http.DetectContentType(data)
	if !allowedPreviewMediaType(mediaType) {
		return "", fmt.Errorf("%w: must be a png, jpeg, gif or webp image", ErrPreviewImage)
	}
	var w, h int
	if mediaType == "image/webp" {
		var ok bool
		if w, h, ok = webpSize(data); !ok {
			return "", fmt.Errorf("%w: unreadable webp header", ErrPreviewImage)
		}
	} else {
		cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
		if err != nil {
			return "", fmt.Errorf("%w: unreadable image header", ErrPreviewImage)
		}
		w, h = cfg.Width, cfg.Height
	}
	if w < 1 || h < 1 || w > MaxPreviewSide || h > MaxPreviewSide {
		return "", fmt.Errorf("%w: %dx%d pixels, the limit is %dx%d",
			ErrPreviewImage, w, h, MaxPreviewSide, MaxPreviewSide)
	}
	return mediaType, nil
}

// webpSize reads the canvas size from a webp header without decoding it. It
// handles the three chunk kinds: VP8 (lossy), VP8L (lossless) and VP8X
// (extended).
func webpSize(b []byte) (w, h int, ok bool) {
	if len(b) < 30 || string(b[0:4]) != "RIFF" || string(b[8:12]) != "WEBP" {
		return 0, 0, false
	}
	switch string(b[12:16]) {
	case "VP8 ":
		// frame tag (3 bytes) then the start code 9d 01 2a, then 14 bit sizes.
		if b[23] != 0x9d || b[24] != 0x01 || b[25] != 0x2a {
			return 0, 0, false
		}
		w = int(binary.LittleEndian.Uint16(b[26:28]) & 0x3fff)
		h = int(binary.LittleEndian.Uint16(b[28:30]) & 0x3fff)
	case "VP8L":
		// signature byte 0x2f, then width-1 and height-1 as 14 bits each.
		if b[20] != 0x2f {
			return 0, 0, false
		}
		bits := binary.LittleEndian.Uint32(b[21:25])
		w = int(bits&0x3fff) + 1
		h = int((bits>>14)&0x3fff) + 1
	case "VP8X":
		// flags (4 bytes), then canvas width-1 and height-1 as 24 bits each.
		w = int(uint32(b[24])|uint32(b[25])<<8|uint32(b[26])<<16) + 1
		h = int(uint32(b[27])|uint32(b[28])<<8|uint32(b[29])<<16) + 1
	default:
		return 0, 0, false
	}
	return w, h, true
}
