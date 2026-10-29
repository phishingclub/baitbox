package service

import (
	"bytes"
	"encoding/binary"
	"errors"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"testing"
)

func encode(t *testing.T, kind string, w, h int) []byte {
	t.Helper()
	img := image.NewPaletted(image.Rect(0, 0, w, h), color.Palette{color.Black, color.White})
	var buf bytes.Buffer
	var err error
	switch kind {
	case "png":
		err = png.Encode(&buf, img)
	case "jpeg":
		err = jpeg.Encode(&buf, img, nil)
	case "gif":
		err = gif.Encode(&buf, img, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// webpHeader builds the first bytes of a webp file of the given chunk kind and
// size, which is all webpSize reads.
func webpHeader(kind string, w, h int) []byte {
	b := make([]byte, 40)
	copy(b[0:], "RIFF")
	copy(b[8:], "WEBP")
	copy(b[12:], kind)
	switch kind {
	case "VP8 ":
		b[23], b[24], b[25] = 0x9d, 0x01, 0x2a
		binary.LittleEndian.PutUint16(b[26:], uint16(w))
		binary.LittleEndian.PutUint16(b[28:], uint16(h))
	case "VP8L":
		b[20] = 0x2f
		binary.LittleEndian.PutUint32(b[21:], uint32(w-1)|uint32(h-1)<<14)
	case "VP8X":
		w, h = w-1, h-1
		b[24], b[25], b[26] = byte(w), byte(w>>8), byte(w>>16)
		b[27], b[28], b[29] = byte(h), byte(h>>8), byte(h>>16)
	}
	return b
}

func TestCheckPreviewImageAccepts(t *testing.T) {
	for _, kind := range []string{"png", "jpeg", "gif"} {
		mt, err := checkPreviewImage(encode(t, kind, 800, 600))
		if err != nil || mt != "image/"+kind {
			t.Errorf("%s: mt=%q err=%v", kind, mt, err)
		}
	}
	for _, kind := range []string{"VP8 ", "VP8L", "VP8X"} {
		w, h, ok := webpSize(webpHeader(kind, 1200, 900))
		if !ok || w != 1200 || h != 900 {
			t.Errorf("webp %q: %dx%d ok=%v", kind, w, h, ok)
		}
	}
}

func TestCheckPreviewImageRejects(t *testing.T) {
	cases := map[string][]byte{
		"too wide png":      encode(t, "png", MaxPreviewSide+1, 10),
		"too tall gif":      encode(t, "gif", 10, MaxPreviewSide+1),
		"too large webp":    webpHeader("VP8X", 20000, 20000),
		"svg":               []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`),
		"html":              []byte("<!doctype html><html><script>alert(1)</script></html>"),
		"truncated png":     encode(t, "png", 10, 10)[:20],
		"over byte limit":   append(encode(t, "png", 10, 10), make([]byte, MaxPreviewBytes)...),
		"webp bad vp8 code": func() []byte { b := webpHeader("VP8 ", 10, 10); b[23] = 0; return b }(),
	}
	for name, data := range cases {
		if _, err := checkPreviewImage(data); !errors.Is(err, ErrPreviewImage) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestAddPreviewImageUsesDetectedType(t *testing.T) {
	svc := newTestRegistry(t)
	publishPage(t, svc, "acme", "thing", "1.0.0")
	// the client claims png but sends a jpeg: the stored type follows the bytes.
	sha, err := svc.AddPreviewImage("acme", "thing", encode(t, "jpeg", 50, 50))
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	ps, _ := svc.repo.ListPackagePreviews(mustPackageID(t, svc, "acme", "thing"))
	if len(ps) != 1 || ps[0].BlobSHA256 != sha || ps[0].MediaType != "image/jpeg" {
		t.Fatalf("stored preview: %+v", ps)
	}
	if _, err := svc.AddPreviewImage("acme", "thing", encode(t, "png", 5000, 10)); err == nil {
		t.Fatal("oversized preview accepted")
	}
}
