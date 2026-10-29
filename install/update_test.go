package install

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"testing"
)

// TestVerifySignatureRoundTrip exercises the signature check logic with an
// ephemeral key, so the test needs no private key on disk; the real private key
// lives only as a build secret.
func TestVerifySignatureRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	data := []byte("a pretend baitbox binary")
	sig := ed25519.Sign(priv, data)
	if err := verifySignatureWith(data, sig, pub); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	// a tampered binary must fail
	if err := verifySignatureWith([]byte("tampered"), sig, pub); err == nil {
		t.Fatal("expected failure for tampered data")
	}
	// a random signature must fail
	if err := verifySignatureWith(data, bytes.Repeat([]byte{0}, ed25519.SignatureSize), pub); err == nil {
		t.Fatal("expected failure for bad signature")
	}
}

func TestReleaseIsNewer(t *testing.T) {
	cases := []struct {
		tag, cur string
		want     bool
	}{
		{"v1.2.0", "1.1.0", true},
		{"v1.0.0", "1.0.0", false},
		{"v1.0.0", "1.2.0", false},
		{"v1.2.3", "dev", true}, // non semver current always updates
		{"not-a-version", "1.0.0", false},
	}
	for _, c := range cases {
		if got := releaseIsNewer(c.tag, c.cur); got != c.want {
			t.Fatalf("releaseIsNewer(%q,%q)=%v want %v", c.tag, c.cur, got, c.want)
		}
	}
}

func TestExtractBinaryAndSig(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	write := func(name string, b []byte) {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(b)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(b)
	}
	write("baitbox", []byte("binary-bytes"))
	write("baitbox.sig", []byte("sig-bytes"))
	tw.Close()
	gz.Close()

	bin, sig, err := extractBinaryAndSig(buf.Bytes())
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if string(bin) != "binary-bytes" || string(sig) != "sig-bytes" {
		t.Fatalf("got bin=%q sig=%q", bin, sig)
	}
}
