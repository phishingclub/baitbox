package service

import (
	"bytes"
	"strings"
	"testing"
)

func TestBlobStorePutAndDedupe(t *testing.T) {
	bs, err := NewBlobStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("some package bytes")
	sha1, n1, err := bs.Put(bytes.NewReader(data), 1<<20)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if n1 != int64(len(data)) {
		t.Fatalf("size %d", n1)
	}
	if !bs.Exists(sha1) {
		t.Fatal("blob not stored")
	}
	// identical content dedupes to the same sha, no error.
	sha2, _, err := bs.Put(bytes.NewReader(data), 1<<20)
	if err != nil || sha2 != sha1 {
		t.Fatalf("dedupe failed: sha2=%s err=%v", sha2, err)
	}
	rc, err := bs.Open(sha1)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
}

func TestBlobStoreSizeCap(t *testing.T) {
	bs, err := NewBlobStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	big := strings.NewReader(strings.Repeat("A", 2000))
	if _, _, err := bs.Put(big, 1000); err == nil {
		t.Fatal("expected ErrBlobTooLarge for input over the cap")
	}
}

func TestBlobStorePathRejectsNonSHA(t *testing.T) {
	bs, err := NewBlobStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "a", "../../etc/passwd", strings.Repeat("A", 64), strings.Repeat("a", 63)} {
		if p, err := bs.Path(bad); err == nil || p != "" {
			t.Fatalf("Path(%q) = %q, %v", bad, p, err)
		}
	}
	sha := strings.Repeat("ab", 32)
	p, err := bs.Path(sha)
	if err != nil || !strings.HasSuffix(p, "/ab/"+sha) {
		t.Fatalf("Path(valid) = %q, %v", p, err)
	}
}
