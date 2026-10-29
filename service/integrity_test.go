package service

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/phishingclub/baitbox/manifest"
)

func shaHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// writeArchive writes the given tar entries as a tar.gz temp file and returns
// its path.
func writeArchive(t *testing.T, entries map[string][]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "arc.tgz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for name, b := range entries {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(b)
	}
	tw.Close()
	gz.Close()
	return path
}

// validManifestFor builds a valid baitbox.json for the payload entries.
func validManifestFor(payload map[string][]byte) []byte {
	es := make([]manifest.Entry, 0, len(payload))
	for name, b := range payload {
		es = append(es, manifest.Entry{Path: name, SHA256: shaHex(b)})
	}
	m := manifest.Manifest{
		Format: manifest.Format, ID: "acme-corp/thing", Type: manifest.TypePage,
		Version: "1.0.0", Entries: es, ContentHash: manifest.ComputeContentHash(es),
	}
	mj, _ := json.Marshal(&m)
	return mj
}

func TestInspectArchiveValid(t *testing.T) {
	payload := map[string][]byte{"content/p.html": []byte("hello")}
	entries := map[string][]byte{"baitbox.json": validManifestFor(payload)}
	for k, v := range payload {
		entries[k] = v
	}
	m, err := inspectManifest(writeArchive(t, entries), ArchiveLimits{MaxFile: 1 << 20})
	if err != nil {
		t.Fatalf("valid archive rejected: %v", err)
	}
	if m.ID != "acme-corp/thing" {
		t.Fatalf("id %q", m.ID)
	}
}

func TestInspectArchiveMissingManifest(t *testing.T) {
	entries := map[string][]byte{"content/p.html": []byte("x")}
	if _, err := inspectManifest(writeArchive(t, entries), ArchiveLimits{MaxFile: 1 << 20}); err == nil {
		t.Fatal("expected error for missing manifest")
	}
}

func TestInspectArchiveTraversal(t *testing.T) {
	payload := map[string][]byte{"content/p.html": []byte("x")}
	entries := map[string][]byte{"baitbox.json": validManifestFor(payload), "content/p.html": []byte("x"), "../evil": []byte("x")}
	if _, err := inspectManifest(writeArchive(t, entries), ArchiveLimits{MaxFile: 1 << 20}); err == nil {
		t.Fatal("expected error for path traversal entry")
	}
}

func TestInspectArchiveDisallowedTop(t *testing.T) {
	payload := map[string][]byte{"content/p.html": []byte("x")}
	entries := map[string][]byte{"baitbox.json": validManifestFor(payload), "content/p.html": []byte("x"), "secrets/leak": []byte("x")}
	if _, err := inspectManifest(writeArchive(t, entries), ArchiveLimits{MaxFile: 1 << 20}); err == nil {
		t.Fatal("expected error for disallowed top level path")
	}
}

func TestInspectArchiveEntryHashMismatch(t *testing.T) {
	payload := map[string][]byte{"content/p.html": []byte("original")}
	mj := validManifestFor(payload)
	// ship different bytes than the manifest declares
	entries := map[string][]byte{"baitbox.json": mj, "content/p.html": []byte("tampered")}
	if _, err := inspectManifest(writeArchive(t, entries), ArchiveLimits{MaxFile: 1 << 20}); err == nil {
		t.Fatal("expected error for entry hash mismatch")
	}
}

func TestInspectArchiveUndeclaredFile(t *testing.T) {
	payload := map[string][]byte{"content/p.html": []byte("x")}
	entries := map[string][]byte{"baitbox.json": validManifestFor(payload), "content/p.html": []byte("x"), "assets/extra.txt": []byte("undeclared")}
	if _, err := inspectManifest(writeArchive(t, entries), ArchiveLimits{MaxFile: 1 << 20}); err == nil {
		t.Fatal("expected error for undeclared payload file")
	}
}

func TestInspectArchiveOversizeFile(t *testing.T) {
	big := []byte(strings.Repeat("A", 5000))
	payload := map[string][]byte{"content/p.html": big}
	entries := map[string][]byte{"baitbox.json": validManifestFor(payload), "content/p.html": big}
	if _, err := inspectManifest(writeArchive(t, entries), ArchiveLimits{MaxFile: 1024}); err == nil {
		t.Fatal("expected error for file over the size cap")
	}
}

// writeOrderedArchive writes tar entries in the given order, allowing duplicate
// and non canonical names that a map cannot express.
func writeOrderedArchive(t *testing.T, names []string, data [][]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "arc.tgz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for i, name := range names {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data[i])), Typeflag: tar.TypeReg})
		_, _ = tw.Write(data[i])
	}
	tw.Close()
	gz.Close()
	return path
}

func TestInspectArchiveDuplicateEntry(t *testing.T) {
	good := []byte("hello")
	payload := map[string][]byte{"content/p.html": good}
	mj := validManifestFor(payload)
	// the hashed copy comes first, a second copy with other bytes follows.
	path := writeOrderedArchive(t,
		[]string{"baitbox.json", "content/p.html", "content/p.html"},
		[][]byte{mj, good, []byte("evil")})
	if _, err := inspectManifest(path, ArchiveLimits{MaxFile: 1 << 20}); err == nil {
		t.Fatal("expected error for duplicate payload entry")
	}
	// a second manifest is rejected too.
	path = writeOrderedArchive(t,
		[]string{"baitbox.json", "content/p.html", "baitbox.json"},
		[][]byte{mj, good, mj})
	if _, err := inspectManifest(path, ArchiveLimits{MaxFile: 1 << 20}); err == nil {
		t.Fatal("expected error for duplicate manifest")
	}
}

func TestInspectArchiveNonCanonicalName(t *testing.T) {
	good := []byte("hello")
	mj := validManifestFor(map[string][]byte{"content/p.html": good})
	for _, alias := range []string{"./content/p.html", "content//p.html", "content/./p.html"} {
		path := writeOrderedArchive(t, []string{"baitbox.json", alias}, [][]byte{mj, good})
		if _, err := inspectManifest(path, ArchiveLimits{MaxFile: 1 << 20}); err == nil {
			t.Fatalf("expected error for non canonical name %q", alias)
		}
	}
	path := writeOrderedArchive(t, []string{"./baitbox.json", "content/p.html"}, [][]byte{mj, good})
	if _, err := inspectManifest(path, ArchiveLimits{MaxFile: 1 << 20}); err == nil {
		t.Fatal("expected error for non canonical manifest name")
	}
}

func TestInspectArchiveManifestCap(t *testing.T) {
	good := []byte("hello")
	// a manifest just over 1 MiB, even with a far larger per file cap.
	big := append([]byte(`{"format":"`), []byte(strings.Repeat("x", maxManifestBytes))...)
	path := writeOrderedArchive(t, []string{"baitbox.json", "content/p.html"}, [][]byte{big, good})
	_, err := inspectManifest(path, ArchiveLimits{MaxFile: 64 << 20})
	if err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("expected size limit error, got %v", err)
	}
}

// writeHeaderArchive writes tar entries from explicit headers, so a test can set
// the type flag and the long name formats.
func writeHeaderArchive(t *testing.T, hdrs []*tar.Header, data [][]byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "arc.tgz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for i, h := range hdrs {
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(data[i]))
		}
		if h.Mode == 0 {
			h.Mode = 0o644
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatalf("header %q: %v", h.Name, err)
		}
		if h.Typeflag == tar.TypeReg {
			_, _ = tw.Write(data[i])
		}
	}
	tw.Close()
	gz.Close()
	return path
}

func TestInspectArchiveDirectoryEntries(t *testing.T) {
	good := []byte("hello")
	mj := validManifestFor(map[string][]byte{"content/p.html": good})
	reg := func(n string) *tar.Header { return &tar.Header{Name: n, Typeflag: tar.TypeReg} }
	dir := func(n string) *tar.Header { return &tar.Header{Name: n, Typeflag: tar.TypeDir, Mode: 0o755} }

	// ordinary directory entries a tar tool adds are accepted.
	ok := writeHeaderArchive(t, []*tar.Header{dir("content/"), reg("baitbox.json"), reg("content/p.html")}, [][]byte{nil, mj, good})
	if _, err := inspectManifest(ok, ArchiveLimits{MaxFile: 1 << 20}); err != nil {
		t.Fatalf("plain directory entry rejected: %v", err)
	}
	bad := []string{"../evil/", "/abs/", "./content/", "content//x/", "other/", "content/..x/"}
	for _, d := range bad {
		p := writeHeaderArchive(t, []*tar.Header{dir(d), reg("baitbox.json"), reg("content/p.html")}, [][]byte{nil, mj, good})
		if _, err := inspectManifest(p, ArchiveLimits{MaxFile: 1 << 20}); err == nil {
			t.Fatalf("directory %q accepted", d)
		}
	}
	// a directory and a file of the same name, either order.
	p := writeHeaderArchive(t, []*tar.Header{reg("baitbox.json"), dir("content/p.html/"), reg("content/p.html")}, [][]byte{mj, nil, good})
	if _, err := inspectManifest(p, ArchiveLimits{MaxFile: 1 << 20}); err == nil {
		t.Fatal("directory then file of the same name accepted")
	}
	p = writeHeaderArchive(t, []*tar.Header{reg("baitbox.json"), reg("content/p.html"), dir("content/p.html/")}, [][]byte{mj, good, nil})
	if _, err := inspectManifest(p, ArchiveLimits{MaxFile: 1 << 20}); err == nil {
		t.Fatal("file then directory of the same name accepted")
	}
}

func TestInspectArchiveLongNamesAndOtherTypes(t *testing.T) {
	long := "content/" + strings.Repeat("a", 150) + ".html"
	good := []byte("hello")
	mj := validManifestFor(map[string][]byte{long: good})
	for _, format := range []tar.Format{tar.FormatPAX, tar.FormatGNU} {
		p := writeHeaderArchive(t, []*tar.Header{
			{Name: "baitbox.json", Typeflag: tar.TypeReg},
			{Name: long, Typeflag: tar.TypeReg, Format: format},
		}, [][]byte{mj, good})
		if _, err := inspectManifest(p, ArchiveLimits{MaxFile: 1 << 20}); err != nil {
			t.Fatalf("long name in format %v rejected: %v", format, err)
		}
		// a long name that hides a traversal is still caught after the reader
		// resolves it.
		evil := "content/" + strings.Repeat("a", 150) + "/../../../etc/x"
		p = writeHeaderArchive(t, []*tar.Header{
			{Name: "baitbox.json", Typeflag: tar.TypeReg},
			{Name: evil, Typeflag: tar.TypeReg, Format: format},
		}, [][]byte{mj, good})
		if _, err := inspectManifest(p, ArchiveLimits{MaxFile: 1 << 20}); err == nil {
			t.Fatalf("long traversal name in format %v accepted", format)
		}
	}
	// links are refused outright.
	mj2 := validManifestFor(map[string][]byte{"content/p.html": good})
	p := writeHeaderArchive(t, []*tar.Header{
		{Name: "baitbox.json", Typeflag: tar.TypeReg},
		{Name: "content/p.html", Typeflag: tar.TypeReg},
		{Name: "content/l", Typeflag: tar.TypeSymlink, Linkname: "../../etc/passwd"},
	}, [][]byte{mj2, good, nil})
	if _, err := inspectManifest(p, ArchiveLimits{MaxFile: 1 << 20}); err == nil {
		t.Fatal("symlink accepted")
	}
}

func TestInspectArchiveDirectoryFlood(t *testing.T) {
	good := []byte("hello")
	mj := validManifestFor(map[string][]byte{"content/p.html": good})
	hdrs := []*tar.Header{{Name: "baitbox.json", Typeflag: tar.TypeReg}, {Name: "content/p.html", Typeflag: tar.TypeReg}}
	data := [][]byte{mj, good}
	for i := 0; i <= maxArchiveOtherEntries; i++ {
		hdrs = append(hdrs, &tar.Header{Name: fmt.Sprintf("content/d%d/", i), Typeflag: tar.TypeDir, Mode: 0o755})
		data = append(data, nil)
	}
	p := writeHeaderArchive(t, hdrs, data)
	if _, err := inspectManifest(p, ArchiveLimits{MaxFile: 1 << 20}); err == nil || !strings.Contains(err.Error(), "directory entries") {
		t.Fatalf("directory flood: %v", err)
	}
}

func TestInspectArchiveCaseOnlyClash(t *testing.T) {
	good := []byte("hello")
	mj := validManifestFor(map[string][]byte{"content/p.html": good})
	p := writeHeaderArchive(t, []*tar.Header{
		{Name: "baitbox.json", Typeflag: tar.TypeReg},
		{Name: "content/P.html/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "content/p.html", Typeflag: tar.TypeReg},
	}, [][]byte{mj, nil, good})
	if _, err := inspectManifest(p, ArchiveLimits{MaxFile: 1 << 20}); err == nil {
		t.Fatal("directory and file differing only by case accepted")
	}
}

func TestCapReaderStopsTheStream(t *testing.T) {
	r := &capReader{r: strings.NewReader(strings.Repeat("x", 100)), left: 10}
	n, err := io.Copy(io.Discard, r)
	if n != 10 || !errors.Is(err, errStreamTooLarge) {
		t.Fatalf("read %d bytes, err %v", n, err)
	}
	// headers the tar reader skips count too: a long PAX record past the cap fails.
	good := []byte("hello")
	mj := validManifestFor(map[string][]byte{"content/p.html": good})
	p := writeHeaderArchive(t, []*tar.Header{
		{Name: "baitbox.json", Typeflag: tar.TypeReg},
		{Name: "content/p.html", Typeflag: tar.TypeReg, PAXRecords: map[string]string{"comment": strings.Repeat("y", 512<<10)}},
	}, [][]byte{mj, good})
	if _, err := inspectManifest(p, ArchiveLimits{MaxFile: 1 << 20, MaxUnpacked: 4 << 10, MaxFiles: 2}); !errors.Is(err, errStreamTooLarge) {
		t.Fatalf("oversized stream: %v", err)
	}
}
