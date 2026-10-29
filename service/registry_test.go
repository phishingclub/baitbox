package service

import (
	"bytes"
	"errors"
	"testing"

	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/manifest"
)

func TestPublishAndResolveLatest(t *testing.T) {
	svc := newTestRegistry(t)
	publishPage(t, svc, "acme", "thing", "1.0.0")

	ns, pkg, v, err := svc.Resolve("acme", "thing", "latest")
	if err != nil {
		t.Fatalf("resolve latest: %v", err)
	}
	if ns.Name != "acme" || pkg.Name != "thing" || v.Version != "1.0.0" {
		t.Fatalf("resolved %s/%s@%s", ns.Name, pkg.Name, v.Version)
	}
	// the stored version's content hash must equal the manifest's own computed hash
	// over its entries, so the row can never disagree with the archive it serves.
	m, err := manifest.Parse([]byte(v.Manifest))
	if err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	if v.ContentHash != manifest.ComputeContentHash(m.Entries) {
		t.Fatalf("content hash %q does not match entries", v.ContentHash)
	}
}

func TestResolveMissing(t *testing.T) {
	svc := newTestRegistry(t)
	publishPage(t, svc, "acme", "thing", "1.0.0")
	cases := []struct{ ns, name, version string }{
		{"nope", "thing", "latest"},
		{"acme", "nope", "latest"},
		{"acme", "thing", "9.9.9"},
	}
	for _, c := range cases {
		if _, _, _, err := svc.Resolve(c.ns, c.name, c.version); !errors.Is(err, ErrNotFound) {
			t.Fatalf("resolve %s/%s@%s: want ErrNotFound, got %v", c.ns, c.name, c.version, err)
		}
	}
}

// TestLatestIsSemverNotPublishOrder back-publishes an older patch after a newer
// one and confirms latest still serves the highest semver version, not the most
// recently published.
func TestLatestIsSemverNotPublishOrder(t *testing.T) {
	svc := newTestRegistry(t)
	publishPage(t, svc, "acme", "thing", "1.0.0")
	publishPage(t, svc, "acme", "thing", "2.0.0")
	// published last, but a lower version: must not become latest.
	publishPage(t, svc, "acme", "thing", "1.5.0")

	_, _, v, err := svc.Resolve("acme", "thing", "latest")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if v.Version != "2.0.0" {
		t.Fatalf("latest = %q, want 2.0.0", v.Version)
	}
}

func TestRepublishSameVersionRejected(t *testing.T) {
	svc := newTestRegistry(t)
	first := publishPage(t, svc, "acme", "thing", "1.0.0")

	_, _, err := svc.AuthorPackage(AuthoredPackage{
		Namespace: "acme", Name: "thing", Type: manifest.TypePage, Version: "1.0.0",
		Files: map[string][]byte{"content/index.html": []byte("different bytes")},
	})
	if !errors.Is(err, ErrVersionExists) {
		t.Fatalf("re-publish: want ErrVersionExists, got %v", err)
	}
	// the rejected re-publish must not disturb the stored version or its blob.
	_, _, v, rerr := svc.Resolve("acme", "thing", "1.0.0")
	if rerr != nil {
		t.Fatalf("resolve after reject: %v", rerr)
	}
	if v.ArchiveBlobSHA256 != first.ArchiveBlobSHA256 {
		t.Fatalf("archive blob changed by rejected publish")
	}
	if !svc.blobs.Exists(first.ArchiveBlobSHA256) {
		t.Fatal("original blob removed by rejected publish")
	}
}

func TestPublishNamespaceMismatch(t *testing.T) {
	svc := newTestRegistry(t)
	// AuthorPackage builds the archive for one id, but Publish is told a different
	// target name: the manifest id must match the coordinates or it is rejected.
	archive, _, err := BuildArchive(PackageSpec{
		ID: "acme/thing", Type: manifest.TypePage, Version: "1.0.0",
	}, map[string][]byte{"content/index.html": []byte("x")})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if _, err := svc.Publish("acme", "other", "1.0.0", "application/gzip", bytes.NewReader(archive)); !errors.Is(err, ErrNamespaceMismatch) {
		t.Fatalf("name mismatch: want ErrNamespaceMismatch, got %v", err)
	}
	if _, err := svc.Publish("wrongns", "thing", "1.0.0", "application/gzip", bytes.NewReader(archive)); !errors.Is(err, ErrNamespaceMismatch) {
		t.Fatalf("namespace mismatch: want ErrNamespaceMismatch, got %v", err)
	}
}

func TestEffectiveLatest(t *testing.T) {
	ver := func(v string, yanked bool) database.PackageVersion {
		return database.PackageVersion{Version: v, Yanked: yanked}
	}
	tests := []struct {
		name     string
		versions []database.PackageVersion
		want     string // "" means nil
	}{
		{"empty", nil, ""},
		{"single", []database.PackageVersion{ver("1.0.0", false)}, "1.0.0"},
		{
			"numeric precedence not lexical",
			[]database.PackageVersion{ver("9.0.0", false), ver("10.0.0", false)},
			"10.0.0",
		},
		{
			"yanked highest is skipped",
			[]database.PackageVersion{ver("1.0.0", false), ver("2.0.0", true)},
			"1.0.0",
		},
		{
			"all yanked falls back to highest",
			[]database.PackageVersion{ver("1.0.0", true), ver("2.0.0", true)},
			"2.0.0",
		},
		{
			"prerelease precedes release",
			[]database.PackageVersion{ver("1.0.0-rc.1", false), ver("1.0.0", false)},
			"1.0.0",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := effectiveLatest(tc.versions)
			if tc.want == "" {
				if got != nil {
					t.Fatalf("want nil, got %q", got.Version)
				}
				return
			}
			if got == nil || got.Version != tc.want {
				t.Fatalf("want %q, got %v", tc.want, got)
			}
		})
	}
}

func TestSemverLess(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"9.0.0", "10.0.0", true}, // numeric, not lexical
		{"10.0.0", "9.0.0", false},
		{"1.0.0", "1.0.0", false},
		{"1.0.0-rc.1", "1.0.0", true},
		{"1.2.0", "1.10.0", true},
	}
	for _, tc := range tests {
		if got := semverLess(tc.a, tc.b); got != tc.want {
			t.Fatalf("semverLess(%q,%q)=%v want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestContentHashDeterministic confirms identical payload yields the same
// content hash (and the same archive bytes, so a re-upload dedupes).
func TestContentHashDeterministic(t *testing.T) {
	files := map[string][]byte{
		"content/index.html": []byte("hello"),
		"assets/logo.png":    []byte("PNGDATA"),
	}
	a1, m1, err := BuildArchive(PackageSpec{ID: "acme/thing", Type: manifest.TypePage, Version: "1.0.0"}, files)
	if err != nil {
		t.Fatalf("build 1: %v", err)
	}
	a2, m2, err := BuildArchive(PackageSpec{ID: "acme/thing", Type: manifest.TypePage, Version: "1.0.0"}, files)
	if err != nil {
		t.Fatalf("build 2: %v", err)
	}
	if m1.ContentHash != m2.ContentHash {
		t.Fatalf("content hash not deterministic: %q vs %q", m1.ContentHash, m2.ContentHash)
	}
	if string(a1) != string(a2) {
		t.Fatal("archive bytes not deterministic")
	}
}
