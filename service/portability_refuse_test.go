package service

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/manifest"
)

// TestImportBlobTooLargeIsInvalidBundle: a stored file over the archive cap is
// reported as an invalid bundle with a reason, not a server fault.
func TestImportBlobTooLargeIsInvalidBundle(t *testing.T) {
	dst := newTestRegistry(t)
	dst.maxDownload = 1024
	big := bytes.Repeat([]byte("x"), 2048)
	b := exportBundle{Format: bundleFormat}
	tarball := makeBundleTar(t, b, map[string][]byte{bundleSha(big): big})
	_, err := dst.ImportBundle(bytes.NewReader(tarball))
	if !errors.Is(err, ErrInvalidBundle) || !strings.Contains(err.Error(), "larger than the package archive limit") {
		t.Fatalf("want ErrInvalidBundle with a size reason, got %v", err)
	}
}

// TestImportRefusesOnePackageKeepsTheRest: one package whose stored version is
// bad is refused with a warning; a good package in the same bundle still
// imports, and the bad package's own namespace is not created.
func TestImportRefusesOnePackageKeepsTheRest(t *testing.T) {
	good, _, err := BuildArchive(PackageSpec{ID: "acme/good", Type: manifest.TypePage, Version: "1.0.0"},
		map[string][]byte{"content/index.html": []byte("good")})
	if err != nil {
		t.Fatal(err)
	}
	// a valid archive filed under an address its manifest does not name.
	stray, _, err := BuildArchive(PackageSpec{ID: "other/elsewhere", Type: manifest.TypePage, Version: "1.0.0"},
		map[string][]byte{"content/index.html": []byte("stray")})
	if err != nil {
		t.Fatal(err)
	}
	b := exportBundle{
		Format: bundleFormat,
		Namespaces: []nsDTO{
			{Name: "acme", Visibility: database.VisibilityPrivate},
			{Name: "broken", Visibility: database.VisibilityPrivate},
			{Name: "empty", Visibility: database.VisibilityPrivate},
		},
		Packages: []pkgDTO{
			{Namespace: "acme", Name: "good", Type: manifest.TypePage},
			{Namespace: "broken", Name: "bad", Type: manifest.TypePage},
		},
		Versions: []verDTO{
			{Namespace: "acme", Name: "good", Version: "1.0.0", ArchiveSha: bundleSha(good)},
			{Namespace: "broken", Name: "bad", Version: "1.0.0", ArchiveSha: bundleSha(stray)},
			{Namespace: "broken", Name: "bad", Version: "01.0.0", ArchiveSha: bundleSha(stray)},
		},
	}
	tarball := makeBundleTar(t, b, map[string][]byte{bundleSha(good): good, bundleSha(stray): stray})
	dst := newTestRegistry(t)
	sum, err := dst.ImportBundle(bytes.NewReader(tarball))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if sum.Packages != 1 || sum.Versions != 1 || len(sum.Refused) != 1 || sum.Refused[0] != "broken/bad" {
		t.Fatalf("summary = %+v", sum)
	}
	// acme holds the good package; empty has no packages and is a plain export of
	// an empty namespace, so it is created too. broken is not.
	if sum.Namespaces != 2 {
		t.Fatalf("namespaces = %d, want 2", sum.Namespaces)
	}
	if _, err := dst.GetNamespace("broken"); err == nil {
		t.Fatal("namespace of a refused only package was created")
	}
	if _, err := dst.GetNamespace("empty"); err != nil {
		t.Fatal("an empty namespace in the bundle was not imported")
	}
	if _, _, v, err := dst.Resolve("acme", "good", "1.0.0"); err != nil || v == nil {
		t.Fatalf("good package missing: %v", err)
	}
	if dst.blobs.Exists(bundleSha(stray)) {
		t.Fatal("the refused package's blob was kept")
	}
}

// TestImportPreviewBlobRecordsRealSize: a preview image blob row carries the
// stored size, not zero.
func TestImportPreviewBlobRecordsRealSize(t *testing.T) {
	src := newTestRegistry(t)
	publishPage(t, src, "acme", "thing", "1.0.0")
	img := encode(t, "png", 8, 8)
	if _, err := src.AddPreviewImage("acme", "thing", img); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := src.ExportBundle(&buf); err != nil {
		t.Fatal(err)
	}
	db := newTestDB(t)
	dst := registryOverDB(t, db)
	if _, err := dst.ImportBundle(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("import: %v", err)
	}
	var row database.Blob
	if err := db.Where("sha256 = ?", bundleSha(img)).First(&row).Error; err != nil {
		t.Fatalf("blob row: %v", err)
	}
	if row.Size != int64(len(img)) {
		t.Fatalf("size = %d, want %d", row.Size, len(img))
	}
}

// TestImportNamespaceDescriptionCap: a bundle namespace description over the cap
// is an invalid bundle, the same rule as the admin edit.
func TestImportNamespaceDescriptionCap(t *testing.T) {
	b := exportBundle{
		Format:     bundleFormat,
		Namespaces: []nsDTO{{Name: "acme", Visibility: database.VisibilityPrivate, Description: strings.Repeat("d", 4001)}},
	}
	dst := newTestRegistry(t)
	_, err := dst.ImportBundle(bytes.NewReader(makeBundleTar(t, b, nil)))
	if !errors.Is(err, ErrInvalidBundle) || !strings.Contains(err.Error(), "description") {
		t.Fatalf("want ErrInvalidBundle about the description, got %v", err)
	}
}

// TestImportInspectsEachArchiveOnce: many version entries naming one archive
// cost one integrity check, and only the entry it belongs to imports.
func TestImportInspectsEachArchiveOnce(t *testing.T) {
	archive, _, err := BuildArchive(PackageSpec{ID: "acme/p0", Type: manifest.TypePage, Version: "1.0.0"},
		map[string][]byte{"content/index.html": []byte("p0")})
	if err != nil {
		t.Fatal(err)
	}
	sha := bundleSha(archive)
	b := exportBundle{Format: bundleFormat, Namespaces: []nsDTO{{Name: "acme", Visibility: database.VisibilityPrivate}}}
	const n = 2000
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("p%d", i)
		b.Packages = append(b.Packages, pkgDTO{Namespace: "acme", Name: name, Type: manifest.TypePage})
		b.Versions = append(b.Versions, verDTO{Namespace: "acme", Name: name, Version: "1.0.0", ArchiveSha: sha})
	}
	calls := 0
	orig := inspectArchive
	inspectArchive = func(path string, l ArchiveLimits) (*manifest.Manifest, int64, error) {
		calls++
		return orig(path, l)
	}
	defer func() { inspectArchive = orig }()
	dst := newTestRegistry(t)
	sum, err := dst.ImportBundle(bytes.NewReader(makeBundleTar(t, b, map[string][]byte{sha: archive})))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if calls != 1 {
		t.Fatalf("archive inspected %d times, want 1", calls)
	}
	if sum.Packages != 1 || len(sum.Refused) != n-1 {
		t.Fatalf("imported %d, refused %d", sum.Packages, len(sum.Refused))
	}
}

// TestImportCheapChecksFirst: a bad archive reference or too many entries is
// refused before any archive is opened.
func TestImportCheapChecksFirst(t *testing.T) {
	archive, _, err := BuildArchive(PackageSpec{ID: "acme/p0", Type: manifest.TypePage, Version: "1.0.0"},
		map[string][]byte{"content/index.html": []byte("p0")})
	if err != nil {
		t.Fatal(err)
	}
	sha := bundleSha(archive)
	calls := 0
	orig := inspectArchive
	inspectArchive = func(path string, l ArchiveLimits) (*manifest.Manifest, int64, error) {
		calls++
		return orig(path, l)
	}
	defer func() { inspectArchive = orig }()
	base := func() exportBundle {
		return exportBundle{
			Format:     bundleFormat,
			Namespaces: []nsDTO{{Name: "acme", Visibility: database.VisibilityPrivate}},
			Packages:   []pkgDTO{{Namespace: "acme", Name: "p0", Type: manifest.TypePage}},
			Versions:   []verDTO{{Namespace: "acme", Name: "p0", Version: "1.0.0", ArchiveSha: sha}},
		}
	}
	badRef := base()
	badRef.Versions = append(badRef.Versions,
		verDTO{Namespace: "acme", Name: "p0", Version: "1.0.1", ArchiveSha: "../../" + sha[6:]})
	tooMany := base()
	for i := 0; i < maxBundleEntries; i++ {
		tooMany.Versions = append(tooMany.Versions,
			verDTO{Namespace: "acme", Name: "p0", Version: fmt.Sprintf("2.0.%d", i), ArchiveSha: sha})
	}
	for name, b := range map[string]exportBundle{"bad reference": badRef, "too many": tooMany} {
		calls = 0
		_, err := newTestRegistry(t).ImportBundle(bytes.NewReader(makeBundleTar(t, b, map[string][]byte{sha: archive})))
		if !errors.Is(err, ErrInvalidBundle) {
			t.Fatalf("%s: %v", name, err)
		}
		if calls != 0 {
			t.Fatalf("%s: %d archives inspected before the refusal", name, calls)
		}
	}
}
