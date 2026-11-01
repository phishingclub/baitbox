package service

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/manifest"
)

// publishSized publishes a page whose html file holds n bytes.
func publishSized(t *testing.T, svc *RegistryService, ns, name, version string, n int) *database.PackageVersion {
	t.Helper()
	v, _, err := svc.AuthorPackage(AuthoredPackage{
		Namespace: ns, Name: name, Type: manifest.TypePage, Version: version,
		Files: map[string][]byte{"content/index.html": bytes.Repeat([]byte("x"), n)},
	})
	if err != nil {
		t.Fatalf("publish %s/%s@%s: %v", ns, name, version, err)
	}
	return v
}

func deps(ids ...string) []manifest.Dependency {
	out := make([]manifest.Dependency, len(ids))
	for i, id := range ids {
		out[i] = manifest.Dependency{ID: id, Range: "*"}
	}
	return out
}

// TestBundleCapsMatchPhishingClub: the caps equal the Phishing Club consumer
// limits (maxBundleDependencies and maxBundleBytes).
func TestBundleCapsMatchPhishingClub(t *testing.T) {
	if manifest.MaxDependencies != 100 {
		t.Fatalf("dependency cap = %d, want 100", manifest.MaxDependencies)
	}
	if MaxBundleInstallBytes != 64<<20 {
		t.Fatalf("install cap = %d, want 64 MiB", MaxBundleInstallBytes)
	}
	if newTestRegistry(t).bundleCap != MaxBundleInstallBytes {
		t.Fatal("service does not use the install cap by default")
	}
}

// TestPublishStoresUnpackedSize: a published version records the unpacked size,
// the same total a fresh read of its archive gives, manifest included.
func TestPublishStoresUnpackedSize(t *testing.T) {
	svc := newTestRegistry(t)
	v := publishSized(t, svc, "team", "page", "1.0.0", 1000)
	got := readUnpacked(t, svc, v)
	if v.UnpackedSize != got || got <= 1000 {
		t.Fatalf("unpacked size = %d, archive reads %d", v.UnpackedSize, got)
	}
	_, _, stored, err := svc.Resolve("team", "page", "1.0.0")
	if err != nil || stored.UnpackedSize != got {
		t.Fatalf("stored unpacked size = %v, %v", stored, err)
	}
}

// TestBundlePublishRefusedOverCap: a bundle whose own size plus the latest
// version of each reference is over the cap is refused with a message naming
// the total; one under the cap is accepted.
func TestBundlePublishRefusedOverCap(t *testing.T) {
	svc := newTestRegistry(t)
	svc.bundleCap = 5000
	publishSized(t, svc, "team", "a", "1.0.0", 3000)
	publishSized(t, svc, "team", "b", "1.0.0", 3000)

	if _, err := publishBundle(svc, "team", "small", "1.0.0", deps("team/a")); err != nil {
		t.Fatalf("bundle under the cap: %v", err)
	}
	_, err := publishBundle(svc, "team", "big", "1.0.0", deps("team/a", "team/b"))
	if !errors.Is(err, ErrBundleTooLarge) || !strings.Contains(err.Error(), "team/big") || !strings.Contains(err.Error(), "bytes") {
		t.Fatalf("want ErrBundleTooLarge naming the bundle and total, got %v", err)
	}
	if _, _, _, err := svc.Resolve("team", "big", ""); err == nil {
		t.Fatal("refused bundle left a package behind")
	}
}

// TestBundleMeasuresLatestDependency: the size uses the version latest serves
// (highest semver, not yanked), the one Phishing Club installs.
func TestBundleMeasuresLatestDependency(t *testing.T) {
	svc := newTestRegistry(t)
	svc.bundleCap = 5000
	publishSized(t, svc, "team", "a", "1.0.0", 100)
	publishSized(t, svc, "team", "a", "0.9.0", 6000) // older, not latest
	if _, err := publishBundle(svc, "team", "kit", "1.0.0", deps("team/a")); err != nil {
		t.Fatalf("bundle should measure 1.0.0, not the larger older version: %v", err)
	}
}

// TestDependencyChangeRefusedWhenBundleWouldExceed: a new latest version of a
// referenced package that would push a bundle over the cap is refused, naming
// the bundle, while a version that does not become latest is allowed. A yank or
// delete is always applied and reports the bundle as a warning.
func TestDependencyChangeRefusedWhenBundleWouldExceed(t *testing.T) {
	svc := newTestRegistry(t)
	svc.bundleCap = 5000
	publishSized(t, svc, "team", "a", "1.0.0", 100)
	if _, err := publishBundle(svc, "team", "kit", "1.0.0", deps("team/a")); err != nil {
		t.Fatal(err)
	}

	_, _, err := svc.AuthorPackage(AuthoredPackage{
		Namespace: "team", Name: "a", Type: manifest.TypePage, Version: "1.1.0",
		Files: map[string][]byte{"content/index.html": bytes.Repeat([]byte("x"), 6000)},
	})
	if !errors.Is(err, ErrBundleTooLarge) || !strings.Contains(err.Error(), "team/kit") {
		t.Fatalf("new latest over the cap: want ErrBundleTooLarge naming team/kit, got %v", err)
	}
	if _, _, v, err := svc.Resolve("team", "a", "1.1.0"); err == nil {
		t.Fatalf("refused version was stored: %+v", v)
	}

	// an older version is never served as latest, so it is allowed.
	publishSized(t, svc, "team", "a", "0.9.0", 6000)

	// yanking or deleting 1.0.0 makes latest serve the large 0.9.0. Neither is
	// ever refused, so a broken version can always be pulled; the bundle that now
	// exceeds the cap is reported instead.
	w, err := svc.YankVersion("team", "a", "1.0.0", true)
	warn := w.BundlesOverCap
	if err != nil || len(warn) != 1 || !strings.Contains(warn[0], "team/kit") {
		t.Fatalf("yank: want success with a team/kit warning, got %v, %v", warn, err)
	}
	if _, _, v, _ := svc.Resolve("team", "a", "1.0.0"); v == nil || !v.Yanked {
		t.Fatal("yank was not applied")
	}
	// restoring it moves latest back to the small version, so no warning.
	if w, err := svc.YankVersion("team", "a", "1.0.0", false); err != nil || len(w.BundlesOverCap) != 0 {
		t.Fatalf("unyank: got %v, %v", w, err)
	}
	w, err = svc.DeleteVersion("team", "a", "1.0.0")
	warn = w.BundlesOverCap
	if err != nil || len(warn) != 1 || !strings.Contains(warn[0], "team/kit") {
		t.Fatalf("delete: want success with a team/kit warning, got %v, %v", warn, err)
	}
	if _, _, _, err := svc.Resolve("team", "a", "1.0.0"); err == nil {
		t.Fatal("delete was not applied")
	}
	// a missing version keeps the not found result.
	if _, err := svc.YankVersion("team", "a", "9.9.9", true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing version: want ErrNotFound, got %v", err)
	}
}

// TestMoveStoresUnpackedSize: a moved package is repacked under its new id,
// and each version keeps an unpacked size that matches its new archive.
func TestMoveStoresUnpackedSize(t *testing.T) {
	svc := newTestRegistry(t)
	publishSized(t, svc, "team", "a", "1.0.0", 500)
	if _, err := svc.repo.EnsureNamespace("other", database.VisibilityPrivate); err != nil {
		t.Fatal(err)
	}
	if err := svc.MovePackage("team", "a", "other", "a"); err != nil {
		t.Fatal(err)
	}
	_, _, v, err := svc.Resolve("other", "a", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if got := readUnpacked(t, svc, v); v.UnpackedSize != got || got <= 500 {
		t.Fatalf("unpacked size = %d, archive reads %d", v.UnpackedSize, got)
	}
}

// readUnpacked measures the unpacked size of a version's stored archive.
func readUnpacked(t *testing.T, svc *RegistryService, v *database.PackageVersion) int64 {
	t.Helper()
	f, err := os.Open(svc.blobs.path(v.ArchiveBlobSHA256))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	n, err := archiveUnpackedSize(f)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// TestImportRefusesBundleOverCap: an imported bundle over the cap is refused
// with a warning; the packages it references still import.
func TestImportRefusesBundleOverCap(t *testing.T) {
	src := newTestRegistry(t)
	publishSized(t, src, "team", "a", "1.0.0", 3000)
	publishSized(t, src, "team", "b", "1.0.0", 3000)
	if _, err := publishBundle(src, "team", "kit", "1.0.0", deps("team/a", "team/b")); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := src.ExportBundle(&buf); err != nil {
		t.Fatal(err)
	}
	dst := newTestRegistry(t)
	dst.bundleCap = 5000
	sum, err := dst.ImportBundle(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(sum.Refused) != 1 || sum.Refused[0] != "team/kit" {
		t.Fatalf("refused = %v, want [team/kit]", sum.Refused)
	}
	if !strings.Contains(strings.Join(sum.Warnings, "\n"), "install size limit") {
		t.Fatalf("warnings = %v", sum.Warnings)
	}
	if _, _, v, err := dst.Resolve("team", "a", "1.0.0"); err != nil || v == nil || v.UnpackedSize <= 3000 {
		t.Fatalf("referenced package not imported with its size: %+v, %v", v, err)
	}
}

// TestImportRefusesUpgradeThatBreaksLocalBundle: an imported newer version of a
// package that a local bundle references is refused when it would push that
// bundle over the cap.
func TestImportRefusesUpgradeThatBreaksLocalBundle(t *testing.T) {
	src := newTestRegistry(t)
	publishSized(t, src, "team", "a", "2.0.0", 6000)
	var buf bytes.Buffer
	if err := src.ExportBundle(&buf); err != nil {
		t.Fatal(err)
	}
	dst := newTestRegistry(t)
	dst.bundleCap = 5000
	publishSized(t, dst, "team", "a", "1.0.0", 100)
	if _, err := publishBundle(dst, "team", "kit", "1.0.0", deps("team/a")); err != nil {
		t.Fatal(err)
	}
	sum, err := dst.ImportBundle(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(sum.Refused) != 1 || sum.Refused[0] != "team/a" || !strings.Contains(strings.Join(sum.Warnings, "\n"), "team/kit") {
		t.Fatalf("summary = %+v", sum)
	}
	if _, _, v, err := dst.Resolve("team", "a", "2.0.0"); err == nil {
		t.Fatalf("refused upgrade stored: %+v", v)
	}
}
