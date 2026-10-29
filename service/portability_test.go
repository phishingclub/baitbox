package service

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/manifest"
)

func bundleSha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// makeBundleTar writes an export bundle (registry.json first, then blobs) as a
// tar.gz, so a test can hand-craft a malicious or inconsistent bundle the
// exporter would never produce.
func makeBundleTar(t *testing.T, b exportBundle, blobs map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	write := func(name string, data []byte) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	meta, err := json.Marshal(&b)
	if err != nil {
		t.Fatal(err)
	}
	write(registryFileName, meta)
	for sha, data := range blobs {
		write("blobs/"+sha, data)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExportImportRoundTripIdempotent(t *testing.T) {
	src := newTestRegistry(t)
	publishPage(t, src, "acme", "thing", "1.0.0")
	var buf bytes.Buffer
	if err := src.ExportBundle(&buf); err != nil {
		t.Fatalf("export: %v", err)
	}
	bundleBytes := buf.Bytes()

	dst := newTestRegistry(t)
	sum, err := dst.ImportBundle(bytes.NewReader(bundleBytes))
	if err != nil {
		t.Fatalf("import 1: %v", err)
	}
	if sum.Namespaces != 1 || sum.Packages != 1 || sum.Versions != 1 {
		t.Fatalf("import 1 summary = %+v", sum)
	}
	if _, _, v, rerr := dst.Resolve("acme", "thing", "1.0.0"); rerr != nil || v == nil {
		t.Fatalf("imported version missing: %v", rerr)
	}

	// re-import is idempotent: nothing new added, the package is skipped.
	sum2, err := dst.ImportBundle(bytes.NewReader(bundleBytes))
	if err != nil {
		t.Fatalf("import 2: %v", err)
	}
	if sum2.Packages != 0 || sum2.Versions != 0 || sum2.Namespaces != 0 {
		t.Fatalf("re-import added rows: %+v", sum2)
	}
	if len(sum2.Skipped) != 1 || sum2.Skipped[0] != "acme/thing" {
		t.Fatalf("re-import skipped = %v", sum2.Skipped)
	}
}

func TestImportSkipDoesNotClobberLocalMeta(t *testing.T) {
	src := newTestRegistry(t)
	publishPage(t, src, "acme", "thing", "1.0.0")
	var buf bytes.Buffer
	if err := src.ExportBundle(&buf); err != nil {
		t.Fatalf("export: %v", err)
	}

	dst := newTestRegistry(t)
	if _, err := dst.ImportBundle(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("import: %v", err)
	}
	// an operator edits the local metadata after importing.
	if err := dst.UpdatePackageMeta("acme", "thing", "Local Title", "local desc", "local"); err != nil {
		t.Fatalf("edit meta: %v", err)
	}
	// re-importing the same (not newer) bundle must not overwrite those edits.
	if _, err := dst.ImportBundle(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("re-import: %v", err)
	}
	_, pkg, _, err := dst.Resolve("acme", "thing", "latest")
	if err != nil {
		t.Fatal(err)
	}
	if pkg.Title != "Local Title" || pkg.Description != "local desc" || pkg.Tags != "local" {
		t.Fatalf("local meta clobbered: title=%q desc=%q tags=%q", pkg.Title, pkg.Description, pkg.Tags)
	}
}

func TestImportUpgradesOnNewerVersion(t *testing.T) {
	// a bundle carrying only 1.0.0 is imported first.
	src1 := newTestRegistry(t)
	publishPage(t, src1, "acme", "thing", "1.0.0")
	var buf1 bytes.Buffer
	if err := src1.ExportBundle(&buf1); err != nil {
		t.Fatalf("export 1: %v", err)
	}
	dst := newTestRegistry(t)
	if _, err := dst.ImportBundle(bytes.NewReader(buf1.Bytes())); err != nil {
		t.Fatalf("import 1: %v", err)
	}

	// a later bundle carries a newer version.
	src2 := newTestRegistry(t)
	publishPage(t, src2, "acme", "thing", "1.0.0")
	publishPage(t, src2, "acme", "thing", "1.1.0")
	var buf2 bytes.Buffer
	if err := src2.ExportBundle(&buf2); err != nil {
		t.Fatalf("export 2: %v", err)
	}
	sum, err := dst.ImportBundle(bytes.NewReader(buf2.Bytes()))
	if err != nil {
		t.Fatalf("import 2: %v", err)
	}
	if len(sum.Upgraded) != 1 || sum.Upgraded[0] != "acme/thing" {
		t.Fatalf("upgrade list = %v", sum.Upgraded)
	}
	if sum.Versions != 1 { // only the newly added 1.1.0
		t.Fatalf("versions added = %d, want 1", sum.Versions)
	}
	if _, _, v, rerr := dst.Resolve("acme", "thing", "latest"); rerr != nil || v.Version != "1.1.0" {
		t.Fatalf("latest after upgrade = %v (err %v)", v, rerr)
	}
}

// requireOnlyRefused imports tarball into dst and requires the import to succeed
// with key as its only refused package, nothing written and no namespace made.
func requireOnlyRefused(t *testing.T, dst *RegistryService, tarball []byte, key string) *ImportSummary {
	t.Helper()
	sum, err := dst.ImportBundle(bytes.NewReader(tarball))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(sum.Refused) != 1 || sum.Refused[0] != key || sum.Packages != 0 || sum.Versions != 0 || sum.Namespaces != 0 {
		t.Fatalf("summary = %+v", sum)
	}
	if len(sum.Warnings) == 0 || !strings.HasPrefix(sum.Warnings[len(sum.Warnings)-1], key+": ") {
		t.Fatalf("warnings = %v", sum.Warnings)
	}
	ns, _, _ := splitID(key)
	if _, err := dst.GetNamespace(ns); err == nil {
		t.Fatal("a namespace whose packages were all refused must not be created")
	}
	return sum
}

// TestImportRejectsArchiveIdentityMismatch: a crafted bundle that files a valid
// archive under an address that disagrees with the archive's own manifest id is
// refused.
func TestImportRejectsArchiveIdentityMismatch(t *testing.T) {
	archive, _, err := BuildArchive(PackageSpec{ID: "acme/base", Type: manifest.TypePage, Version: "1.0.0"},
		map[string][]byte{"content/index.html": []byte("hi")})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	sha := bundleSha(archive)
	b := exportBundle{
		Format:     bundleFormat,
		Namespaces: []nsDTO{{Name: "acme", Visibility: database.VisibilityPrivate}},
		Packages:   []pkgDTO{{Namespace: "acme", Name: "other", Type: manifest.TypePage}},
		Versions: []verDTO{{
			Namespace: "acme", Name: "other", Version: "1.0.0",
			ArchiveSha: sha, Size: int64(len(archive)),
		}},
	}
	tarball := makeBundleTar(t, b, map[string][]byte{sha: archive})

	dst := newTestRegistry(t)
	requireOnlyRefused(t, dst, tarball, "acme/other")
}

// TestImportRejectsVersionStringMismatch: the bundle's version string must equal
// the verified archive manifest's version, so a hand edited bundle cannot claim a
// different version than the archive it ships.
func TestImportRejectsVersionStringMismatch(t *testing.T) {
	archive, _, err := BuildArchive(PackageSpec{ID: "acme/base", Type: manifest.TypePage, Version: "1.0.0"},
		map[string][]byte{"content/index.html": []byte("hi")})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	sha := bundleSha(archive)
	b := exportBundle{
		Format:     bundleFormat,
		Namespaces: []nsDTO{{Name: "acme", Visibility: database.VisibilityPrivate}},
		Packages:   []pkgDTO{{Namespace: "acme", Name: "base", Type: manifest.TypePage}},
		Versions: []verDTO{{
			Namespace: "acme", Name: "base",
			// the bundle lies: claims 9.9.9 and a bogus size.
			Version: "9.9.9", ArchiveSha: sha, Size: 99999,
		}},
	}
	tarball := makeBundleTar(t, b, map[string][]byte{sha: archive})

	dst := newTestRegistry(t)
	requireOnlyRefused(t, dst, tarball, "acme/base")
	// the shipped blob is reclaimed and holds no pin.
	if dst.blobs.Exists(sha) || dst.blobs.isPinned(sha) {
		t.Fatal("rejected bundle left its blob behind")
	}
}

// TestImportStoresSizeFromBlob: the stored size is the real blob size, never the
// bundle's claim.
func TestImportStoresSizeFromBlob(t *testing.T) {
	archive, _, err := BuildArchive(PackageSpec{ID: "acme/base", Type: manifest.TypePage, Version: "1.0.0"},
		map[string][]byte{"content/index.html": []byte("hi")})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	sha := bundleSha(archive)
	b := exportBundle{
		Format:     bundleFormat,
		Namespaces: []nsDTO{{Name: "acme", Visibility: database.VisibilityPrivate}},
		Packages:   []pkgDTO{{Namespace: "acme", Name: "base", Type: manifest.TypePage}},
		Versions:   []verDTO{{Namespace: "acme", Name: "base", Version: "1.0.0", ArchiveSha: sha, Size: 99999}},
	}
	dst := newTestRegistry(t)
	if _, err := dst.ImportBundle(bytes.NewReader(makeBundleTar(t, b, map[string][]byte{sha: archive}))); err != nil {
		t.Fatalf("import: %v", err)
	}
	_, _, v, rerr := dst.Resolve("acme", "base", "1.0.0")
	if rerr != nil {
		t.Fatalf("resolve: %v", rerr)
	}
	if v.Size != int64(len(archive)) {
		t.Fatalf("size = %d, want %d", v.Size, len(archive))
	}
}

// singlePageBundle builds a one package bundle around a freshly built archive.
func singlePageBundle(t *testing.T, ns, nsVis, name, pkgType, archiveType, version string, deps []manifest.Dependency) ([]byte, string) {
	t.Helper()
	files := map[string][]byte{"content/index.html": []byte("hi " + name)}
	archive, _, err := BuildArchive(PackageSpec{ID: ns + "/" + name, Type: archiveType, Version: version, Dependencies: deps}, files)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	sha := bundleSha(archive)
	b := exportBundle{
		Format:     bundleFormat,
		Namespaces: []nsDTO{{Name: ns, Visibility: nsVis}},
		Packages:   []pkgDTO{{Namespace: ns, Name: name, Type: pkgType}},
		Versions:   []verDTO{{Namespace: ns, Name: name, Version: version, ArchiveSha: sha}},
	}
	return makeBundleTar(t, b, map[string][]byte{sha: archive}), sha
}

// TestImportRefusesPrivateIntoPublicNamespace: a bundle that marks a namespace
// private must never file its content into a local namespace that is public.
func TestImportRefusesPrivateIntoPublicNamespace(t *testing.T) {
	dst := newTestRegistry(t)
	mustEnsureNS(t, dst, "acme", database.VisibilityPublic)
	tarball, sha := singlePageBundle(t, "acme", database.VisibilityPrivate, "secret", manifest.TypePage, manifest.TypePage, "1.0.0", nil)
	sum, err := dst.ImportBundle(bytes.NewReader(tarball))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(sum.Refused) != 1 || sum.Refused[0] != "acme/secret" || len(sum.Warnings) != 1 {
		t.Fatalf("summary = %+v", sum)
	}
	if sum.Packages != 0 || sum.Versions != 0 {
		t.Fatalf("refused package was written: %+v", sum)
	}
	if _, _, _, rerr := dst.Resolve("acme", "secret", "latest"); !errors.Is(rerr, ErrNotFound) {
		t.Fatalf("private package became reachable in a public namespace: %v", rerr)
	}
	if dst.blobs.Exists(sha) {
		t.Fatal("refused package blob not reclaimed")
	}
	// a bundle visibility that is not exactly public reads as private too.
	tarball2, _ := singlePageBundle(t, "acme", "PUBLIC", "secret", manifest.TypePage, manifest.TypePage, "1.0.0", nil)
	sum2, err := dst.ImportBundle(bytes.NewReader(tarball2))
	if err != nil || len(sum2.Refused) != 1 {
		t.Fatalf("odd visibility: sum=%+v err=%v", sum2, err)
	}
}

// TestImportPublicIntoPrivateNamespaceAllowed: content only ever gets more
// private, so a public bundle namespace that is private here imports fine.
func TestImportPublicIntoPrivateNamespaceAllowed(t *testing.T) {
	dst := newTestRegistry(t)
	mustEnsureNS(t, dst, "acme", database.VisibilityPrivate)
	tarball, _ := singlePageBundle(t, "acme", database.VisibilityPublic, "open", manifest.TypePage, manifest.TypePage, "1.0.0", nil)
	sum, err := dst.ImportBundle(bytes.NewReader(tarball))
	if err != nil || sum.Packages != 1 || len(sum.Refused) != 0 {
		t.Fatalf("sum=%+v err=%v", sum, err)
	}
	if ns, _ := dst.GetNamespace("acme"); ns.Visibility != database.VisibilityPrivate {
		t.Fatalf("import changed local visibility to %s", ns.Visibility)
	}
}

// TestImportNewNamespaceNormalisesVisibility: a namespace created by import gets
// public only for the exact value, anything else is private.
func TestImportNewNamespaceNormalisesVisibility(t *testing.T) {
	dst := newTestRegistry(t)
	tarball, _ := singlePageBundle(t, "acme", "everyone", "p", manifest.TypePage, manifest.TypePage, "1.0.0", nil)
	if _, err := dst.ImportBundle(bytes.NewReader(tarball)); err != nil {
		t.Fatalf("import: %v", err)
	}
	if ns, _ := dst.GetNamespace("acme"); ns == nil || ns.Visibility != database.VisibilityPrivate {
		t.Fatalf("visibility = %v", ns)
	}
}

// TestImportRefusesTypeMismatch: an existing package keeps its type; a bundle
// that carries a package of the same address but another type is refused.
func TestImportRefusesTypeMismatch(t *testing.T) {
	dst := newTestRegistry(t)
	publishPage(t, dst, "acme", "thing", "1.0.0")
	tarball, _ := singlePageBundle(t, "acme", database.VisibilityPrivate, "thing", manifest.TypeEmail, manifest.TypeEmail, "2.0.0", nil)
	sum, err := dst.ImportBundle(bytes.NewReader(tarball))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(sum.Refused) != 1 || sum.Versions != 0 {
		t.Fatalf("summary = %+v", sum)
	}
	if _, _, v, _ := dst.Resolve("acme", "thing", "latest"); v.Version != "1.0.0" {
		t.Fatalf("latest = %s", v.Version)
	}
}

// TestImportRejectsArchiveTypeMismatch: the archive's own type must equal the
// package type the bundle files it under.
func TestImportRejectsArchiveTypeMismatch(t *testing.T) {
	dst := newTestRegistry(t)
	tarball, _ := singlePageBundle(t, "acme", database.VisibilityPrivate, "thing", manifest.TypeEmail, manifest.TypePage, "1.0.0", nil)
	requireOnlyRefused(t, dst, tarball, "acme/thing")
}

// TestImportRejectsInvalidPackageType: a package type outside the known set is
// rejected.
func TestImportRejectsInvalidPackageType(t *testing.T) {
	dst := newTestRegistry(t)
	tarball, _ := singlePageBundle(t, "acme", database.VisibilityPrivate, "thing", "rootkit", manifest.TypePage, "1.0.0", nil)
	if _, err := dst.ImportBundle(bytes.NewReader(tarball)); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("want ErrInvalidBundle, got %v", err)
	}
}

// TestImportRejectsUndeclaredNamespace: a package must live in a namespace the
// bundle declares, so its visibility is known.
func TestImportRejectsUndeclaredNamespace(t *testing.T) {
	archive, _, err := BuildArchive(PackageSpec{ID: "acme/base", Type: manifest.TypePage, Version: "1.0.0"},
		map[string][]byte{"content/index.html": []byte("hi")})
	if err != nil {
		t.Fatal(err)
	}
	sha := bundleSha(archive)
	b := exportBundle{
		Format:   bundleFormat,
		Packages: []pkgDTO{{Namespace: "acme", Name: "base", Type: manifest.TypePage}},
		Versions: []verDTO{{Namespace: "acme", Name: "base", Version: "1.0.0", ArchiveSha: sha}},
	}
	dst := newTestRegistry(t)
	mustEnsureNS(t, dst, "acme", database.VisibilityPublic)
	if _, err := dst.ImportBundle(bytes.NewReader(makeBundleTar(t, b, map[string][]byte{sha: archive}))); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("want ErrInvalidBundle, got %v", err)
	}
}

// TestImportRefusesPublicPackageWithPrivateDep: imported versions go through the
// same dependency visibility rule as publish.
func TestImportRefusesPublicPackageWithPrivateDep(t *testing.T) {
	dst := newTestRegistry(t)
	mustEnsureNS(t, dst, "secret", database.VisibilityPrivate)
	publishPage(t, dst, "secret", "lure", "1.0.0")
	deps := []manifest.Dependency{{ID: "secret/lure", Range: "^1.0.0"}}
	tarball, _ := singlePageBundle(t, "open", database.VisibilityPublic, "kit", manifest.TypeBundle, manifest.TypeBundle, "1.0.0", deps)
	sum, err := dst.ImportBundle(bytes.NewReader(tarball))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(sum.Refused) != 1 || sum.Refused[0] != "open/kit" {
		t.Fatalf("summary = %+v", sum)
	}
	if _, _, _, rerr := dst.Resolve("open", "kit", "latest"); !errors.Is(rerr, ErrNotFound) {
		t.Fatalf("refused bundle was stored: %v", rerr)
	}
}

// TestImportDepOnPackageInSameBundle: a bundle may depend on a package the same
// import brings in.
func TestImportDepOnPackageInSameBundle(t *testing.T) {
	src := newTestRegistry(t)
	mustEnsureNS(t, src, "acme", database.VisibilityPublic)
	publishPage(t, src, "acme", "lure", "1.0.0")
	if _, err := publishBundle(src, "acme", "kit", "1.0.0", []manifest.Dependency{{ID: "acme/lure", Range: "^1.0.0"}}); err != nil {
		t.Fatalf("publish bundle: %v", err)
	}
	var buf bytes.Buffer
	if err := src.ExportBundle(&buf); err != nil {
		t.Fatal(err)
	}
	dst := newTestRegistry(t)
	sum, err := dst.ImportBundle(bytes.NewReader(buf.Bytes()))
	if err != nil || sum.Packages != 2 || len(sum.Refused) != 0 {
		t.Fatalf("sum=%+v err=%v", sum, err)
	}
}

// TestImportRejectsVersionWithMissingBlob: a version that references an archive
// sha not shipped in the bundle refuses its package before any write.
func TestImportRejectsVersionWithMissingBlob(t *testing.T) {
	b := exportBundle{
		Format:     bundleFormat,
		Namespaces: []nsDTO{{Name: "acme", Visibility: database.VisibilityPrivate}},
		Packages:   []pkgDTO{{Namespace: "acme", Name: "base", Type: manifest.TypePage}},
		Versions: []verDTO{{
			Namespace: "acme", Name: "base", Version: "1.0.0",
			ArchiveSha: bundleSha([]byte("not shipped")),
		}},
	}
	tarball := makeBundleTar(t, b, nil)
	dst := newTestRegistry(t)
	requireOnlyRefused(t, dst, tarball, "acme/base")
}

// TestImportNormalisesNamespaceColor: an imported namespace color goes through
// the admin allowlist; a value outside it is cleared with a warning.
func TestImportNormalisesNamespaceColor(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		warn     bool
	}{
		{"red", "red", false},
		{"#AABBCC", "#aabbcc", false},
		{"red; background:url(//x)", "", true},
		{"", "", false},
	} {
		dst := newTestRegistry(t)
		files := map[string][]byte{"content/index.html": []byte("hi")}
		archive, _, err := BuildArchive(PackageSpec{ID: "acme/p", Type: manifest.TypePage, Version: "1.0.0"}, files)
		if err != nil {
			t.Fatal(err)
		}
		sha := bundleSha(archive)
		b := exportBundle{
			Format:     bundleFormat,
			Namespaces: []nsDTO{{Name: "acme", Visibility: database.VisibilityPrivate, Color: tc.in}},
			Packages:   []pkgDTO{{Namespace: "acme", Name: "p", Type: manifest.TypePage}},
			Versions:   []verDTO{{Namespace: "acme", Name: "p", Version: "1.0.0", ArchiveSha: sha}},
		}
		sum, err := dst.ImportBundle(bytes.NewReader(makeBundleTar(t, b, map[string][]byte{sha: archive})))
		if err != nil {
			t.Fatalf("%q: import: %v", tc.in, err)
		}
		ns, _ := dst.GetNamespace("acme")
		if ns == nil || ns.Color != tc.want {
			t.Fatalf("%q: stored color = %v, want %q", tc.in, ns, tc.want)
		}
		if (len(sum.Warnings) > 0) != tc.warn {
			t.Fatalf("%q: warnings = %v", tc.in, sum.Warnings)
		}
	}
}

// TestImportPackageMetaRules: imported title and description get the admin caps
// and the tags the admin cleanup; too many previews are rejected.
func TestImportPackageMetaRules(t *testing.T) {
	build := func(p pkgDTO) []byte {
		files := map[string][]byte{"content/index.html": []byte("hi")}
		archive, _, err := BuildArchive(PackageSpec{ID: "acme/p", Type: manifest.TypePage, Version: "1.0.0"}, files)
		if err != nil {
			t.Fatal(err)
		}
		sha := bundleSha(archive)
		p.Namespace, p.Name, p.Type = "acme", "p", manifest.TypePage
		b := exportBundle{
			Format:     bundleFormat,
			Namespaces: []nsDTO{{Name: "acme", Visibility: database.VisibilityPrivate}},
			Packages:   []pkgDTO{p},
			Versions:   []verDTO{{Namespace: "acme", Name: "p", Version: "1.0.0", ArchiveSha: sha}},
		}
		return makeBundleTar(t, b, map[string][]byte{sha: archive})
	}
	dst := newTestRegistry(t)
	if _, err := dst.ImportBundle(bytes.NewReader(build(pkgDTO{Title: strings.Repeat("t", 300)}))); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("long title: err = %v", err)
	}
	if _, err := dst.ImportBundle(bytes.NewReader(build(pkgDTO{Description: strings.Repeat("d", 5000)}))); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("long description: err = %v", err)
	}
	var many []previewDTO
	for i := 0; i <= MaxPreviewImages; i++ {
		many = append(many, previewDTO{Sha: strings.Repeat("a", 64), MediaType: "image/png", Position: i})
	}
	if _, err := dst.ImportBundle(bytes.NewReader(build(pkgDTO{Title: "x", Previews: many}))); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("too many previews: err = %v", err)
	}
	if _, err := dst.ImportBundle(bytes.NewReader(build(pkgDTO{Title: " Nice ", Tags: " B,a, ,A ,b"}))); err != nil {
		t.Fatalf("import: %v", err)
	}
	_, pkg, _, err := dst.Resolve("acme", "p", "latest")
	if err != nil {
		t.Fatal(err)
	}
	if pkg.Title != "Nice" || pkg.Tags != "b,a" {
		t.Fatalf("title=%q tags=%q", pkg.Title, pkg.Tags)
	}
}

// TestImportNamespaceListedTwiceKeepsPrivate: a namespace listed twice with
// conflicting visibility is created private, and a package with no versions is
// refused rather than left as an empty row.
func TestImportNamespaceListedTwiceKeepsPrivate(t *testing.T) {
	dst := newTestRegistry(t)
	files := map[string][]byte{"content/index.html": []byte("hi")}
	archive, _, err := BuildArchive(PackageSpec{ID: "acme/p", Type: manifest.TypePage, Version: "1.0.0"}, files)
	if err != nil {
		t.Fatal(err)
	}
	sha := bundleSha(archive)
	b := exportBundle{
		Format: bundleFormat,
		Namespaces: []nsDTO{
			{Name: "acme", Visibility: database.VisibilityPrivate},
			{Name: "acme", Visibility: database.VisibilityPublic},
		},
		Packages: []pkgDTO{
			{Namespace: "acme", Name: "p", Type: manifest.TypePage},
			{Namespace: "acme", Name: "empty", Type: manifest.TypePage},
		},
		Versions: []verDTO{{Namespace: "acme", Name: "p", Version: "1.0.0", ArchiveSha: sha}},
	}
	sum, err := dst.ImportBundle(bytes.NewReader(makeBundleTar(t, b, map[string][]byte{sha: archive})))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if ns, _ := dst.GetNamespace("acme"); ns == nil || ns.Visibility != database.VisibilityPrivate {
		t.Fatalf("namespace = %+v", ns)
	}
	if len(sum.Refused) != 1 || sum.Refused[0] != "acme/empty" {
		t.Fatalf("summary = %+v", sum)
	}
	if ns, _ := dst.GetNamespace("acme"); ns != nil {
		if p, _ := dst.repo.GetPackage(ns.ID, "empty"); p != nil {
			t.Fatal("empty package row was written")
		}
	}
	// a namespace name with upper case is rejected, so no case variant can alias.
	b.Namespaces = []nsDTO{{Name: "Acme", Visibility: database.VisibilityPublic}}
	if _, err := dst.ImportBundle(bytes.NewReader(makeBundleTar(t, b, map[string][]byte{sha: archive}))); !errors.Is(err, ErrInvalidBundle) {
		t.Fatalf("upper case namespace: err = %v", err)
	}
}

// tagColorMap returns every tag color row of svc keyed by tag name.
func tagColorMap(t *testing.T, svc *RegistryService) map[string]string {
	t.Helper()
	tags, err := svc.ListTags()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for i := range tags {
		out[tags[i].Name] = tags[i].Color
	}
	return out
}

// TestExportImportKeepsPackageMetaAndTagColors: the editable package details
// (title, description, tags) and the tag colors survive an export and import.
// A tag that already has a color locally keeps it, and a color outside the
// allowlist is dropped with a warning.
func TestExportImportKeepsPackageMetaAndTagColors(t *testing.T) {
	src := newTestRegistry(t)
	publishPage(t, src, "acme", "thing", "1.0.0")
	if err := src.UpdatePackageMeta("acme", "thing", "Edited Title", "edited desc", "o365,urgent,plain"); err != nil {
		t.Fatalf("edit meta: %v", err)
	}
	if err := src.SetTagColor("o365", "red"); err != nil {
		t.Fatalf("tag color: %v", err)
	}
	if err := src.SetTagColor("urgent", "#1a2b3c"); err != nil {
		t.Fatalf("tag color: %v", err)
	}
	var buf bytes.Buffer
	if err := src.ExportBundle(&buf); err != nil {
		t.Fatalf("export: %v", err)
	}

	dst := newTestRegistry(t)
	if _, err := dst.ImportBundle(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("import: %v", err)
	}
	_, pkg, _, err := dst.Resolve("acme", "thing", "latest")
	if err != nil {
		t.Fatal(err)
	}
	if pkg.Title != "Edited Title" || pkg.Description != "edited desc" || pkg.Tags != "o365,urgent,plain" {
		t.Fatalf("meta not kept: title=%q desc=%q tags=%q", pkg.Title, pkg.Description, pkg.Tags)
	}
	got := tagColorMap(t, dst)
	if got["o365"] != "red" || got["urgent"] != "#1a2b3c" || got["plain"] != "" {
		t.Fatalf("tag colors = %v", got)
	}

	// a single package export carries the colors of that package's tags too.
	var pbuf bytes.Buffer
	if err := src.ExportPackageBundle(&pbuf, "acme", "thing", false); err != nil {
		t.Fatalf("package export: %v", err)
	}
	dst2 := newTestRegistry(t)
	if _, err := dst2.ImportBundle(bytes.NewReader(pbuf.Bytes())); err != nil {
		t.Fatalf("package import: %v", err)
	}
	if got := tagColorMap(t, dst2); got["o365"] != "red" || got["urgent"] != "#1a2b3c" {
		t.Fatalf("package bundle tag colors = %v", got)
	}

	// a local color is kept, an unknown color is dropped with a warning, and a
	// color for a tag no package carries is ignored.
	dst3 := newTestRegistry(t)
	publishPage(t, dst3, "local", "other", "1.0.0")
	if err := dst3.UpdatePackageMeta("local", "other", "", "", "o365"); err != nil {
		t.Fatal(err)
	}
	if err := dst3.SetTagColor("o365", "blue"); err != nil {
		t.Fatal(err)
	}
	var b exportBundle
	if err := json.Unmarshal(registryJSON(t, buf.Bytes()), &b); err != nil {
		t.Fatal(err)
	}
	b.TagColors = append(b.TagColors, tagColorDTO{Name: "plain", Color: "url(evil)"}, tagColorDTO{Name: "ghost", Color: "green"})
	blobs := bundleBlobs(t, buf.Bytes())
	sum, err := dst3.ImportBundle(bytes.NewReader(makeBundleTar(t, b, blobs)))
	if err != nil {
		t.Fatalf("crafted import: %v", err)
	}
	got = tagColorMap(t, dst3)
	if got["o365"] != "blue" || got["urgent"] != "#1a2b3c" || got["plain"] != "" {
		t.Fatalf("crafted import tag colors = %v", got)
	}
	if _, ok := got["ghost"]; ok {
		t.Fatal("a tag no package carries got a color row")
	}
	if len(sum.Warnings) != 1 || !strings.Contains(sum.Warnings[0], "tag plain") {
		t.Fatalf("warnings = %v", sum.Warnings)
	}

	// a package that is skipped writes no tags, so a local tag it shares gets no
	// color from the bundle.
	dst4 := newTestRegistry(t)
	publishPage(t, dst4, "acme", "thing", "1.0.0")
	if err := dst4.UpdatePackageMeta("acme", "thing", "", "", "urgent"); err != nil {
		t.Fatal(err)
	}
	sum, err = dst4.ImportBundle(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("skip import: %v", err)
	}
	if len(sum.Skipped) != 1 {
		t.Fatalf("summary = %+v", sum)
	}
	if got := tagColorMap(t, dst4); got["urgent"] != "" {
		t.Fatalf("skipped package colored a local tag: %v", got)
	}
}

// readBundleTar returns every regular file of an export bundle by name.
func readBundleTar(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		out[hdr.Name] = body
	}
	return out
}

// registryJSON returns the registry.json of an export bundle.
func registryJSON(t *testing.T, data []byte) []byte {
	t.Helper()
	return readBundleTar(t, data)[registryFileName]
}

// bundleBlobs returns the blobs of an export bundle keyed by sha.
func bundleBlobs(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for name, body := range readBundleTar(t, data) {
		if strings.HasPrefix(name, "blobs/") {
			out[strings.TrimPrefix(name, "blobs/")] = body
		}
	}
	return out
}
