package service

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/manifest"
)

// publishPageWithDeps authors a page that names dependencies.
func publishPageWithDeps(svc *RegistryService, ns, name, version string, deps []manifest.Dependency) error {
	_, _, err := svc.AuthorPackage(AuthoredPackage{
		Namespace: ns, Name: name, Type: manifest.TypePage, Version: version,
		Dependencies: deps,
		Files:        map[string][]byte{"content/index.html": []byte("<p>" + name + version + "</p>")},
	})
	return err
}

// TestPublishRejectsTypeChange: a package keeps the type it was created with.
func TestPublishRejectsTypeChange(t *testing.T) {
	svc := newTestRegistry(t)
	publishPage(t, svc, "acme", "thing", "1.0.0")
	_, _, err := svc.AuthorPackage(AuthoredPackage{
		Namespace: "acme", Name: "thing", Type: manifest.TypeEmail, Version: "2.0.0",
		Files: map[string][]byte{"content/email.html": []byte("hi")},
	})
	if !errors.Is(err, ErrTypeMismatch) {
		t.Fatalf("want ErrTypeMismatch, got %v", err)
	}
}

// TestNonBundleDepVisibility: the visibility rule covers every package type, so a
// public page cannot name a private package.
func TestNonBundleDepVisibility(t *testing.T) {
	svc := newTestRegistry(t)
	mustEnsureNS(t, svc, "priv", database.VisibilityPrivate)
	mustEnsureNS(t, svc, "pub", database.VisibilityPublic)
	publishPage(t, svc, "priv", "base", "1.0.0")
	err := publishPageWithDeps(svc, "pub", "page", "1.0.0", []manifest.Dependency{{ID: "priv/base", Range: "^1.0.0"}})
	if err == nil || !strings.Contains(err.Error(), "cannot reference the private package") {
		t.Fatalf("public page with private dep: want rejection, got %v", err)
	}
	// a private page in another namespace cannot name it either.
	mustEnsureNS(t, svc, "other", database.VisibilityPrivate)
	if err := publishPageWithDeps(svc, "other", "page", "1.0.0", []manifest.Dependency{{ID: "priv/base", Range: "^1.0.0"}}); err == nil {
		t.Fatal("private page naming another private namespace was accepted")
	}
	// the same namespace is fine.
	if err := publishPageWithDeps(svc, "priv", "page", "1.0.0", []manifest.Dependency{{ID: "priv/base", Range: "^1.0.0"}}); err != nil {
		t.Fatalf("own namespace dep: %v", err)
	}
}

// TestVisibilityFlipChecksOlderVersions: every version is checked, not only
// latest, since an older version stays installable by its exact number.
func TestVisibilityFlipChecksOlderVersions(t *testing.T) {
	svc := newTestRegistry(t)
	mustEnsureNS(t, svc, "lib", database.VisibilityPublic)
	mustEnsureNS(t, svc, "lib2", database.VisibilityPublic)
	mustEnsureNS(t, svc, "pub", database.VisibilityPublic)
	publishPage(t, svc, "lib", "x", "1.0.0")
	publishPage(t, svc, "lib2", "y", "1.0.0")
	if _, err := publishBundle(svc, "pub", "kit", "1.0.0", []manifest.Dependency{{ID: "lib/x", Range: "^1.0.0"}}); err != nil {
		t.Fatalf("kit 1.0.0: %v", err)
	}
	if _, err := publishBundle(svc, "pub", "kit", "2.0.0", []manifest.Dependency{{ID: "lib2/y", Range: "^1.0.0"}}); err != nil {
		t.Fatalf("kit 2.0.0: %v", err)
	}
	lib, _ := svc.GetNamespace("lib")
	err := svc.UpdateNamespace(lib.ID, "", database.VisibilityPrivate)
	if !errors.Is(err, ErrVisibilityRefused) || !strings.Contains(err.Error(), "pub/kit@1.0.0") {
		t.Fatalf("flip breaking an older version: want refusal naming pub/kit@1.0.0, got %v", err)
	}
	if ns, _ := svc.GetNamespace("lib"); ns.Visibility != database.VisibilityPublic {
		t.Fatal("refused flip was applied")
	}
}

// TestMoveChecksEveryVersion: moving a package into a public namespace is refused
// when any of its versions names a private package.
func TestMoveChecksEveryVersion(t *testing.T) {
	svc := newTestRegistry(t)
	mustEnsureNS(t, svc, "team", database.VisibilityPrivate)
	mustEnsureNS(t, svc, "pub", database.VisibilityPublic)
	publishPage(t, svc, "team", "base", "1.0.0")
	if err := publishPageWithDeps(svc, "team", "page", "1.0.0", []manifest.Dependency{{ID: "team/base", Range: "^1.0.0"}}); err != nil {
		t.Fatalf("page 1.0.0: %v", err)
	}
	publishPage(t, svc, "team", "page", "2.0.0")
	if err := svc.MovePackage("team", "page", "pub", ""); err == nil {
		t.Fatal("move that exposes an older version's private dep was accepted")
	}
	if _, _, _, err := svc.Resolve("team", "page", "latest"); err != nil {
		t.Fatalf("refused move changed the package: %v", err)
	}
}

// TestMoveAbortsOnConcurrentPublish: a version published after the move planned
// its repack aborts the move with a retry error instead of filing that version
// under an address its manifest disagrees with.
func TestMoveAbortsOnConcurrentPublish(t *testing.T) {
	svc := newTestRegistry(t)
	mustEnsureNS(t, svc, "dst", database.VisibilityPrivate)
	publishPage(t, svc, "acme", "thing", "1.0.0")
	svc.beforeRepackCommit = func() {
		svc.beforeRepackCommit = nil
		publishPage(t, svc, "acme", "thing", "1.1.0")
	}
	if err := svc.MovePackage("acme", "thing", "dst", ""); !errors.Is(err, ErrConcurrentChange) {
		t.Fatalf("want ErrConcurrentChange, got %v", err)
	}
	// nothing moved, both versions still resolve under the old address.
	for _, v := range []string{"1.0.0", "1.1.0"} {
		if _, _, _, err := svc.Resolve("acme", "thing", v); err != nil {
			t.Fatalf("version %s lost: %v", v, err)
		}
		if got := manifestIDAt(t, svc, "acme", "thing", v); got != "acme/thing" {
			t.Fatalf("version %s manifest id = %s", v, got)
		}
	}
	// a retry succeeds.
	if err := svc.MovePackage("acme", "thing", "dst", ""); err != nil {
		t.Fatalf("retry: %v", err)
	}
}

// TestRenameAbortsOnConcurrentPublish: the same guard for a namespace rename.
func TestRenameAbortsOnConcurrentPublish(t *testing.T) {
	svc := newTestRegistry(t)
	publishPage(t, svc, "acme", "thing", "1.0.0")
	svc.beforeRepackCommit = func() {
		svc.beforeRepackCommit = nil
		publishPage(t, svc, "acme", "other", "1.0.0")
	}
	if err := svc.RenameNamespace("acme", "acme2"); !errors.Is(err, ErrConcurrentChange) {
		t.Fatalf("want ErrConcurrentChange, got %v", err)
	}
	if _, err := svc.GetNamespace("acme"); err != nil {
		t.Fatalf("namespace renamed despite the abort: %v", err)
	}
	if err := svc.RenameNamespace("acme", "acme2"); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if got := manifestIDAt(t, svc, "acme2", "other", "1.0.0"); got != "acme2/other" {
		t.Fatalf("other manifest id = %s", got)
	}
}

// TestDeleteNamespaceDropsTokenScope: a deleted namespace is removed from every
// token scope, so a namespace created later under the same name is not readable
// by an old token.
func TestDeleteNamespaceDropsTokenScope(t *testing.T) {
	db := newTestDB(t)
	svc := registryOverDB(t, db)
	ns := mustEnsureNS(t, svc, "acme", database.VisibilityPrivate)
	tok := database.Token{TokenHash: strings.Repeat("a", 64), Name: "t", Entitlements: `["acme","other"]`}
	wild := database.Token{TokenHash: strings.Repeat("b", 64), Name: "w", Entitlements: `["*"]`}
	if err := db.Create(&tok).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&wild).Error; err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteNamespace(ns.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	var got database.Token
	if err := db.Where("id = ?", tok.ID).First(&got).Error; err != nil {
		t.Fatal(err)
	}
	if got.Entitlements != `["other"]` {
		t.Fatalf("entitlements = %s", got.Entitlements)
	}
	var gotWild database.Token
	if err := db.Where("id = ?", wild.ID).First(&gotWild).Error; err != nil || gotWild.Entitlements != `["*"]` {
		t.Fatalf("wildcard token changed: %s %v", gotWild.Entitlements, err)
	}
}

// TestDeleteNamespaceNotEmpty: a namespace with packages is kept.
func TestDeleteNamespaceNotEmpty(t *testing.T) {
	svc := newTestRegistry(t)
	publishPage(t, svc, "acme", "thing", "1.0.0")
	ns, _ := svc.GetNamespace("acme")
	if err := svc.DeleteNamespace(ns.ID); !errors.Is(err, ErrNamespaceNotEmpty) {
		t.Fatalf("want ErrNamespaceNotEmpty, got %v", err)
	}
}

// TestBlobPinBlocksCleanup: a blob put by an operation that has not written its
// row yet survives a concurrent cleanup, and is removable once released.
func TestBlobPinBlocksCleanup(t *testing.T) {
	svc := newTestRegistry(t)
	sha, _, err := svc.blobs.Put(bytes.NewReader([]byte("in flight")), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	svc.cleanupBlob(sha)
	if !svc.blobs.Exists(sha) {
		t.Fatal("cleanup removed a pinned blob")
	}
	// a second Put of the same bytes pins it again; one release is not enough.
	if _, _, err := svc.blobs.Put(bytes.NewReader([]byte("in flight")), 1<<20); err != nil {
		t.Fatal(err)
	}
	svc.blobs.Release(sha)
	svc.cleanupBlob(sha)
	if !svc.blobs.Exists(sha) {
		t.Fatal("cleanup removed a blob still pinned by a second Put")
	}
	svc.blobs.Release(sha)
	svc.cleanupBlob(sha)
	if svc.blobs.Exists(sha) {
		t.Fatal("unreferenced released blob was not cleaned up")
	}
}

// TestPublishReleasesPins: a publish, successful or rejected, leaves no pin.
func TestPublishReleasesPins(t *testing.T) {
	svc := newTestRegistry(t)
	v := publishPage(t, svc, "acme", "thing", "1.0.0")
	if svc.blobs.isPinned(v.ArchiveBlobSHA256) {
		t.Fatal("published blob still pinned")
	}
	// the duplicate publish is rejected and its (deduped) blob stays referenced.
	_, _, err := svc.AuthorPackage(AuthoredPackage{
		Namespace: "acme", Name: "thing", Type: manifest.TypePage, Version: "1.0.0", Title: "thing",
		Files: map[string][]byte{"content/index.html": []byte("<h1>thing 1.0.0</h1>")},
	})
	if !errors.Is(err, ErrVersionExists) {
		t.Fatalf("want ErrVersionExists, got %v", err)
	}
	if svc.blobs.isPinned(v.ArchiveBlobSHA256) || !svc.blobs.Exists(v.ArchiveBlobSHA256) {
		t.Fatal("rejected duplicate publish disturbed the stored blob")
	}
}
