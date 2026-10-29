package service

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/manifest"
	"github.com/phishingclub/baitbox/repository"
)

// manifestIDAt resolves a version and returns the id recorded in its archive's
// manifest, so a test can confirm a move repacked the archive under the new
// address (not just moved the row).
func manifestIDAt(t *testing.T, svc *RegistryService, ns, name, version string) string {
	t.Helper()
	_, m, _, err := svc.VersionContent(ns, name, version)
	if err != nil {
		t.Fatalf("version content %s/%s@%s: %v", ns, name, version, err)
	}
	return m.ID
}

func TestMovePackageRepacksAllVersions(t *testing.T) {
	svc := newTestRegistry(t)
	mustEnsureNS(t, svc, "acme", database.VisibilityPrivate)
	mustEnsureNS(t, svc, "dst", database.VisibilityPrivate)
	v1 := publishPage(t, svc, "acme", "thing", "1.0.0")
	v2 := publishPage(t, svc, "acme", "thing", "2.0.0")
	oldBlobs := []string{v1.ArchiveBlobSHA256, v2.ArchiveBlobSHA256}

	if err := svc.MovePackage("acme", "thing", "dst", "renamed"); err != nil {
		t.Fatalf("move: %v", err)
	}

	// resolves at the new address, both versions, each repacked under the new id.
	for _, ver := range []string{"1.0.0", "2.0.0"} {
		if _, _, _, err := svc.Resolve("dst", "renamed", ver); err != nil {
			t.Fatalf("resolve new %s: %v", ver, err)
		}
		if id := manifestIDAt(t, svc, "dst", "renamed", ver); id != "dst/renamed" {
			t.Fatalf("manifest id at %s = %q, want dst/renamed", ver, id)
		}
	}

	// the old address 404s for the package and the namespace entry.
	if _, _, _, err := svc.Resolve("acme", "thing", "1.0.0"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old address still resolves: %v", err)
	}

	// every superseded blob is reclaimed (no leak), and the new blobs are
	// referenced (not double-freed). The id changed, so each repack produced a new
	// distinct sha.
	for _, old := range oldBlobs {
		if svc.blobs.Exists(old) {
			t.Fatalf("old blob %s leaked after move", old)
		}
		if ref, _ := svc.repo.BlobReferenced(old); ref {
			t.Fatalf("old blob %s still referenced after move", old)
		}
	}
	for _, ver := range []string{"1.0.0", "2.0.0"} {
		_, _, nv, err := svc.Resolve("dst", "renamed", ver)
		if err != nil {
			t.Fatal(err)
		}
		if ref, _ := svc.repo.BlobReferenced(nv.ArchiveBlobSHA256); !ref {
			t.Fatalf("new blob for %s not referenced", ver)
		}
		if !svc.blobs.Exists(nv.ArchiveBlobSHA256) {
			t.Fatalf("new blob for %s missing on disk", ver)
		}
	}
}

func TestMovePackageTargetConflicts(t *testing.T) {
	svc := newTestRegistry(t)
	mustEnsureNS(t, svc, "acme", database.VisibilityPrivate)
	mustEnsureNS(t, svc, "dst", database.VisibilityPrivate)
	publishPage(t, svc, "acme", "thing", "1.0.0")
	publishPage(t, svc, "dst", "thing", "1.0.0")

	// a package of the target name already exists at the destination.
	if err := svc.MovePackage("acme", "thing", "dst", ""); err == nil {
		t.Fatal("expected conflict error moving onto an existing name")
	}
	// the source is untouched after the rejected move.
	if _, _, _, err := svc.Resolve("acme", "thing", "1.0.0"); err != nil {
		t.Fatalf("source disturbed by rejected move: %v", err)
	}

	// a missing target namespace is rejected.
	if err := svc.MovePackage("acme", "thing", "ghost", ""); err == nil {
		t.Fatal("expected error moving to a nonexistent namespace")
	}
}

func TestRenameNamespaceRepacksAndRewritesDeps(t *testing.T) {
	db := newTestDB(t)
	svc := registryOverDB(t, db)
	mustEnsureNS(t, svc, "acme", database.VisibilityPrivate)
	base := publishPage(t, svc, "acme", "base", "1.0.0")
	// a bundle in the same namespace references a sibling; after rename it must
	// keep pointing at that sibling under the new namespace name.
	bundleV, err := publishBundle(svc, "acme", "kit", "1.0.0", []manifest.Dependency{{ID: "acme/base", Range: "^1.0.0"}})
	if err != nil {
		t.Fatalf("publish bundle: %v", err)
	}
	oldBlobs := []string{base.ArchiveBlobSHA256, bundleV.ArchiveBlobSHA256}

	// a token scoped to the old namespace should follow the rename.
	trepo := repository.NewTokenRepository(db)
	entJSON, _ := json.Marshal([]string{"acme"})
	if missing, err := trepo.CreateScoped(
		&database.Token{TokenHash: "h1", Entitlements: string(entJSON)}, []string{"acme"},
	); err != nil || len(missing) > 0 {
		t.Fatalf("seed token: %v %v", missing, err)
	}

	if err := svc.RenameNamespace("acme", "acme2"); err != nil {
		t.Fatalf("rename: %v", err)
	}

	// new address resolves, old 404s.
	if _, _, _, err := svc.Resolve("acme2", "base", "1.0.0"); err != nil {
		t.Fatalf("new ns base: %v", err)
	}
	if _, _, _, err := svc.Resolve("acme", "base", "1.0.0"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old ns still resolves: %v", err)
	}

	// the bundle manifest id and its dependency id both follow the rename.
	if id := manifestIDAt(t, svc, "acme2", "kit", "1.0.0"); id != "acme2/kit" {
		t.Fatalf("bundle id = %q", id)
	}
	_, m, _, err := svc.VersionContent("acme2", "kit", "1.0.0")
	if err != nil {
		t.Fatalf("bundle content: %v", err)
	}
	if len(m.Dependencies) != 1 || m.Dependencies[0].ID != "acme2/base" {
		t.Fatalf("dependency not rewritten: %+v", m.Dependencies)
	}

	// the token entitlement was rewritten to the new namespace name.
	tokens, err := trepo.List()
	if err != nil {
		t.Fatalf("list tokens: %v", err)
	}
	if len(tokens) != 1 || tokens[0].Entitlements != `["acme2"]` {
		t.Fatalf("token entitlement = %q, want [\"acme2\"]", tokens[0].Entitlements)
	}

	// every old blob is reclaimed; nothing leaked or double-referenced.
	for _, old := range oldBlobs {
		if svc.blobs.Exists(old) {
			t.Fatalf("old blob %s leaked after rename", old)
		}
	}
}

func TestRenameNamespaceConflicts(t *testing.T) {
	svc := newTestRegistry(t)
	mustEnsureNS(t, svc, "acme", database.VisibilityPrivate)
	mustEnsureNS(t, svc, "taken", database.VisibilityPrivate)
	publishPage(t, svc, "acme", "thing", "1.0.0")

	if err := svc.RenameNamespace("acme", "taken"); err == nil {
		t.Fatal("expected error renaming onto an existing namespace")
	}
	// the source is untouched: still resolvable at the old name.
	if _, _, _, err := svc.Resolve("acme", "thing", "1.0.0"); err != nil {
		t.Fatalf("source disturbed by rejected rename: %v", err)
	}
}

// TestRenameNamespaceDropsStaleScope: a token scope that names the target name
// grants nothing before the rename, and must not grant the renamed namespace.
func TestRenameNamespaceDropsStaleScope(t *testing.T) {
	db := newTestDB(t)
	svc := registryOverDB(t, db)
	mustEnsureNS(t, svc, "acme", database.VisibilityPrivate)
	publishPage(t, svc, "acme", "base", "1.0.0")
	// written straight to the table: the token create path refuses a missing name.
	stale := database.Token{TokenHash: "stale", Entitlements: `["other","target"]`}
	if err := db.Create(&stale).Error; err != nil {
		t.Fatal(err)
	}
	follower := database.Token{TokenHash: "follower", Entitlements: `["acme"]`}
	if err := db.Create(&follower).Error; err != nil {
		t.Fatal(err)
	}
	if err := svc.RenameNamespace("acme", "target"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	tokens := NewTokenService(repository.NewTokenRepository(db))
	for _, tc := range []struct {
		id, want string
		reads    bool
	}{{stale.ID, `["other"]`, false}, {follower.ID, `["target"]`, true}} {
		var got database.Token
		if err := db.Where("id = ?", tc.id).First(&got).Error; err != nil {
			t.Fatal(err)
		}
		if got.Entitlements != tc.want {
			t.Fatalf("token %s entitlements %q, want %q", got.TokenHash, got.Entitlements, tc.want)
		}
		if tokens.CanRead(&got, "target") != tc.reads {
			t.Fatalf("token %s reads target = %v", got.TokenHash, !tc.reads)
		}
	}
}
