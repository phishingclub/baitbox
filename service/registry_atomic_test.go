package service

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/manifest"
)

// TestPublishRechecksDepsInsideTransaction: a namespace flipped to private after
// the publish checks ran but before its transaction opens must still stop a
// public package that depends on it.
func TestPublishRechecksDepsInsideTransaction(t *testing.T) {
	svc := newTestRegistry(t)
	lib := mustEnsureNS(t, svc, "lib", database.VisibilityPublic)
	mustEnsureNS(t, svc, "open", database.VisibilityPublic)
	publishPage(t, svc, "lib", "lure", "1.0.0")

	svc.beforeWriteCommit = func() {
		// a direct write, skipping the UpdateNamespace check, stands in for a change
		// that committed between the checks and the write.
		if err := svc.repo.UpdateNamespace(lib.ID, "", database.VisibilityPrivate); err != nil {
			t.Fatal(err)
		}
	}
	_, err := publishBundle(svc, "open", "kit", "1.0.0", []manifest.Dependency{{ID: "lib/lure", Range: "^1.0.0"}})
	if err == nil || !strings.Contains(err.Error(), "private package") {
		t.Fatalf("want a dependency visibility error, got %v", err)
	}
	if _, _, _, rerr := svc.Resolve("open", "kit", "1.0.0"); rerr == nil {
		t.Fatal("the version must not be stored")
	}
}

// TestImportRechecksDepsInsideTransaction: the import dependency rules repeat on
// the transaction handle, so a change between planning and writing rolls the
// whole import back with ErrConcurrentChange.
func TestImportRechecksDepsInsideTransaction(t *testing.T) {
	dst := newTestRegistry(t)
	lib := mustEnsureNS(t, dst, "lib", database.VisibilityPublic)
	publishPage(t, dst, "lib", "lure", "1.0.0")
	deps := []manifest.Dependency{{ID: "lib/lure", Range: "^1.0.0"}}
	tarball, sha := singlePageBundle(t, "open", database.VisibilityPublic, "kit", manifest.TypeBundle, manifest.TypeBundle, "1.0.0", deps)

	dst.beforeWriteCommit = func() {
		if err := dst.repo.UpdateNamespace(lib.ID, "", database.VisibilityPrivate); err != nil {
			t.Fatal(err)
		}
	}
	_, err := dst.ImportBundle(bytes.NewReader(tarball))
	if !errors.Is(err, ErrConcurrentChange) {
		t.Fatalf("want ErrConcurrentChange, got %v", err)
	}
	if _, gerr := dst.GetNamespace("open"); gerr == nil {
		t.Fatal("a rolled back import must not create its namespace")
	}
	if dst.blobs.Exists(sha) || dst.blobs.isPinned(sha) {
		t.Fatal("rolled back import left its blob behind")
	}
}

// TestImportRechecksTargetNamespaceVisibility: a local namespace that turned
// public after planning must not receive private bundle content.
func TestImportRechecksTargetNamespaceVisibility(t *testing.T) {
	dst := newTestRegistry(t)
	acme := mustEnsureNS(t, dst, "acme", database.VisibilityPrivate)
	tarball, _ := singlePageBundle(t, "acme", database.VisibilityPrivate, "secret", manifest.TypePage, manifest.TypePage, "1.0.0", nil)
	dst.beforeWriteCommit = func() {
		if err := dst.repo.UpdateNamespace(acme.ID, "", database.VisibilityPublic); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := dst.ImportBundle(bytes.NewReader(tarball)); !errors.Is(err, ErrConcurrentChange) {
		t.Fatalf("want ErrConcurrentChange, got %v", err)
	}
	if _, _, _, rerr := dst.Resolve("acme", "secret", "1.0.0"); rerr == nil {
		t.Fatal("private content must not land in a public namespace")
	}
}

// TestUpdateNamespaceDescriptionCap: the service refuses an over long namespace
// description even when the controller is bypassed.
func TestUpdateNamespaceDescriptionCap(t *testing.T) {
	svc := newTestRegistry(t)
	ns := mustEnsureNS(t, svc, "acme", database.VisibilityPrivate)
	if err := svc.UpdateNamespace(ns.ID, strings.Repeat("d", 4001), database.VisibilityPrivate); err == nil {
		t.Fatal("over long description accepted")
	}
	if err := svc.UpdateNamespace(ns.ID, strings.Repeat("d", 4000), database.VisibilityPrivate); err != nil {
		t.Fatalf("description at cap rejected: %v", err)
	}
}

// TestImportRechecksNewPackageInsideTransaction: a package the import plans to
// create that a publish creates first must roll the import back with
// ErrConcurrentChange, not fail on the unique index.
func TestImportRechecksNewPackageInsideTransaction(t *testing.T) {
	dst := newTestRegistry(t)
	mustEnsureNS(t, dst, "acme", database.VisibilityPrivate)
	tarball, _ := singlePageBundle(t, "acme", database.VisibilityPrivate, "kit", manifest.TypePage, manifest.TypePage, "1.0.0", nil)
	dst.beforeWriteCommit = func() {
		dst.beforeWriteCommit = nil
		publishPage(t, dst, "acme", "kit", "1.0.0")
	}
	// the recheck names the package, so the unique index backstop did not fire.
	if _, err := dst.ImportBundle(bytes.NewReader(tarball)); !errors.Is(err, ErrConcurrentChange) || !strings.Contains(err.Error(), "was created during the import") {
		t.Fatalf("want the recheck ErrConcurrentChange, got %v", err)
	}
	// the published version stays and the import added nothing.
	vs, err := versionsOf(dst, "acme", "kit")
	if err != nil || len(vs) != 1 {
		t.Fatalf("versions = %d err=%v", len(vs), err)
	}
}

// TestImportRechecksNewVersionInsideTransaction: a version the import plans to
// add to an existing package that a publish adds first must roll the import
// back with ErrConcurrentChange.
func TestImportRechecksNewVersionInsideTransaction(t *testing.T) {
	dst := newTestRegistry(t)
	mustEnsureNS(t, dst, "acme", database.VisibilityPrivate)
	publishPage(t, dst, "acme", "kit", "1.0.0")
	tarball, _ := singlePageBundle(t, "acme", database.VisibilityPrivate, "kit", manifest.TypePage, manifest.TypePage, "2.0.0", nil)
	dst.beforeWriteCommit = func() {
		dst.beforeWriteCommit = nil
		publishPage(t, dst, "acme", "kit", "2.0.0")
	}
	if _, err := dst.ImportBundle(bytes.NewReader(tarball)); !errors.Is(err, ErrConcurrentChange) || !strings.Contains(err.Error(), "was published during the import") {
		t.Fatalf("want the recheck ErrConcurrentChange, got %v", err)
	}
	vs, err := versionsOf(dst, "acme", "kit")
	if err != nil || len(vs) != 2 {
		t.Fatalf("versions = %d err=%v", len(vs), err)
	}
}

// TestUniqueInsertMapsToConcurrentChange: the backstop turns a unique index
// failure into ErrConcurrentChange without the database message, and leaves
// other errors alone.
func TestUniqueInsertMapsToConcurrentChange(t *testing.T) {
	svc := newTestRegistry(t)
	ns := mustEnsureNS(t, svc, "acme", database.VisibilityPrivate)
	if err := svc.repo.CreatePackage(&database.Package{NamespaceID: ns.ID, Name: "dup", Type: manifest.TypePage}); err != nil {
		t.Fatal(err)
	}
	err := svc.repo.CreatePackage(&database.Package{NamespaceID: ns.ID, Name: "dup", Type: manifest.TypePage})
	if err == nil {
		t.Fatal("duplicate package insert succeeded")
	}
	mapped := uniqueAsConflict(err)
	if !errors.Is(mapped, ErrConcurrentChange) || strings.Contains(mapped.Error(), "UNIQUE") {
		t.Fatalf("mapped = %v", mapped)
	}
	other := errors.New("disk full")
	if uniqueAsConflict(other) != other {
		t.Fatal("a non unique error must pass through")
	}
}

// versionsOf lists the stored versions of a package by address.
func versionsOf(svc *RegistryService, ns, name string) ([]database.PackageVersion, error) {
	_, pkg, _, err := svc.Resolve(ns, name, "latest")
	if err != nil {
		return nil, err
	}
	return svc.repo.ListVersions(pkg.ID)
}
