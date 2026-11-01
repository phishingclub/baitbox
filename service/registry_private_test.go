package service

import (
	"errors"
	"testing"

	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/manifest"
	"github.com/phishingclub/baitbox/repository"
)

// TestPrivateRegistryRefusesPublicNamespace: with registry.public off a
// namespace cannot be created public or switched to public; private ones work.
// A public registry allows both.
func TestPrivateRegistryRefusesPublicNamespace(t *testing.T) {
	svc := registryOverDBPublic(t, newTestDB(t), false)
	if _, err := svc.CreateNamespace("open", "", database.VisibilityPublic, ""); !errors.Is(err, ErrPublicDisabled) {
		t.Fatalf("create public: %v", err)
	}
	ns, err := svc.CreateNamespace("closed", "", database.VisibilityPrivate, "")
	if err != nil {
		t.Fatalf("create private: %v", err)
	}
	if err := svc.UpdateNamespace(ns.ID, "", database.VisibilityPublic); !errors.Is(err, ErrPublicDisabled) {
		t.Fatalf("switch to public: %v", err)
	}
	if err := svc.UpdateNamespace(ns.ID, "described", database.VisibilityPrivate); err != nil {
		t.Fatalf("private update: %v", err)
	}

	pub := registryOverDBPublic(t, newTestDB(t), true)
	ns, err = pub.CreateNamespace("open", "", database.VisibilityPublic, "")
	if err != nil {
		t.Fatalf("create public on a public registry: %v", err)
	}
	if err := pub.UpdateNamespace(ns.ID, "", database.VisibilityPrivate); err != nil {
		t.Fatalf("switch to private: %v", err)
	}
	if err := pub.UpdateNamespace(ns.ID, "", database.VisibilityPublic); err != nil {
		t.Fatalf("switch back to public: %v", err)
	}
}

// TestPrivateRegistryTreatsPublicAsPrivate: a namespace stored as public reads
// as private on a private registry, so the dependency rules treat it as private
// too.
func TestPrivateRegistryTreatsPublicAsPrivate(t *testing.T) {
	priv := registryOverDBPublic(t, newTestDB(t), false)
	pub := registryOverDBPublic(t, newTestDB(t), true)
	if v := priv.EffectiveVisibility(database.VisibilityPublic); v != database.VisibilityPrivate {
		t.Fatalf("private registry: %q", v)
	}
	if v := pub.EffectiveVisibility(database.VisibilityPublic); v != database.VisibilityPublic {
		t.Fatalf("public registry: %q", v)
	}
	deps := []manifest.Dependency{{ID: "shared/logo"}}
	allPublic := func(string) string { return database.VisibilityPublic }
	isPage := func(string, string) (string, bool) { return manifest.TypePage, true }
	if err := pub.checkDeps(manifest.TypeBundle, "kits", database.VisibilityPublic, deps, allPublic, isPage); err != nil {
		t.Fatalf("public registry, public dependency: %v", err)
	}
	// on a private registry the bundle and its dependency are both private, and a
	// private package may only use packages of its own namespace.
	if err := priv.checkDeps(manifest.TypeBundle, "kits", database.VisibilityPublic, deps, allPublic, isPage); err == nil {
		t.Fatal("private registry let a package use another namespace")
	}
	if err := priv.checkDeps(manifest.TypeBundle, "shared", database.VisibilityPublic, deps, allPublic, isPage); err != nil {
		t.Fatalf("private registry, same namespace: %v", err)
	}
}

// TestPrivatizeStoredPublic: on a private registry every namespace stored as
// public is stored as private, so turning registry.public on later shows nothing
// that was hidden. A public registry changes nothing.
func TestPrivatizeStoredPublic(t *testing.T) {
	db := newTestDB(t)
	repo := repository.NewRegistry(db)
	for _, n := range []string{"one", "two"} {
		if _, err := repo.EnsureNamespace(n, database.VisibilityPublic); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := repo.EnsureNamespace("closed", database.VisibilityPrivate); err != nil {
		t.Fatal(err)
	}
	stored := func(name string) string {
		ns, err := repo.GetNamespace(name)
		if err != nil {
			t.Fatal(err)
		}
		return ns.Visibility
	}

	if n, err := registryOverDBPublic(t, db, true).PrivatizeStoredPublic(); err != nil || n != 0 {
		t.Fatalf("public registry: %d %v", n, err)
	}
	if v := stored("one"); v != database.VisibilityPublic {
		t.Fatalf("public registry changed a namespace: %q", v)
	}

	priv := registryOverDBPublic(t, db, false)
	if n, err := priv.PrivatizeStoredPublic(); err != nil || n != 2 {
		t.Fatalf("private registry: %d %v", n, err)
	}
	for _, name := range []string{"one", "two", "closed"} {
		if v := stored(name); v != database.VisibilityPrivate {
			t.Fatalf("%s is %q", name, v)
		}
	}
	if n, err := priv.PrivatizeStoredPublic(); err != nil || n != 0 {
		t.Fatalf("second run: %d %v", n, err)
	}
}
