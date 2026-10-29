package service

import (
	"strings"
	"testing"

	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/manifest"
)

// TestPublicBundleRejectsPrivateDep: a public bundle may reference only packages
// in public namespaces. A reference into a private namespace is rejected at
// publish, and the reference into a public one is accepted.
func TestPublicBundleRejectsPrivateDep(t *testing.T) {
	svc := newTestRegistry(t)
	mustEnsureNS(t, svc, "priv", database.VisibilityPrivate)
	mustEnsureNS(t, svc, "pub", database.VisibilityPublic)
	publishPage(t, svc, "priv", "base", "1.0.0")
	publishPage(t, svc, "pub", "base", "1.0.0")

	_, err := publishBundle(svc, "pub", "kit", "1.0.0", []manifest.Dependency{{ID: "priv/base", Range: "^1.0.0"}})
	if err == nil || !strings.Contains(err.Error(), "public bundle cannot reference the private package") {
		t.Fatalf("public->private dep: want rejection, got %v", err)
	}

	// a public bundle referencing a public package is allowed.
	if _, err := publishBundle(svc, "pub", "kit", "1.0.0", []manifest.Dependency{{ID: "pub/base", Range: "^1.0.0"}}); err != nil {
		t.Fatalf("public->public dep: %v", err)
	}
}

// TestPrivateBundleOwnNamespaceAllowed: a private bundle may reference packages
// in its own namespace even though they are private.
func TestPrivateBundleOwnNamespaceAllowed(t *testing.T) {
	svc := newTestRegistry(t)
	mustEnsureNS(t, svc, "team", database.VisibilityPrivate)
	publishPage(t, svc, "team", "base", "1.0.0")

	if _, err := publishBundle(svc, "team", "kit", "1.0.0", []manifest.Dependency{{ID: "team/base", Range: "^1.0.0"}}); err != nil {
		t.Fatalf("private bundle referencing own namespace: %v", err)
	}
}

// TestBundleRejectsNestedBundleOrTemplate: a bundle cannot reference another
// bundle (no nesting).
func TestBundleRejectsNestedBundleOrTemplate(t *testing.T) {
	svc := newTestRegistry(t)
	mustEnsureNS(t, svc, "team", database.VisibilityPrivate)
	publishPage(t, svc, "team", "base", "1.0.0")
	if _, err := publishBundle(svc, "team", "inner", "1.0.0", []manifest.Dependency{{ID: "team/base", Range: "^1.0.0"}}); err != nil {
		t.Fatalf("inner bundle: %v", err)
	}
	_, err := publishBundle(svc, "team", "outer", "1.0.0", []manifest.Dependency{{ID: "team/inner", Range: "^1.0.0"}})
	if err == nil || !strings.Contains(err.Error(), "cannot reference another bundle") {
		t.Fatalf("nested bundle: want rejection, got %v", err)
	}
}

// TestBundleRejectsMissingDep: a reference to a package that does not exist is
// rejected.
func TestBundleRejectsMissingDep(t *testing.T) {
	svc := newTestRegistry(t)
	mustEnsureNS(t, svc, "team", database.VisibilityPublic)
	_, err := publishBundle(svc, "team", "kit", "1.0.0", []manifest.Dependency{{ID: "team/ghost", Range: "^1.0.0"}})
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("missing dep: want rejection, got %v", err)
	}
}

// TestUpdateNamespaceRejectsFlipThatBreaksBundle: flipping a referenced
// namespace to private is rejected while a public bundle still references a
// package in it, since nothing re-validates bundles after the fact.
func TestUpdateNamespaceRejectsFlipThatBreaksBundle(t *testing.T) {
	svc := newTestRegistry(t)
	lib := mustEnsureNS(t, svc, "lib", database.VisibilityPublic)
	mustEnsureNS(t, svc, "pub", database.VisibilityPublic)
	publishPage(t, svc, "lib", "base", "1.0.0")
	if _, err := publishBundle(svc, "pub", "kit", "1.0.0", []manifest.Dependency{{ID: "lib/base", Range: "^1.0.0"}}); err != nil {
		t.Fatalf("publish bundle: %v", err)
	}

	err := svc.UpdateNamespace(lib.ID, "", database.VisibilityPrivate)
	if err == nil || !strings.Contains(err.Error(), "would break") {
		t.Fatalf("flip lib private: want rejection, got %v", err)
	}
	// the namespace visibility is unchanged after the rejected flip.
	cur, gerr := svc.GetNamespaceByID(lib.ID)
	if gerr != nil {
		t.Fatal(gerr)
	}
	if cur.Visibility != database.VisibilityPublic {
		t.Fatalf("visibility changed despite rejection: %q", cur.Visibility)
	}
}

// TestUpdateNamespaceAllowsHarmlessFlip: flipping a namespace that no public
// bundle depends on is allowed.
func TestUpdateNamespaceAllowsHarmlessFlip(t *testing.T) {
	svc := newTestRegistry(t)
	solo := mustEnsureNS(t, svc, "solo", database.VisibilityPublic)
	publishPage(t, svc, "solo", "base", "1.0.0")

	if err := svc.UpdateNamespace(solo.ID, "desc", database.VisibilityPrivate); err != nil {
		t.Fatalf("harmless flip rejected: %v", err)
	}
	cur, err := svc.GetNamespaceByID(solo.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cur.Visibility != database.VisibilityPrivate {
		t.Fatalf("visibility not applied: %q", cur.Visibility)
	}
}
