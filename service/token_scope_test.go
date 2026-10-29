package service

import (
	"strings"
	"testing"

	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/repository"
)

// TestTokenScopesMustNameExistingNamespaces: a token can only be scoped to
// namespaces that exist, and the refusal names the missing ones.
func TestTokenScopesMustNameExistingNamespaces(t *testing.T) {
	db := newTestDB(t)
	svc := registryOverDB(t, db)
	mustEnsureNS(t, svc, "acme", database.VisibilityPrivate)
	tokens := NewTokenService(repository.NewTokenRepository(db))

	for _, ok := range [][]string{{"acme"}, {"*"}, {}, {"acme", "*"}} {
		if err := tokens.CheckScopes(ok); err != nil {
			t.Fatalf("CheckScopes(%v) = %v", ok, err)
		}
	}
	err := tokens.CheckScopes([]string{"acme", "ghost", "later"})
	if err == nil || !IsValidation(err) || !strings.Contains(err.Error(), "ghost, later") {
		t.Fatalf("CheckScopes with missing names = %v", err)
	}

	if _, _, err := tokens.Create("bad", []string{"ghost"}, nil, nil, "", ""); err == nil || !IsValidation(err) {
		t.Fatalf("Create with a missing namespace = %v", err)
	}
	list, err := tokens.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("a refused create wrote %d tokens", len(list))
	}
	if _, _, err := tokens.Create("good", []string{"acme"}, nil, nil, "", ""); err != nil {
		t.Fatalf("Create with an existing namespace = %v", err)
	}
}

// TestDeletedNamespaceScopeNotReused: deleting a namespace drops it from token
// scopes, so a namespace created later under the same name is not readable by
// an old token.
func TestDeletedNamespaceScopeNotReused(t *testing.T) {
	db := newTestDB(t)
	svc := registryOverDB(t, db)
	ns := mustEnsureNS(t, svc, "acme", database.VisibilityPrivate)
	mustEnsureNS(t, svc, "keep", database.VisibilityPrivate)
	tokens := NewTokenService(repository.NewTokenRepository(db))
	_, tok, err := tokens.Create("reader", []string{"acme", "keep"}, nil, nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteNamespace(ns.ID); err != nil {
		t.Fatal(err)
	}
	mustEnsureNS(t, svc, "acme", database.VisibilityPrivate)
	var got database.Token
	if err := db.Where("id = ?", tok.ID).First(&got).Error; err != nil {
		t.Fatal(err)
	}
	if tokens.CanRead(&got, "acme") {
		t.Fatalf("old token reads the new namespace (entitlements %s)", got.Entitlements)
	}
	if !tokens.CanRead(&got, "keep") {
		t.Fatalf("old token lost its other namespace (entitlements %s)", got.Entitlements)
	}
}
