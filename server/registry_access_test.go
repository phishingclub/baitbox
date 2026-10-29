package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/repository"
	"github.com/phishingclub/baitbox/service"
	"gorm.io/gorm"
)

// seedPackage stores namespace ns with visibility vis holding package name at
// version 1.0.0.
func seedPackage(t *testing.T, db *gorm.DB, ns, vis, name string) {
	t.Helper()
	repo := repository.NewRegistry(db)
	n, err := repo.EnsureNamespace(ns, vis)
	if err != nil {
		t.Fatal(err)
	}
	p, err := repo.EnsurePackage(n.ID, name, "page")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateVersion(&database.PackageVersion{PackageID: p.ID, Version: "1.0.0", Manifest: "{}"}); err != nil {
		t.Fatal(err)
	}
}

// newToken issues a read token and returns its clear value and id.
func newToken(t *testing.T, db *gorm.DB, scopes, cidrs []string, expires *time.Time) (string, string) {
	t.Helper()
	clear, tok, err := service.NewTokenService(repository.NewTokenRepository(db)).
		Create("test", scopes, cidrs, expires, "", "test")
	if err != nil {
		t.Fatal(err)
	}
	return clear, tok.ID
}

func hit(e *gin.Engine, method, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	e.ServeHTTP(w, req)
	return w
}

// registryPaths is every registry route plus trailing slash variants, unknown
// paths and a wrong method.
var registryPaths = []struct{ method, path string }{
	{http.MethodGet, "/api/v1/info"},
	{http.MethodGet, "/api/v1/index"},
	{http.MethodGet, "/api/v1/packages/shared/kit"},
	{http.MethodGet, "/api/v1/packages/shared/kit/1.0.0"},
	{http.MethodGet, "/api/v1/packages/shared/kit/1.0.0/download"},
	{http.MethodGet, "/api/v1/packages/shared/kit/1.0.0/files/content/index.html"},
	{http.MethodGet, "/api/v1/blobs/abc"},
	{http.MethodGet, "/api/v1/previews/shared/kit/abc"},
	{http.MethodGet, "/api/v1/nope"},
	{http.MethodGet, "/api/v1/info/"},
	{http.MethodGet, "/api/v1/index/"},
	{http.MethodGet, "/api/v1/packages/shared/kit/"},
	{http.MethodGet, "/api/v1/packages/shared/kit/1.0.0/"},
	{http.MethodGet, "/api/v1/packages/shared/kit/1.0.0/download/"},
	{http.MethodGet, "/api/v1/blobs/abc/"},
	{http.MethodGet, "/"},
	{http.MethodGet, "/favicon.ico"},
	{http.MethodPost, "/api/v1/info"},
}

// unauthorized fails the test unless w is the generic 401.
func unauthorized(t *testing.T, w *httptest.ResponseRecorder, what string) {
	t.Helper()
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("%s: %d, want 401", what, w.Code)
	}
	if w.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("%s: WWW-Authenticate %q", what, w.Header().Get("WWW-Authenticate"))
	}
	if body := strings.TrimSpace(w.Body.String()); body != `{"error":"unauthorized"}` {
		t.Fatalf("%s: body %q", what, body)
	}
}

// TestPrivateRegistryNeedsToken: with registry.public off every registry route
// and every unknown path answers 401 to a caller without a valid token: none,
// unknown, expired, revoked, or used from outside its allowed range.
func TestPrivateRegistryNeedsToken(t *testing.T) {
	e, db := newTestEnv(t, false)
	seedPackage(t, db, "shared", database.VisibilityPublic, "kit")
	past := time.Now().Add(-time.Hour)
	expired, _ := newToken(t, db, []string{"*"}, nil, &past)
	revoked, revokedID := newToken(t, db, []string{"*"}, nil, nil)
	if err := service.NewTokenService(repository.NewTokenRepository(db)).Revoke(revokedID); err != nil {
		t.Fatal(err)
	}
	// httptest requests come from 192.0.2.1.
	wrongRange, _ := newToken(t, db, []string{"*"}, []string{"198.51.100.0/24"}, nil)
	tokens := map[string]string{
		"no token": "", "unknown": "bb_not_a_real_token", "expired": expired,
		"revoked": revoked, "wrong range": wrongRange,
	}
	for name, tok := range tokens {
		for _, p := range registryPaths {
			unauthorized(t, hit(e.Public, p.method, p.path, tok), name+" "+p.method+" "+p.path)
		}
	}
}

// TestPrivateRegistryWithToken: a valid token gets through, scopes still apply,
// and a namespace marked public is not readable without a scope for it.
func TestPrivateRegistryWithToken(t *testing.T) {
	e, db := newTestEnv(t, false)
	seedPackage(t, db, "shared", database.VisibilityPublic, "kit")
	seedPackage(t, db, "other", database.VisibilityPrivate, "lure")
	all, _ := newToken(t, db, []string{"*"}, []string{"192.0.2.0/24"}, nil)
	scoped, _ := newToken(t, db, []string{"other"}, nil, nil)

	if w := hit(e.Public, http.MethodGet, "/api/v1/info", all); w.Code != http.StatusOK {
		t.Fatalf("info with token: %d", w.Code)
	}
	w := hit(e.Public, http.MethodGet, "/api/v1/index", all)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"name":"kit"`) {
		t.Fatalf("index with token: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), `"visibility":"public"`) {
		t.Fatalf("index shows a public namespace on a private registry: %s", w.Body.String())
	}
	if w := hit(e.Public, http.MethodGet, "/api/v1/packages/shared/kit", all); w.Code != http.StatusOK {
		t.Fatalf("package with token: %d", w.Code)
	}
	if w := hit(e.Public, http.MethodGet, "/api/v1/packages/shared/kit", scoped); w.Code != http.StatusNotFound {
		t.Fatalf("namespace marked public, token scoped elsewhere: %d", w.Code)
	}
	w = hit(e.Public, http.MethodGet, "/api/v1/index", scoped)
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), `"name":"kit"`) ||
		!strings.Contains(w.Body.String(), `"name":"lure"`) {
		t.Fatalf("index with scoped token: %d %s", w.Code, w.Body.String())
	}
	if w := hit(e.Public, http.MethodGet, "/api/v1/nope", all); w.Code != http.StatusNotFound {
		t.Fatalf("unknown path with token: %d", w.Code)
	}
}

// TestPublicRegistryAnonymousReads: with registry.public on, anonymous callers
// read public namespaces and nothing else.
func TestPublicRegistryAnonymousReads(t *testing.T) {
	e, db := newTestEnv(t, true)
	seedPackage(t, db, "shared", database.VisibilityPublic, "kit")
	seedPackage(t, db, "other", database.VisibilityPrivate, "lure")

	if w := hit(e.Public, http.MethodGet, "/api/v1/info", ""); w.Code != http.StatusOK {
		t.Fatalf("info: %d", w.Code)
	}
	w := hit(e.Public, http.MethodGet, "/api/v1/index", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"name":"kit"`) ||
		strings.Contains(w.Body.String(), `"name":"lure"`) {
		t.Fatalf("index: %d %s", w.Code, w.Body.String())
	}
	if w := hit(e.Public, http.MethodGet, "/api/v1/packages/shared/kit", ""); w.Code != http.StatusOK {
		t.Fatalf("public package: %d", w.Code)
	}
	if w := hit(e.Public, http.MethodGet, "/api/v1/packages/other/lure", ""); w.Code != http.StatusNotFound {
		t.Fatalf("private package: %d", w.Code)
	}
	if w := hit(e.Public, http.MethodGet, "/api/v1/nope", ""); w.Code != http.StatusNotFound {
		t.Fatalf("unknown path: %d", w.Code)
	}
}
