package server

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/phishingclub/baitbox/config"
	"github.com/phishingclub/baitbox/database"
	"gorm.io/gorm"
)

func newTestEngines(t *testing.T) *Engines {
	t.Helper()
	e, _ := newTestEnv(t, false)
	return e
}

// newTestEnv builds both engines over a fresh database, with registry.public
// set to true or false, and returns the database for seeding.
func newTestEnv(t *testing.T, public bool) (*Engines, *gorm.DB) {
	t.Helper()
	return newTestEnvWith(t, func(c *config.Config) { c.Registry.Public = public })
}

// newTestEnvWith is newTestEnv with the config changed by edit first.
func newTestEnvWith(t *testing.T, edit func(*config.Config)) (*Engines, *gorm.DB) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "baitbox.sqlite3")
	db, err := database.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Env:            "dev",
		Registry:       config.Registry{Address: ":8112", TLSHost: "registry.test"},
		Administration: config.Administration{Address: ":8114", TLSHost: "admin.test"},
		Blobs:          config.Blobs{Path: filepath.Join(dir, "blobs")},
		Database:       config.Database{Path: dbPath},
	}
	edit(cfg)
	e, err := New(cfg, filepath.Join(dir, "config.json"), db, "dev")
	if err != nil {
		t.Fatal(err)
	}
	return e, db
}

func hasRoute(e *gin.Engine, method, path string) bool {
	for _, r := range e.Routes() {
		if r.Method == method && r.Path == path {
			return true
		}
	}
	return false
}

// TestFilesRouteOnlyOnRegistry: package files are never served from the admin
// origin, and no admin route exists on the registry listener.
func TestFilesRouteOnlyOnRegistry(t *testing.T) {
	e := newTestEngines(t)
	files := "/api/v1/packages/:ns/:name/:version/files/*path"
	if !hasRoute(e.Public, "GET", files) {
		t.Fatal("registry listener lacks the files route")
	}
	if hasRoute(e.Admin, "GET", files) {
		t.Fatal("admin listener serves package files")
	}
	for _, r := range e.Public.Routes() {
		if r.Path == "/api/v1/login" || r.Path == "/api/v1/admin/stats" || r.Path == "/admin/export" {
			t.Fatalf("registry listener has admin route %s", r.Path)
		}
	}
}

// TestAdminRegistryReadsNeedSession: the admin listener serves the registry
// protocol only to a signed in operator; registry reads belong on the
// registry listener.
func TestAdminRegistryReadsNeedSession(t *testing.T) {
	e := newTestEngines(t)
	for _, p := range []string{
		"/api/v1/info", "/api/v1/index", "/api/v1/packages/ns/pkg", "/api/v1/packages/ns/pkg/1.0.0",
		"/api/v1/packages/ns/pkg/1.0.0/download", "/api/v1/previews/ns/pkg/abc",
	} {
		w := httptest.NewRecorder()
		e.Admin.ServeHTTP(w, httptest.NewRequest(http.MethodGet, p, nil))
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("anonymous admin %s: %d", p, w.Code)
		}
	}
}

// TestAdminNoTrailingSlashRedirect: an address outside the admin allowlist gets
// 403 for a trailing slash variant of an admin route, never a redirect that
// would show the route exists.
func TestAdminNoTrailingSlashRedirect(t *testing.T) {
	e, _ := newTestEnvWith(t, func(c *config.Config) {
		// httptest requests come from 192.0.2.1.
		c.IPSecurity.AdminAllowed = []string{"198.51.100.0/24"}
	})
	for _, p := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/me/"},
		{http.MethodGet, "/api/v1/index/"},
		{http.MethodGet, "/api/v1/admin/stats/"},
		{http.MethodGet, "/api/v1/admin/namespaces/"},
		{http.MethodPost, "/api/v1/login/"},
		{http.MethodGet, "/admin/export/"},
		{http.MethodGet, "/api/v1/me"},
		{http.MethodGet, "/namespaces/"},
	} {
		w := httptest.NewRecorder()
		e.Admin.ServeHTTP(w, httptest.NewRequest(p.method, p.path, nil))
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s %s from outside the allowlist: %d, want 403", p.method, p.path, w.Code)
		}
	}
}
