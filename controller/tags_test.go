package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/manifest"
	"github.com/phishingclub/baitbox/repository"
	"github.com/phishingclub/baitbox/service"
)

// tagFixture is a registry with a public package and a private package that
// share one tag and each carry one tag of their own, every tag colored.
func tagFixture(t *testing.T) (*service.RegistryService, *service.TokenService) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := database.Open(filepath.Join(t.TempDir(), "tags.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	blobs, err := service.NewBlobStore(t.TempDir())
	if err != nil {
		t.Fatalf("blobs: %v", err)
	}
	reg := service.NewRegistryService(service.RegistryDeps{
		Repo: repository.NewRegistry(db), Blobs: blobs, MaxDownload: 64 << 20, MaxFile: 128 << 20,
		Public: true,
	})
	tokens := service.NewTokenService(repository.NewTokenRepository(db))
	for _, p := range []struct{ ns, vis, name string }{{"open", database.VisibilityPublic, "lure"}, {"hidden", database.VisibilityPrivate, "kit"}} {
		if _, err := repository.NewRegistry(db).EnsureNamespace(p.ns, p.vis); err != nil {
			t.Fatal(err)
		}
		if _, _, err := reg.AuthorPackage(service.AuthoredPackage{
			Namespace: p.ns, Name: p.name, Type: manifest.TypePage, Version: "1.0.0", Title: p.name,
			Files: map[string][]byte{"content/index.html": []byte("<h1>x</h1>")},
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := reg.UpdatePackageMeta("open", "lure", "lure", "", "shared,pubonly"); err != nil {
		t.Fatal(err)
	}
	if err := reg.UpdatePackageMeta("hidden", "kit", "kit", "", "shared,secrettag,plain"); err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"shared", "pubonly", "secrettag"} {
		if err := reg.SetTagColor(tag, "red"); err != nil {
			t.Fatal(err)
		}
	}
	return reg, tokens
}

func callJSON(t *testing.T, h gin.HandlerFunc, path string) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, path, nil)
	h(c)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: status %d %s", path, w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestAdminTagsListsEveryTagInUse: the admin tag list holds every tag a package
// carries, including one with no color and ones only on a private package.
func TestAdminTagsListsEveryTagInUse(t *testing.T) {
	reg, tokens := tagFixture(t)
	api := NewAdminAPI(AdminAPIDeps{Registry: reg, Tokens: tokens})
	out := callJSON(t, api.TagsList, "/api/v1/admin/tags")
	got := map[string]string{}
	var order []string
	for _, x := range out["tags"].([]any) {
		m := x.(map[string]any)
		got[m["name"].(string)] = m["color"].(string)
		order = append(order, m["name"].(string))
	}
	want := map[string]string{"plain": "", "pubonly": "red", "secrettag": "red", "shared": "red"}
	if len(got) != len(want) {
		t.Fatalf("tags = %v", got)
	}
	for k, v := range want {
		if c, ok := got[k]; !ok || c != v {
			t.Fatalf("tag %s: got %q present=%v, want %q (all %v)", k, c, ok, v, got)
		}
	}
	if order[0] != "plain" || order[len(order)-1] != "shared" {
		t.Fatalf("tags not sorted: %v", order)
	}
}

// TestPublicIndexHidesPrivateTags: without a token the public index lists only
// public packages, and its tag colors never name a tag that exists only on a
// private package.
func TestPublicIndexHidesPrivateTags(t *testing.T) {
	reg, tokens := tagFixture(t)
	out := callJSON(t, NewRegistry(reg, tokens).Index, "/api/v1/index")
	colors := out["tagColors"].(map[string]any)
	if _, ok := colors["secrettag"]; ok {
		t.Fatalf("private tag leaked in tagColors: %v", colors)
	}
	if colors["shared"] != "red" || colors["pubonly"] != "red" || len(colors) != 2 {
		t.Fatalf("tagColors = %v", colors)
	}
	pkgs := out["packages"].([]any)
	if len(pkgs) != 1 {
		t.Fatalf("packages = %v", pkgs)
	}
	for _, tg := range pkgs[0].(map[string]any)["tags"].([]any) {
		if tg == "secrettag" || tg == "plain" {
			t.Fatalf("private tag leaked on a package: %v", tg)
		}
	}
}
