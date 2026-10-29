package repository

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/phishingclub/baitbox/database"
	"gorm.io/gorm"
)

func newQueryTestRepo(t *testing.T) (*Registry, *gorm.DB) {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "q.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	return NewRegistry(db), db
}

// seedPkg creates a namespace (if needed) and a package with the given meta.
func seedPkg(t *testing.T, r *Registry, ns, name, pkgType, tags, description string) {
	t.Helper()
	n, err := r.EnsureNamespace(ns, database.VisibilityPublic)
	if err != nil {
		t.Fatalf("ensure ns: %v", err)
	}
	p, err := r.EnsurePackage(n.ID, name, pkgType)
	if err != nil {
		t.Fatalf("ensure pkg: %v", err)
	}
	if err := r.UpdatePackageMeta(p.ID, name, description, tags); err != nil {
		t.Fatalf("meta: %v", err)
	}
}

func TestListPackagesOrderColumnAllowlist(t *testing.T) {
	r, _ := newQueryTestRepo(t)
	seedPkg(t, r, "acme", "alpha", "page", "", "")

	// an allowlisted column is accepted.
	if _, err := r.ListPackages(&QueryArgs{OrderBy: "name"}); err != nil {
		t.Fatalf("allowlisted order rejected: %v", err)
	}
	// columns outside the allowlist are rejected before reaching SQL.
	for _, bad := range []string{"tags", "description", "password", "name; drop table packages"} {
		if _, err := r.ListPackages(&QueryArgs{OrderBy: bad}); err == nil {
			t.Fatalf("order column %q should be rejected", bad)
		}
	}
	// CountPackages ignores ordering, so a bad order must not affect it.
	if n, err := r.CountPackages(&QueryArgs{OrderBy: "tags"}); err != nil || n != 1 {
		t.Fatalf("count = %d err=%v", n, err)
	}
}

func TestListPackagesSearch(t *testing.T) {
	r, _ := newQueryTestRepo(t)
	seedPkg(t, r, "acme", "alpha", "page", "", "the alpha package")
	seedPkg(t, r, "acme", "beta", "email", "", "a beta thing")

	got, err := r.ListPackages(&QueryArgs{Search: "alph"})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(got) != 1 || got[0].Name != "alpha" {
		t.Fatalf("search alph returned %d rows: %+v", len(got), got)
	}
	// search also matches the description column.
	got, err = r.ListPackages(&QueryArgs{Search: "beta thing"})
	if err != nil {
		t.Fatalf("search desc: %v", err)
	}
	if len(got) != 1 || got[0].Name != "beta" {
		t.Fatalf("search desc returned %d rows", len(got))
	}
	// a LIKE wildcard in the user value is escaped: "a%a" would match "alpha" if
	// the % stayed a wildcard.
	got, err = r.ListPackages(&QueryArgs{Search: "a%a"})
	if err != nil {
		t.Fatalf("search wildcard: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("wildcard a%%a matched %d rows, want 0 (wildcard not escaped)", len(got))
	}
}

// TestListPackagesSearchUnderscore checks an underscore is matched as itself,
// not as any one character.
func TestListPackagesSearchUnderscore(t *testing.T) {
	r, _ := newQueryTestRepo(t)
	seedPkg(t, r, "acme", "foo_bar", "page", "", "")
	seedPkg(t, r, "acme", "fooxbar", "page", "", "")
	got, err := r.ListPackages(&QueryArgs{Search: "foo_bar"})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(got) != 1 || got[0].Name != "foo_bar" {
		t.Fatalf("search foo_bar returned %+v, want only foo_bar", got)
	}
	n, err := r.CountPackages(&QueryArgs{Search: "foo_bar"})
	if err != nil || n != 1 {
		t.Fatalf("count = %d err=%v, want 1", n, err)
	}
}

func TestListPackagesFilters(t *testing.T) {
	r, _ := newQueryTestRepo(t)
	seedPkg(t, r, "acme", "alpha", "page", "o365,login", "")
	seedPkg(t, r, "acme", "beta", "email", "o3650", "")
	seedPkg(t, r, "other", "gamma", "page", "o365", "")

	// type filter.
	got, _ := r.ListPackages(&QueryArgs{FilterType: "email"})
	if len(got) != 1 || got[0].Name != "beta" {
		t.Fatalf("type filter returned %+v", got)
	}

	// namespace filter.
	got, _ = r.ListPackages(&QueryArgs{FilterNamespace: "other"})
	if len(got) != 1 || got[0].Name != "gamma" {
		t.Fatalf("namespace filter returned %+v", got)
	}

	// tag filter matches on comma boundaries: "o365" must not match "o3650".
	got, _ = r.ListPackages(&QueryArgs{FilterTag: "o365"})
	names := map[string]bool{}
	for _, p := range got {
		names[p.Name] = true
	}
	if len(got) != 2 || !names["alpha"] || !names["gamma"] {
		t.Fatalf("tag filter o365 returned %+v, want alpha+gamma only", got)
	}
}

func TestListPackagesPaging(t *testing.T) {
	r, _ := newQueryTestRepo(t)
	for _, name := range []string{"a", "b", "c"} {
		seedPkg(t, r, "acme", name, "page", "", "")
	}
	// page size 2, ordered by name.
	page1, err := r.ListPackages(&QueryArgs{OrderBy: "name", Limit: 2, Offset: 0})
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1) != 2 || page1[0].Name != "a" || page1[1].Name != "b" {
		t.Fatalf("page1 = %+v", page1)
	}
	page2, err := r.ListPackages(&QueryArgs{OrderBy: "name", Limit: 2, Offset: 2})
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	if len(page2) != 1 || page2[0].Name != "c" {
		t.Fatalf("page2 = %+v", page2)
	}
	// the total ignores paging.
	if n, _ := r.CountPackages(nil); n != 3 {
		t.Fatalf("count = %d, want 3", n)
	}
}

// TestTagFilterIsExact: the list tag filter matches one whole tag, the same way
// TagInUse does, so a comma or a LIKE wildcard never widens it.
func TestTagFilterIsExact(t *testing.T) {
	r, _ := newQueryTestRepo(t)
	seedPkg(t, r, "acme", "alpha", "page", "o365,phish", "")
	seedPkg(t, r, "acme", "beta", "page", "o3650", "")
	seedPkg(t, r, "acme", "gamma", "page", "o_65", "")
	cases := map[string]int64{
		"o365": 1, "O365 ": 1, "phish": 1, "o3650": 1, "o_65": 1,
		"o365,phish": 0, "o%": 0, "o_": 0, "%": 0, ",": 0, "o36": 0,
	}
	for tag, want := range cases {
		n, err := r.CountPackages(&QueryArgs{FilterTag: tag})
		if err != nil {
			t.Fatalf("filter %q: %v", tag, err)
		}
		if n != want {
			t.Errorf("filter %q matched %d, want %d", tag, n, want)
		}
		used, err := r.TagInUse(tag)
		if err != nil {
			t.Fatalf("TagInUse %q: %v", tag, err)
		}
		if used != (want > 0) {
			t.Errorf("TagInUse %q = %v, want %v", tag, used, want > 0)
		}
	}
}

func TestOrderColumnErrorIsDistinct(t *testing.T) {
	r, _ := newQueryTestRepo(t)
	if _, err := r.ListPackages(&QueryArgs{OrderBy: "tags"}); !errors.Is(err, ErrOrderColumn) {
		t.Fatalf("bad order column error %v", err)
	}
	if _, err := r.ListNamespaces(&QueryArgs{OrderBy: "visibility"}); !errors.Is(err, ErrOrderColumn) {
		t.Fatalf("bad namespace order column error %v", err)
	}
}
