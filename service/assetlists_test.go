package service

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/manifest"
)

// scannerPick is a variable that lets the installer pick an allow deny list.
var scannerPick = manifest.Variable{Name: "SCANNER_LIST", Type: manifest.VarText, Required: true, Pick: manifest.PickAllowDeny}

// officePick is a second list pick variable.
var officePick = manifest.Variable{Name: "OFFICE_LIST", Type: manifest.VarText, Required: true, Pick: manifest.PickAllowDeny}

// listDoc is the data.yaml of an allow deny package with one list.
func listDoc(listName string, allowed bool) string {
	kind := "false"
	if allowed {
		kind = "true"
	}
	return "name: " + listName + "\nallowDenies:\n  - name: " + listName + "\n    allowed: " + kind +
		"\n    cidrs: |\n      10.0.0.0/8\n"
}

// authorList publishes an allow deny package with one list.
func authorList(t *testing.T, svc *RegistryService, ns, name, version, listName string, allowed bool) {
	t.Helper()
	_, _, err := svc.AuthorPackage(AuthoredPackage{
		Namespace: ns, Name: name, Type: manifest.TypeAllowDeny, Version: version, Title: listName,
		Files: map[string][]byte{"content/" + name + "/data.yaml": []byte(listDoc(listName, allowed))},
	})
	if err != nil {
		t.Fatalf("publish list %s/%s@%s: %v", ns, name, version, err)
	}
}

// pageWithLists authors a page whose one asset uses the given list names.
func pageWithLists(
	svc *RegistryService, ns, name, version string, lists []string, deps []string, vars ...manifest.Variable,
) error {
	doc := "name: " + name + "\n"
	if len(lists) > 0 {
		doc += "assets:\n  - path: logo.png\n    allowDeny:\n"
		for _, l := range lists {
			doc += "      - \"" + l + "\"\n"
		}
	}
	ds := make([]manifest.Dependency, 0, len(deps))
	for _, d := range deps {
		ds = append(ds, manifest.Dependency{ID: d, Range: "*"})
	}
	_, _, err := svc.AuthorPackage(AuthoredPackage{
		Namespace: ns, Name: name, Type: manifest.TypePage, Version: version, Title: name,
		Dependencies: ds, Variables: vars,
		Files: map[string][]byte{
			"content/" + name + "/data.yaml": []byte(doc),
			"content/" + name + "/page.html": []byte("<h1>hi</h1>"),
			"assets/logo.png":                []byte("png"),
		},
	})
	return err
}

func TestAssetListsResolveThroughDependencies(t *testing.T) {
	svc := newTestRegistry(t)
	authorList(t, svc, "acme", "scanners", "1.0.0", "Scanners", false)
	authorList(t, svc, "acme", "bots", "1.0.0", "Bots", false)
	authorList(t, svc, "acme", "office", "1.0.0", "Office", true)
	authorList(t, svc, "other", "elsewhere", "1.0.0", "Elsewhere", false)
	authorList(t, svc, "acme", "dupe", "1.0.0", "Scanners", true)

	good := []struct {
		name  string
		lists []string
		deps  []string
		vars  []manifest.Variable
	}{
		{"one deny list", []string{"Scanners"}, []string{"acme/scanners"}, nil},
		{"two deny lists", []string{"Scanners", "Bots"}, []string{"acme/scanners", "acme/bots"}, nil},
		{"installer pick", []string{"@@SCANNER_LIST@@"}, nil, []manifest.Variable{scannerPick}},
		{"pick of another name", []string{"@@OFFICE_LIST@@"}, nil, []manifest.Variable{officePick}},
		{"no lists, an unused dependency", nil, []string{"acme/scanners"}, nil},
	}
	for i, c := range good {
		if err := pageWithLists(svc, "acme", "good", "1.0."+string(rune('0'+i)), c.lists, c.deps, c.vars...); err != nil {
			t.Errorf("%s: refused: %v", c.name, err)
		}
	}
	bad := []struct {
		name  string
		lists []string
		deps  []string
		vars  []manifest.Variable
		want  string
	}{
		{"no dependency", []string{"Scanners"}, nil, nil, "no allow / deny package"},
		{"free text name", []string{"Some global list"}, []string{"acme/scanners"}, nil, "no allow / deny package"},
		{"pick not declared", []string{"@@SCANNER_LIST@@"}, nil, nil, "not a variable that lets the installer pick"},
		{"pick of another kind", []string{"@@SCANNER_LIST@@"}, nil,
			[]manifest.Variable{{Name: "SCANNER_LIST", Type: manifest.VarText, Required: true}}, "not a variable"},
		{"mixed kinds", []string{"Scanners", "Office"}, []string{"acme/scanners", "acme/office"}, nil, "mixes allow and deny"},
		{"pick and a list", []string{"Scanners", "@@SCANNER_LIST@@"}, []string{"acme/scanners"},
			[]manifest.Variable{scannerPick}, "must be the asset's only list"},
		{"two picks", []string{"@@SCANNER_LIST@@", "@@OFFICE_LIST@@"}, nil,
			[]manifest.Variable{scannerPick, officePick}, "must be the asset's only list"},
		{"optional list pick", []string{"@@SCANNER_LIST@@"}, nil,
			[]manifest.Variable{{Name: "SCANNER_LIST", Type: manifest.VarText, Pick: manifest.PickAllowDeny}}, "must be required"},
		{"missing dependency", nil, []string{"acme/nothere"}, nil, "does not exist"},
		{"two packages declare one name", []string{"Scanners"}, []string{"acme/scanners", "acme/dupe"}, nil, "declared by both"},
	}
	for _, c := range bad {
		err := pageWithLists(svc, "acme", "bad", "1.0.0", c.lists, c.deps, c.vars...)
		if err == nil || !IsValidation(err) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %v, want a validation error with %q", c.name, err, c.want)
		}
	}
	// a dependency in another namespace is refused, even a public list.
	mustEnsureNS(t, svc, "pub", database.VisibilityPublic)
	authorList(t, svc, "pub", "shared", "1.0.0", "Shared", false)
	err := pageWithLists(svc, "acme", "cross", "1.0.0", []string{"Shared"}, []string{"pub/shared"})
	if err == nil || !IsValidation(err) || !strings.Contains(err.Error(), "not in the namespace acme") {
		t.Errorf("list of another namespace: %v", err)
	}
	// a dependency that is not an allow deny package is refused.
	publishPage(t, svc, "acme", "plain", "1.0.0")
	err = pageWithLists(svc, "acme", "notalist", "1.0.0", nil, []string{"acme/plain"})
	if err == nil || !IsValidation(err) || !strings.Contains(err.Error(), "is a page package") {
		t.Errorf("dependency that is not a list: %v", err)
	}
	// an allow deny package has no dependencies.
	_, _, err = svc.AuthorPackage(AuthoredPackage{
		Namespace: "acme", Name: "chained", Type: manifest.TypeAllowDeny, Version: "1.0.0",
		Dependencies: []manifest.Dependency{{ID: "acme/scanners", Range: "*"}},
		Files:        map[string][]byte{"content/chained/data.yaml": []byte(listDoc("Chained", false))},
	})
	if err == nil || !IsValidation(err) || !strings.Contains(err.Error(), "cannot have dependencies") {
		t.Errorf("list package with a dependency: %v", err)
	}
}

// TestAssetListRefsNeedEveryDependency: checkAssetListRefs refuses a dependency
// that has no version or is not a list package, even when no asset uses it, so
// a yank or delete that leaves one behind is reported.
func TestAssetListRefsNeedEveryDependency(t *testing.T) {
	m := &manifest.Manifest{ID: "acme/page", Type: manifest.TypePage,
		Dependencies: []manifest.Dependency{{ID: "acme/gone", Range: "*"}}}
	none := func(string) (*database.PackageVersion, error) { return nil, nil }
	err := checkAssetListRefs("acme", m, nil, none, nil)
	if err == nil || !IsValidation(err) || !strings.Contains(err.Error(), "no version that can be installed") {
		t.Fatalf("missing dependency: %v", err)
	}
}

func TestDuplicateListNamesRefused(t *testing.T) {
	svc := newTestRegistry(t)
	_, _, err := svc.AuthorPackage(AuthoredPackage{
		Namespace: "acme", Name: "lists", Type: manifest.TypeAllowDeny, Version: "1.0.0",
		Files: map[string][]byte{
			"content/a/data.yaml": []byte(listDoc("Scanners", false)),
			"content/b/data.yaml": []byte(listDoc("Scanners", true)),
		},
	})
	if err == nil || !IsValidation(err) || !strings.Contains(err.Error(), "already declared") {
		t.Fatalf("duplicate list name across docs: %v", err)
	}
}

func TestOnlyAllowDenyPackagesDeclareLists(t *testing.T) {
	svc := newTestRegistry(t)
	_, _, err := svc.AuthorPackage(AuthoredPackage{
		Namespace: "acme", Name: "page", Type: manifest.TypePage, Version: "1.0.0",
		Files: map[string][]byte{
			"content/page/data.yaml": []byte(listDoc("Inline", false)),
			"content/page/page.html": []byte("<h1>hi</h1>"),
		},
	})
	if err == nil || !IsValidation(err) || !strings.Contains(err.Error(), "only an allow / deny package") {
		t.Fatalf("inline lists on a page: %v", err)
	}
	// the raw upload path refuses it too.
	files := map[string][]byte{"content/page/data.yaml": []byte(listDoc("Inline", false))}
	archive, _, err := buildArchiveUnchecked(PackageSpec{ID: "acme/page", Type: manifest.TypePage, Version: "1.0.0"}, files)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Publish("acme", "page", "1.0.0", "application/gzip", strings.NewReader(string(archive)))
	if err == nil || !IsValidation(err) || !strings.Contains(err.Error(), "only an allow / deny package") {
		t.Fatalf("raw upload with inline lists on a page: %v", err)
	}
}

func TestListUpdateMustKeepDependentsResolving(t *testing.T) {
	svc := newTestRegistry(t)
	authorList(t, svc, "acme", "scanners", "1.0.0", "Scanners", false)
	if err := pageWithLists(svc, "acme", "login", "1.0.0", []string{"Scanners"}, []string{"acme/scanners"}); err != nil {
		t.Fatal(err)
	}
	// a rename of the list would leave the page naming a list that is gone.
	_, _, err := svc.AuthorPackage(AuthoredPackage{
		Namespace: "acme", Name: "scanners", Type: manifest.TypeAllowDeny, Version: "1.1.0",
		Files: map[string][]byte{"content/scanners/data.yaml": []byte(listDoc("Renamed", false))},
	})
	if err == nil || !IsValidation(err) || !strings.Contains(err.Error(), "acme/login cannot be installed") {
		t.Fatalf("rename of a used list: %v", err)
	}
	// a page that mixes would follow from turning the list into an allow list
	// next to a deny list.
	authorList(t, svc, "acme", "bots", "1.0.0", "Bots", false)
	if err := pageWithLists(svc, "acme", "login", "1.1.0", []string{"Scanners", "Bots"}, []string{"acme/scanners", "acme/bots"}); err != nil {
		t.Fatal(err)
	}
	_, _, err = svc.AuthorPackage(AuthoredPackage{
		Namespace: "acme", Name: "bots", Type: manifest.TypeAllowDeny, Version: "1.1.0",
		Files: map[string][]byte{"content/bots/data.yaml": []byte(listDoc("Bots", true))},
	})
	if err == nil || !strings.Contains(err.Error(), "mixes allow and deny") {
		t.Fatalf("kind flip of a used list: %v", err)
	}
	// a new version that keeps the name and kind is fine.
	authorList(t, svc, "acme", "scanners", "1.2.0", "Scanners", false)
	// turning the one list a page uses from deny to allow is refused, even with
	// nothing to mix with.
	authorList(t, svc, "acme", "solo", "1.0.0", "Solo", false)
	if err := pageWithLists(svc, "acme", "single", "1.0.0", []string{"Solo"}, []string{"acme/solo"}); err != nil {
		t.Fatal(err)
	}
	_, _, err = svc.AuthorPackage(AuthoredPackage{
		Namespace: "acme", Name: "solo", Type: manifest.TypeAllowDeny, Version: "1.1.0",
		Files: map[string][]byte{"content/solo/data.yaml": []byte(listDoc("Solo", true))},
	})
	if err == nil || !IsValidation(err) || !strings.Contains(err.Error(), "changes from a deny list to an allow list") {
		t.Fatalf("single list kind flip: %v", err)
	}
	// and back the other way for an allow list.
	authorList(t, svc, "acme", "office", "1.0.0", "Office", true)
	if err := pageWithLists(svc, "acme", "inside", "1.0.0", []string{"Office"}, []string{"acme/office"}); err != nil {
		t.Fatal(err)
	}
	_, _, err = svc.AuthorPackage(AuthoredPackage{
		Namespace: "acme", Name: "office", Type: manifest.TypeAllowDeny, Version: "1.1.0",
		Files: map[string][]byte{"content/office/data.yaml": []byte(listDoc("Office", false))},
	})
	if err == nil || !strings.Contains(err.Error(), "changes from an allow list to a deny list") {
		t.Fatalf("allow to deny flip: %v", err)
	}
}

// TestYankAndDeleteWarnAboutListBreaks: a yank, unyank or delete is never
// refused for a package that uses the lists, but the break is returned.
func TestYankAndDeleteWarnAboutListBreaks(t *testing.T) {
	svc := newTestRegistry(t)
	authorList(t, svc, "acme", "scanners", "1.0.0", "Old", false)
	authorList(t, svc, "acme", "scanners", "1.1.0", "Scanners", false)
	if err := pageWithLists(svc, "acme", "login", "1.0.0", []string{"Scanners"}, []string{"acme/scanners"}); err != nil {
		t.Fatal(err)
	}
	w, err := svc.YankVersion("acme", "scanners", "1.1.0", true)
	if err != nil || len(w.AssetLists) != 1 || !strings.Contains(w.AssetLists[0], "acme/login") ||
		!strings.Contains(w.AssetLists[0], "Scanners") {
		t.Fatalf("yank: %+v %v", w, err)
	}
	if w, err := svc.YankVersion("acme", "scanners", "1.1.0", false); err != nil || len(w.AssetLists) != 0 {
		t.Fatalf("unyank: %+v %v", w, err)
	}
	w, err = svc.DeleteVersion("acme", "scanners", "1.1.0")
	if err != nil || len(w.AssetLists) != 1 || !strings.Contains(w.AssetLists[0], "acme/login") {
		t.Fatalf("delete: %+v %v", w, err)
	}
}

// TestMoveRefusedWithListDependencies: a package that depends on lists cannot
// move to another namespace, but can be renamed in place.
func TestMoveRefusedWithListDependencies(t *testing.T) {
	svc := newTestRegistry(t)
	mustEnsureNS(t, svc, "other", database.VisibilityPrivate)
	authorList(t, svc, "acme", "scanners", "1.0.0", "Scanners", false)
	if err := pageWithLists(svc, "acme", "login", "1.0.0", []string{"Scanners"}, []string{"acme/scanners"}); err != nil {
		t.Fatal(err)
	}
	err := svc.MovePackage("acme", "login", "other", "")
	if err == nil || !IsValidation(err) || !strings.Contains(err.Error(), "move or recreate the lists") {
		t.Fatalf("move with list deps: %v", err)
	}
	if err := svc.MovePackage("acme", "login", "acme", "login2"); err != nil {
		t.Fatalf("rename in place: %v", err)
	}
}

// TestBundleNeedNotReferenceMemberDependencies: Phishing Club installs a
// member's own list dependencies, so a bundle does not list them and a member
// gaining one never blocks on the bundle.
func TestBundleNeedNotReferenceMemberDependencies(t *testing.T) {
	svc := newTestRegistry(t)
	authorList(t, svc, "acme", "scanners", "1.0.0", "Scanners", false)
	if err := pageWithLists(svc, "acme", "login", "1.0.0", []string{"Scanners"}, []string{"acme/scanners"}); err != nil {
		t.Fatal(err)
	}
	if _, err := publishBundle(svc, "acme", "kit", "1.0.0", []manifest.Dependency{{ID: "acme/login", Range: "*"}}); err != nil {
		t.Fatalf("bundle without the member dependency: %v", err)
	}
	authorList(t, svc, "acme", "bots", "1.0.0", "Bots", false)
	if err := pageWithLists(svc, "acme", "login", "1.1.0", []string{"Scanners", "Bots"},
		[]string{"acme/scanners", "acme/bots"}); err != nil {
		t.Fatalf("member gaining a dependency: %v", err)
	}
}

func TestPackageLists(t *testing.T) {
	files := map[string][]byte{
		"content/a/data.yaml": []byte("allowDenies:\n  - name: \" B \"\n    allowed: yes\n  - name: A\n"),
		"content/b/data.yaml": []byte("allowDenies: [unclosed"),
	}
	got := PackageLists(files)
	if len(got) != 2 || got[0] != (PackageList{Name: "A"}) || got[1] != (PackageList{Name: "B", Allowed: true}) {
		t.Fatalf("got %+v", got)
	}
}

// TestImportAssetLists: an import resolves asset lists against a list package
// in the same bundle, and refuses a page whose list does not resolve.
func TestImportAssetLists(t *testing.T) {
	src := newTestRegistry(t)
	authorList(t, src, "acme", "scanners", "1.0.0", "Scanners", false)
	if err := pageWithLists(src, "acme", "login", "1.0.0", []string{"Scanners"}, []string{"acme/scanners"}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := src.ExportBundle(&buf); err != nil {
		t.Fatal(err)
	}
	dst := newTestRegistry(t)
	sum, err := dst.ImportBundle(bytes.NewReader(buf.Bytes()))
	if err != nil || sum.Packages != 2 || len(sum.Refused) != 0 {
		t.Fatalf("sum=%+v err=%v", sum, err)
	}

	// a page archive built outside Bait Box that names a list it does not depend on.
	files := map[string][]byte{
		"content/login/data.yaml": []byte("assets:\n  - path: logo.png\n    allowDeny:\n      - Scanners\n"),
		"assets/logo.png":         []byte("png"),
	}
	page, _, err := buildArchiveUnchecked(PackageSpec{ID: "acme/login", Type: manifest.TypePage, Version: "1.0.0"}, files)
	if err != nil {
		t.Fatal(err)
	}
	b := exportBundle{
		Format:     bundleFormat,
		Namespaces: []nsDTO{{Name: "acme", Visibility: database.VisibilityPrivate}},
		Packages:   []pkgDTO{{Namespace: "acme", Name: "login", Type: manifest.TypePage}},
		Versions:   []verDTO{{Namespace: "acme", Name: "login", Version: "1.0.0", ArchiveSha: bundleSha(page)}},
	}
	other := newTestRegistry(t)
	sum, err = other.ImportBundle(bytes.NewReader(makeBundleTar(t, b, map[string][]byte{bundleSha(page): page})))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(sum.Refused) != 1 || sum.Refused[0] != "acme/login" ||
		len(sum.Warnings) != 1 || !strings.Contains(sum.Warnings[0], "allow / deny list that does not resolve") {
		t.Fatalf("summary = %+v", sum)
	}
}

// TestListPublishRefusedWhenDependentChanges: the list breaks of a new list
// version are found before the write, so a dependent that changes in between
// refuses the publish as a concurrent change instead of letting a version in
// that breaks it.
func TestListPublishRefusedWhenDependentChanges(t *testing.T) {
	svc := newTestRegistry(t)
	authorList(t, svc, "acme", "scanners", "1.0.0", "Scanners", false)
	if err := pageWithLists(svc, "acme", "login", "1.0.0", []string{"Scanners"}, []string{"acme/scanners"}); err != nil {
		t.Fatal(err)
	}
	svc.beforeWriteCommit = func() {
		svc.beforeWriteCommit = nil
		if err := pageWithLists(svc, "acme", "login", "1.1.0", []string{"Scanners"}, []string{"acme/scanners"}); err != nil {
			t.Errorf("publish the dependent in between: %v", err)
		}
	}
	_, _, err := svc.AuthorPackage(AuthoredPackage{
		Namespace: "acme", Name: "scanners", Type: manifest.TypeAllowDeny, Version: "1.1.0",
		Files: map[string][]byte{"content/scanners/data.yaml": []byte(listDoc("Scanners", false))},
	})
	if !errors.Is(err, ErrConcurrentChange) {
		t.Fatalf("err = %v, want a concurrent change", err)
	}
	// with nothing in between the same version publishes.
	authorList(t, svc, "acme", "scanners", "1.1.0", "Scanners", false)
}
