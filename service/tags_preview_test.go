package service

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/phishingclub/baitbox/manifest"
)

// TestSetTagColorRequiresTagInUse: a color can only be set for a tag a package
// carries, so the endpoint cannot fill the table with permanent orphan rows.
func TestSetTagColorRequiresTagInUse(t *testing.T) {
	svc := newTestRegistry(t)
	publishPage(t, svc, "acme", "thing", "1.0.0")
	if err := svc.SetTagColor("nobody", "red"); !errors.Is(err, ErrTagNotInUse) {
		t.Fatalf("want ErrTagNotInUse, got %v", err)
	}
	// a LIKE wildcard in the name must not match some other tag.
	if err := svc.UpdatePackageMeta("acme", "thing", "T", "", "o365,login"); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetTagColor("o3%", "red"); !errors.Is(err, ErrTagNotInUse) {
		t.Fatalf("wildcard matched: %v", err)
	}
	if err := svc.SetTagColor("o365", "red"); err != nil {
		t.Fatalf("tag in use rejected: %v", err)
	}
	tags, _ := svc.ListTags()
	if len(tags) != 1 || tags[0].Name != "o365" || tags[0].Color != "red" {
		t.Fatalf("tags = %+v", tags)
	}
}

// TestTagRowsPrunedWhenUnused: a tag color row goes away once no package carries
// the tag, after a meta edit or a package delete.
func TestTagRowsPrunedWhenUnused(t *testing.T) {
	svc := newTestRegistry(t)
	publishPage(t, svc, "acme", "one", "1.0.0")
	publishPage(t, svc, "acme", "two", "1.0.0")
	if err := svc.UpdatePackageMeta("acme", "one", "One", "", "alpha,beta"); err != nil {
		t.Fatal(err)
	}
	if err := svc.UpdatePackageMeta("acme", "two", "Two", "", "Beta"); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"alpha", "beta"} {
		if err := svc.SetTagColor(n, "blue"); err != nil {
			t.Fatalf("set %s: %v", n, err)
		}
	}
	// one drops alpha: no package carries it, so its row goes.
	if err := svc.UpdatePackageMeta("acme", "one", "One", "", "beta"); err != nil {
		t.Fatal(err)
	}
	names := func() string {
		tags, _ := svc.ListTags()
		var out []string
		for _, tg := range tags {
			out = append(out, tg.Name)
		}
		return strings.Join(out, ",")
	}
	if got := names(); got != "beta" {
		t.Fatalf("after edit tags = %q", got)
	}
	// beta is still on two (stored as Beta) after one is deleted.
	if err := svc.DeletePackage("acme", "one"); err != nil {
		t.Fatal(err)
	}
	if got := names(); got != "beta" {
		t.Fatalf("after first delete tags = %q", got)
	}
	if err := svc.DeletePackage("acme", "two"); err != nil {
		t.Fatal(err)
	}
	if got := names(); got != "" {
		t.Fatalf("after last delete tags = %q", got)
	}
}

// TestManifestPreviewMustBeRasterImage: the manifest thumbnail must name a png,
// jpeg, gif or webp asset whose bytes are that type, at publish and import.
func TestManifestPreviewMustBeRasterImage(t *testing.T) {
	svc := newTestRegistry(t)
	png := encode(t, "png", 16, 16)
	gif := encode(t, "gif", 16, 16)
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)
	publish := func(name, preview string, files map[string][]byte) error {
		files["content/index.html"] = []byte("<p>x</p>")
		_, _, err := svc.AuthorPackage(AuthoredPackage{
			Namespace: "acme", Name: name, Type: manifest.TypePage, Version: "1.0.0",
			Preview: preview, Files: files,
		})
		return err
	}
	if err := publish("ok", "assets/thumb.png", map[string][]byte{"assets/thumb.png": png}); err != nil {
		t.Fatalf("real png preview rejected: %v", err)
	}
	cases := map[string]struct {
		preview string
		files   map[string][]byte
	}{
		"svg by name":        {"assets/thumb.svg", map[string][]byte{"assets/thumb.svg": svg}},
		"html by name":       {"assets/thumb.html", map[string][]byte{"assets/thumb.html": []byte("<p>")}},
		"svg named png":      {"assets/thumb.png", map[string][]byte{"assets/thumb.png": svg}},
		"gif named png":      {"assets/thumb.png", map[string][]byte{"assets/thumb.png": gif}},
		"empty file as jpeg": {"assets/thumb.jpg", map[string][]byte{"assets/thumb.jpg": {}}},
	}
	i := 0
	for name, tc := range cases {
		i++
		if err := publish("bad"+string(rune('a'+i)), tc.preview, tc.files); err == nil {
			t.Errorf("%s: preview accepted", name)
		}
	}

	// a crafted import bundle whose archive declares an svg as a png thumbnail is
	// refused, the same rule as publish.
	archive := buildRawArchive(t, "acme/crafted", "assets/thumb.png", map[string][]byte{
		"content/index.html": []byte("<p>x</p>"),
		"assets/thumb.png":   svg,
	})
	b := exportBundle{
		Format:     bundleFormat,
		Namespaces: []nsDTO{{Name: "acme", Visibility: "private"}},
		Packages:   []pkgDTO{{Namespace: "acme", Name: "crafted", Type: manifest.TypePage}},
		Versions:   []verDTO{{Namespace: "acme", Name: "crafted", Version: "1.0.0", ArchiveSha: bundleSha(archive)}},
	}
	dst := newTestRegistry(t)
	sum, err := dst.ImportBundle(bytes.NewReader(makeBundleTar(t, b, map[string][]byte{bundleSha(archive): archive})))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(sum.Refused) != 1 || !strings.Contains(strings.Join(sum.Warnings, " "), "preview") {
		t.Fatalf("summary = %+v", sum)
	}
}

// buildRawArchive builds a package archive with a manifest preview field set.
// BuildArchive checks the preview name but not its bytes, so this stands in for
// a hostile publisher that skips the server.
func buildRawArchive(t *testing.T, id, preview string, files map[string][]byte) []byte {
	t.Helper()
	archive, _, err := BuildArchive(PackageSpec{ID: id, Type: manifest.TypePage, Version: "1.0.0", Preview: preview}, files)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return archive
}

// TestListTagsInUseMergesColors: every tag a package carries is listed once,
// sorted, in its cleaned form, with its color when one is set and empty when not.
func TestListTagsInUseMergesColors(t *testing.T) {
	svc := newTestRegistry(t)
	publishPage(t, svc, "acme", "one", "1.0.0")
	publishPage(t, svc, "acme", "two", "1.0.0")
	if err := svc.UpdatePackageMeta("acme", "one", "One", "", "beta,alpha"); err != nil {
		t.Fatal(err)
	}
	// a column written before tags were cleaned still lists under the clean name.
	_, two, _, err := svc.Resolve("acme", "two", "latest")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.repo.UpdatePackageMeta(two.ID, "Two", "", " Beta ,gamma"); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetTagColor("gamma", "red"); err != nil {
		t.Fatal(err)
	}
	got, err := svc.ListTagsInUse()
	if err != nil {
		t.Fatal(err)
	}
	want := []TagInfo{{Name: "alpha"}, {Name: "beta"}, {Name: "gamma", Color: "red"}}
	if len(got) != len(want) {
		t.Fatalf("tags = %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("tags = %+v, want %+v", got, want)
		}
	}
}
