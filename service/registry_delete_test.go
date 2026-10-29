package service

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/manifest"
)

// The only version of a package cannot be deleted, so the index never lists a
// package that resolves to nothing. Deleting the package is the way out.
func TestDeleteLastVersionRefused(t *testing.T) {
	svc := newTestRegistry(t)
	publishPage(t, svc, "acme", "lure", "1.0.0")
	publishPage(t, svc, "acme", "lure", "1.1.0")

	if _, err := svc.DeleteVersion("acme", "lure", "1.1.0"); err != nil {
		t.Fatalf("delete one of two versions: %v", err)
	}
	_, err := svc.DeleteVersion("acme", "lure", "1.0.0")
	if !errors.Is(err, ErrLastVersion) || !IsValidation(err) {
		t.Fatalf("delete the last version: want ErrLastVersion as a validation error, got %v", err)
	}
	if _, _, v, err := svc.Resolve("acme", "lure", "latest"); err != nil || v.Version != "1.0.0" {
		t.Fatalf("last version was removed: %v %v", v, err)
	}
	if err := svc.DeletePackage("acme", "lure"); err != nil {
		t.Fatalf("delete package: %v", err)
	}
	if _, _, _, err := svc.Resolve("acme", "lure", "latest"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("package still resolves after delete: %v", err)
	}
}

// Deleting a package removes its versions, previews and row together and
// cleans up every blob they used.
func TestDeletePackageRemovesEverything(t *testing.T) {
	db := newTestDB(t)
	svc := registryOverDB(t, db)
	v1 := publishPage(t, svc, "acme", "kit", "1.0.0")
	v2 := publishPage(t, svc, "acme", "kit", "2.0.0")
	sha, err := svc.AddPreviewImage("acme", "kit", encode(t, "png", 16, 16))
	if err != nil {
		t.Fatalf("add preview: %v", err)
	}
	if err := svc.DeletePackage("acme", "kit"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	for _, model := range []any{&database.Package{}, &database.PackageVersion{}, &database.PackagePreview{}} {
		var n int64
		if err := db.Model(model).Count(&n).Error; err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("%T rows left after delete: %d", model, n)
		}
	}
	for _, s := range []string{v1.ArchiveBlobSHA256, v2.ArchiveBlobSHA256, sha} {
		if _, err := os.Stat(svc.blobs.path(s)); !os.IsNotExist(err) {
			t.Fatalf("blob %s left after delete: %v", s, err)
		}
	}
}

// A secret variable is refused at authoring when it carries a default or is
// optional, and the refusal is a validation error the operator sees.
func TestAuthorRefusesSecretDefault(t *testing.T) {
	svc := newTestRegistry(t)
	def := "hunter2"
	for _, v := range []manifest.Variable{
		{Name: "API_KEY", Type: manifest.VarSecret, Default: &def},
		{Name: "API_KEY", Type: manifest.VarSecret},
	} {
		_, _, err := svc.AuthorPackage(AuthoredPackage{
			Namespace: "acme", Name: "hook", Type: manifest.TypePage, Version: "1.0.0",
			Variables: []manifest.Variable{v},
			Files:     map[string][]byte{"content/index.html": []byte("<p>{{.API_KEY}}</p>")},
		})
		if err == nil || !IsValidation(err) {
			t.Fatalf("secret %+v: want a validation error, got %v", v, err)
		}
	}
	_, _, err := svc.AuthorPackage(AuthoredPackage{
		Namespace: "acme", Name: "hook", Type: manifest.TypePage, Version: "1.0.0",
		Variables: []manifest.Variable{{Name: "API_KEY", Type: manifest.VarSecret, Required: true}},
		Files:     map[string][]byte{"content/index.html": []byte("<p>{{.API_KEY}}</p>")},
	})
	if err != nil {
		t.Fatalf("required secret without default: %v", err)
	}
}

// A package that another package's version depends on cannot be deleted, so
// no stored version is left naming a free address. Older versions count too.
func TestDeletePackageRefusedWithDependents(t *testing.T) {
	svc := newTestRegistry(t)
	mustEnsureNS(t, svc, "pub", database.VisibilityPublic)
	publishPage(t, svc, "pub", "base", "1.0.0")
	dep := []manifest.Dependency{{ID: "pub/base", Range: "^1.0.0"}}
	if _, err := publishBundle(svc, "pub", "kit", "1.0.0", dep); err != nil {
		t.Fatal(err)
	}
	publishPage(t, svc, "pub", "other", "1.0.0")
	if _, err := publishBundle(svc, "pub", "kit", "2.0.0", []manifest.Dependency{{ID: "pub/other", Range: "^1.0.0"}}); err != nil {
		t.Fatal(err)
	}

	err := svc.DeletePackage("pub", "base")
	var depErr *DependentsError
	if !errors.As(err, &depErr) {
		t.Fatalf("delete with a dependent: want DependentsError, got %v", err)
	}
	if len(depErr.Dependents) != 1 || depErr.Dependents[0] != "pub/kit" ||
		!strings.Contains(err.Error(), "pub/kit") {
		t.Fatalf("refusal does not name the dependent: %v %v", depErr.Dependents, err)
	}
	if _, _, _, err := svc.Resolve("pub", "base", "latest"); err != nil {
		t.Fatalf("refused delete removed the package: %v", err)
	}

	// once no version names it, the delete goes through.
	if _, err := svc.DeleteVersion("pub", "kit", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeletePackage("pub", "base"); err != nil {
		t.Fatalf("delete without dependents: %v", err)
	}
}
