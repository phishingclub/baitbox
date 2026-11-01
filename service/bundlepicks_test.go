package service

import (
	"bytes"
	"strings"
	"testing"

	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/manifest"
)

func publishPageVars(t *testing.T, svc *RegistryService, ns, name string, vars []manifest.Variable) {
	t.Helper()
	if err := publishPageVersionVars(svc, ns, name, "1.0.0", vars); err != nil {
		t.Fatalf("publish %s/%s: %v", ns, name, err)
	}
}

func publishPageVersionVars(svc *RegistryService, ns, name, version string, vars []manifest.Variable) error {
	_, _, err := svc.AuthorPackage(AuthoredPackage{
		Namespace: ns, Name: name, Type: manifest.TypePage, Version: version, Title: name,
		Variables: vars,
		Files:     map[string][]byte{"content/index.html": []byte("<h1>" + name + " " + version + "</h1>")},
	})
	return err
}

func publishBundleVars(svc *RegistryService, ns, name string, deps []manifest.Dependency, vars []manifest.Variable, share *bool) error {
	_, _, err := svc.AuthorPackage(AuthoredPackage{
		Namespace: ns, Name: name, Type: manifest.TypeBundle, Version: "1.0.0",
		Dependencies: deps, Variables: vars, ShareVariables: share,
		Files: map[string][]byte{"content/bundle.txt": []byte("kit")},
	})
	return err
}

func TestBundleSharedPickMismatch(t *testing.T) {
	plain := manifest.Variable{Name: "OWN_DOMAIN", Type: manifest.VarText}
	pickDomain := manifest.Variable{Name: "OWN_DOMAIN", Type: manifest.VarText, Required: true, Pick: "domain"}
	pickProxy := manifest.Variable{Name: "OWN_DOMAIN", Type: manifest.VarText, Required: true, Pick: "proxy"}
	no := false
	cases := []struct {
		name      string
		member    []manifest.Variable
		bundle    []manifest.Variable
		share     *bool
		wantError bool
	}{
		{"pick in bundle plain in member", []manifest.Variable{plain}, []manifest.Variable{pickDomain}, nil, true},
		{"plain in bundle pick in member", []manifest.Variable{pickDomain}, []manifest.Variable{plain}, nil, true},
		{"different pick kinds", []manifest.Variable{pickProxy}, []manifest.Variable{pickDomain}, nil, true},
		{"same pick kind", []manifest.Variable{pickDomain}, []manifest.Variable{pickDomain}, nil, false},
		{"both plain", []manifest.Variable{plain}, []manifest.Variable{plain}, nil, false},
		{"not shared", []manifest.Variable{plain}, []manifest.Variable{pickDomain}, &no, false},
	}
	for _, c := range cases {
		svc := newTestRegistry(t)
		mustEnsureNS(t, svc, "team", database.VisibilityPrivate)
		publishPageVars(t, svc, "team", "lure", c.member)
		err := publishBundleVars(svc, "team", "kit", []manifest.Dependency{{ID: "team/lure", Range: "^1.0.0"}}, c.bundle, c.share)
		if c.wantError {
			if err == nil || !IsValidation(err) || !strings.Contains(err.Error(), "shared variable \"OWN_DOMAIN\"") {
				t.Errorf("%s: want refusal, got %v", c.name, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// two members that disagree with each other are refused too, not only the bundle.
func TestBundleSharedPickMismatchBetweenMembers(t *testing.T) {
	svc := newTestRegistry(t)
	mustEnsureNS(t, svc, "team", database.VisibilityPrivate)
	publishPageVars(t, svc, "team", "a", []manifest.Variable{{Name: "X", Type: manifest.VarText, Required: true, Pick: "page"}})
	publishPageVars(t, svc, "team", "b", []manifest.Variable{{Name: "X", Type: manifest.VarText}})
	err := publishBundleVars(svc, "team", "kit", []manifest.Dependency{
		{ID: "team/a", Range: "^1.0.0"}, {ID: "team/b", Range: "^1.0.0"},
	}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "team/a") || !strings.Contains(err.Error(), "team/b") {
		t.Fatalf("want refusal naming both members, got %v", err)
	}
}

// a list pick shared by two members must be an allowDeny pick in both, since Phishing Club fills the shared name once.
func TestBundleSharedAllowDenyPick(t *testing.T) {
	pick := manifest.Variable{Name: "SCANNER_LIST", Type: manifest.VarText, Required: true, Pick: manifest.PickAllowDeny}
	plain := manifest.Variable{Name: "SCANNER_LIST", Type: manifest.VarText, Required: true}
	svc := newTestRegistry(t)
	mustEnsureNS(t, svc, "team", database.VisibilityPrivate)
	publishPageVars(t, svc, "team", "a", []manifest.Variable{pick})
	publishPageVars(t, svc, "team", "b", []manifest.Variable{pick})
	publishPageVars(t, svc, "team", "c", []manifest.Variable{plain})
	if err := publishBundleVars(svc, "team", "same", []manifest.Dependency{
		{ID: "team/a", Range: "^1.0.0"}, {ID: "team/b", Range: "^1.0.0"},
	}, nil, nil); err != nil {
		t.Fatalf("same allowDeny pick refused: %v", err)
	}
	err := publishBundleVars(svc, "team", "mixed", []manifest.Dependency{
		{ID: "team/a", Range: "^1.0.0"}, {ID: "team/c", Range: "^1.0.0"},
	}, nil, nil)
	if err == nil || !IsValidation(err) || !strings.Contains(err.Error(), "an allowDeny pick") {
		t.Fatalf("want refusal of a mixed allowDeny pick, got %v", err)
	}
}

func TestImportRefusesBundleSharedPickMismatch(t *testing.T) {
	member, _, err := BuildArchive(PackageSpec{
		ID: "acme/lure", Type: manifest.TypePage, Version: "1.0.0",
		Variables: []manifest.Variable{{Name: "OWN_SMTP", Type: manifest.VarText}},
	}, map[string][]byte{"content/index.html": []byte("hi")})
	if err != nil {
		t.Fatal(err)
	}
	bundle, _, err := BuildArchive(PackageSpec{
		ID: "acme/kit", Type: manifest.TypeBundle, Version: "1.0.0",
		Dependencies: []manifest.Dependency{{ID: "acme/lure", Range: "^1.0.0"}},
		Variables:    []manifest.Variable{{Name: "OWN_SMTP", Type: manifest.VarText, Required: true, Pick: "smtpConfiguration"}},
	}, map[string][]byte{"content/bundle.txt": []byte("kit")})
	if err != nil {
		t.Fatal(err)
	}
	ms, bs := bundleSha(member), bundleSha(bundle)
	tarball := makeBundleTar(t, exportBundle{
		Format:     bundleFormat,
		Namespaces: []nsDTO{{Name: "acme", Visibility: database.VisibilityPrivate}},
		Packages: []pkgDTO{
			{Namespace: "acme", Name: "lure", Type: manifest.TypePage},
			{Namespace: "acme", Name: "kit", Type: manifest.TypeBundle},
		},
		Versions: []verDTO{
			{Namespace: "acme", Name: "lure", Version: "1.0.0", ArchiveSha: ms},
			{Namespace: "acme", Name: "kit", Version: "1.0.0", ArchiveSha: bs},
		},
	}, map[string][]byte{ms: member, bs: bundle})

	dst := newTestRegistry(t)
	sum, err := dst.ImportBundle(bytes.NewReader(tarball))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(sum.Refused) != 1 || sum.Refused[0] != "acme/kit" || sum.Packages != 1 {
		t.Fatalf("summary = %+v", sum)
	}
	if !strings.Contains(strings.Join(sum.Warnings, "\n"), "shared variable \"OWN_SMTP\"") {
		t.Fatalf("warnings = %v", sum.Warnings)
	}
}

func TestMemberVersionRefusedWhenItBreaksBundlePicks(t *testing.T) {
	plain := []manifest.Variable{{Name: "OWN_DOMAIN", Type: manifest.VarText}}
	pick := []manifest.Variable{{Name: "OWN_DOMAIN", Type: manifest.VarText, Required: true, Pick: "domain"}}
	proxy := []manifest.Variable{{Name: "OWN_DOMAIN", Type: manifest.VarText, Required: true, Pick: "proxy"}}
	deps := []manifest.Dependency{{ID: "team/lure", Range: "^1.0.0"}}

	svc := newTestRegistry(t)
	mustEnsureNS(t, svc, "team", database.VisibilityPrivate)
	publishPageVars(t, svc, "team", "lure", plain)
	if err := publishBundleVars(svc, "team", "kit", deps, plain, nil); err != nil {
		t.Fatalf("bundle: %v", err)
	}
	err := publishPageVersionVars(svc, "team", "lure", "1.1.0", pick)
	if err == nil || !IsValidation(err) || !strings.Contains(err.Error(), "team/kit") ||
		!strings.Contains(err.Error(), "shared variable \"OWN_DOMAIN\"") {
		t.Fatalf("pick replacing plain: want refusal, got %v", err)
	}
	// an older version does not become latest, so the bundle is unaffected.
	if err := publishPageVersionVars(svc, "team", "lure", "0.9.0", pick); err != nil {
		t.Fatalf("older version: %v", err)
	}
	if err := publishPageVersionVars(svc, "team", "lure", "1.1.0", plain); err != nil {
		t.Fatalf("matching version: %v", err)
	}

	// a bundle with matching picks refuses a member version with another kind.
	svc2 := newTestRegistry(t)
	mustEnsureNS(t, svc2, "team", database.VisibilityPrivate)
	publishPageVars(t, svc2, "team", "lure", pick)
	if err := publishBundleVars(svc2, "team", "kit", deps, pick, nil); err != nil {
		t.Fatalf("bundle: %v", err)
	}
	if err := publishPageVersionVars(svc2, "team", "lure", "1.1.0", proxy); err == nil || !IsValidation(err) {
		t.Fatalf("other pick kind: want refusal, got %v", err)
	}

	// a bundle that does not share variables accepts any member version.
	no := false
	svc3 := newTestRegistry(t)
	mustEnsureNS(t, svc3, "team", database.VisibilityPrivate)
	publishPageVars(t, svc3, "team", "lure", plain)
	if err := publishBundleVars(svc3, "team", "kit", deps, plain, &no); err != nil {
		t.Fatalf("bundle: %v", err)
	}
	if err := publishPageVersionVars(svc3, "team", "lure", "1.1.0", pick); err != nil {
		t.Fatalf("unshared bundle: %v", err)
	}
}

func TestImportRefusesMemberVersionThatBreaksLocalBundle(t *testing.T) {
	dst := newTestRegistry(t)
	mustEnsureNS(t, dst, "acme", database.VisibilityPrivate)
	plain := []manifest.Variable{{Name: "OWN_SMTP", Type: manifest.VarText}}
	publishPageVars(t, dst, "acme", "lure", plain)
	if err := publishBundleVars(dst, "acme", "kit", []manifest.Dependency{{ID: "acme/lure", Range: "^1.0.0"}}, plain, nil); err != nil {
		t.Fatalf("bundle: %v", err)
	}
	member, _, err := BuildArchive(PackageSpec{
		ID: "acme/lure", Type: manifest.TypePage, Version: "1.1.0",
		Variables: []manifest.Variable{{Name: "OWN_SMTP", Type: manifest.VarText, Required: true, Pick: "smtpConfiguration"}},
	}, map[string][]byte{"content/index.html": []byte("hi")})
	if err != nil {
		t.Fatal(err)
	}
	sha := bundleSha(member)
	tarball := makeBundleTar(t, exportBundle{
		Format:     bundleFormat,
		Namespaces: []nsDTO{{Name: "acme", Visibility: database.VisibilityPrivate}},
		Packages:   []pkgDTO{{Namespace: "acme", Name: "lure", Type: manifest.TypePage}},
		Versions:   []verDTO{{Namespace: "acme", Name: "lure", Version: "1.1.0", ArchiveSha: sha}},
	}, map[string][]byte{sha: member})
	sum, err := dst.ImportBundle(bytes.NewReader(tarball))
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if len(sum.Refused) != 1 || sum.Refused[0] != "acme/lure" || sum.Versions != 0 {
		t.Fatalf("summary = %+v", sum)
	}
	w := strings.Join(sum.Warnings, "\n")
	if !strings.Contains(w, "acme/kit") || !strings.Contains(w, "shared variable \"OWN_SMTP\"") {
		t.Fatalf("warnings = %v", sum.Warnings)
	}
	if _, _, v, rerr := dst.Resolve("acme", "lure", "latest"); rerr != nil || v.Version != "1.0.0" {
		t.Fatalf("latest = %v (err %v)", v, rerr)
	}
}
