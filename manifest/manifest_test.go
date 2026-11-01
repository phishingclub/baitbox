package manifest

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// a syntactically valid 64 character hex sha256 for fixtures.
const fakeSHA = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

func validEntries() []Entry {
	return []Entry{{Path: "content/p.html", SHA256: fakeSHA}}
}

func baseManifest() *Manifest {
	es := validEntries()
	return &Manifest{
		Format: Format, ID: "acme-corp/thing", Type: TypePage, Version: "1.0.0",
		Entries: es, ContentHash: ComputeContentHash(es),
	}
}

func TestValidateOK(t *testing.T) {
	if err := baseManifest().Validate(); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
}

func TestValidateShareVariablesBundleOnly(t *testing.T) {
	m := baseManifest()
	off := false
	m.ShareVariables = &off
	if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "only to a bundle") {
		t.Fatalf("shareVariables on a page: err = %v", err)
	}
	m.Type = TypeBundle
	m.Dependencies = []Dependency{{ID: "acme-corp/page", Range: "*"}}
	if err := m.Validate(); err != nil {
		t.Fatalf("shareVariables on a bundle rejected: %v", err)
	}
}

func TestValidateBadID(t *testing.T) {
	m := baseManifest()
	m.ID = "NoSlash"
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for id without namespace/name")
	}
}

func TestValidateBadVersion(t *testing.T) {
	m := baseManifest()
	m.Version = "v1"
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for non-semver version")
	}
}

func TestValidateBadType(t *testing.T) {
	m := baseManifest()
	m.Type = "virus"
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for unknown type")
	}
}

func TestValidateRequiredSecretWithDefault(t *testing.T) {
	m := baseManifest()
	def := "leak"
	m.Variables = []Variable{{Name: "API_KEY", Type: VarSecret, Required: true, Default: &def}}
	if err := m.Validate(); err == nil {
		t.Fatal("expected error: a required secret cannot carry a default value")
	}
}

func TestValidateSecretRules(t *testing.T) {
	def := "leak"
	empty := ""
	cases := []struct {
		name string
		v    Variable
		ok   bool
	}{
		{"required no default", Variable{Name: "API_KEY", Type: VarSecret, Required: true}, true},
		{"optional with default", Variable{Name: "API_KEY", Type: VarSecret, Default: &def}, false},
		{"optional empty default", Variable{Name: "API_KEY", Type: VarSecret, Default: &empty}, false},
		{"optional no default", Variable{Name: "API_KEY", Type: VarSecret}, false},
		{"text optional with default", Variable{Name: "GREETING", Type: VarText, Default: &def}, true},
	}
	for _, tc := range cases {
		m := baseManifest()
		m.Variables = []Variable{tc.v}
		err := m.Validate()
		if tc.ok && err != nil {
			t.Errorf("%s: unexpected error %v", tc.name, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("%s: expected an error", tc.name)
		}
	}
}

func TestValidateContentHashMismatch(t *testing.T) {
	m := baseManifest()
	m.ContentHash = "deadbeef"
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for content hash not matching entries")
	}
}

func TestValidateEmptyEntries(t *testing.T) {
	m := baseManifest()
	m.Entries = nil
	m.ContentHash = ComputeContentHash(nil)
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for empty entries")
	}
}

func TestValidateRejectsDuplicateEntry(t *testing.T) {
	m := baseManifest()
	m.Entries = []Entry{{Path: "content/p.html", SHA256: fakeSHA}, {Path: "content/p.html", SHA256: fakeSHA}}
	m.ContentHash = ComputeContentHash(m.Entries)
	if err := m.Validate(); err == nil {
		t.Fatal("expected error for duplicate entry path")
	}
}

func TestValidateRejectsNonCanonicalEntry(t *testing.T) {
	for _, p := range []string{"content//p.html", "./content/p.html", "content/./p.html", "content/../assets/x", "/content/p.html", "other/p.html", "baitbox.json", "content/"} {
		m := baseManifest()
		m.Entries = []Entry{{Path: p, SHA256: fakeSHA}}
		m.ContentHash = ComputeContentHash(m.Entries)
		if err := m.Validate(); err == nil {
			t.Fatalf("expected error for entry path %q", p)
		}
	}
}

func TestValidVersionSemverRules(t *testing.T) {
	for _, v := range []string{"1.0.0", "0.1.0", "10.20.30", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-0.3.7"} {
		if !ValidVersion(v) {
			t.Fatalf("%q should be valid", v)
		}
	}
	for _, v := range []string{"01.0.0", "1.00.0", "1.0.01", "1.0.0-01", "1.0.0-alpha..1", "v1.0.0", "1.0", "1.0.0+build"} {
		if ValidVersion(v) {
			t.Fatalf("%q should be invalid", v)
		}
	}
}

func TestValidEntryPathRejectsBackslashAndControl(t *testing.T) {
	for _, p := range []string{`content\..\x`, `content\x`, "content/a\x00b", "content/a\nb", "assets/\x7f"} {
		if ValidEntryPath(p) {
			t.Fatalf("ValidEntryPath(%q) = true", p)
		}
	}
	for _, p := range []string{"content/index.html", "assets/img/ü.png"} {
		if !ValidEntryPath(p) {
			t.Fatalf("ValidEntryPath(%q) = false", p)
		}
	}
}

func TestValidatePreviewMustBeRasterImage(t *testing.T) {
	for _, p := range []string{"assets/t.png", "assets/t.JPG", "assets/t.jpeg", "assets/t.gif", "assets/t.webp"} {
		m := baseManifest()
		m.Entries = append(m.Entries, Entry{Path: p, SHA256: fakeSHA})
		m.ContentHash = ComputeContentHash(m.Entries)
		m.Preview = p
		if err := m.Validate(); err != nil {
			t.Errorf("preview %q rejected: %v", p, err)
		}
	}
	for _, p := range []string{"assets/t.svg", "assets/t.html", "assets/t", "assets/t.png.svg"} {
		m := baseManifest()
		m.Entries = append(m.Entries, Entry{Path: p, SHA256: fakeSHA})
		m.ContentHash = ComputeContentHash(m.Entries)
		m.Preview = p
		if err := m.Validate(); err == nil {
			t.Errorf("preview %q accepted", p)
		}
	}
}

func TestValidateDependencyCap(t *testing.T) {
	deps := func(n int) []Dependency {
		out := make([]Dependency, n)
		for i := range out {
			out[i] = Dependency{ID: fmt.Sprintf("acme-corp/dep-%d", i), Range: "^1.0.0"}
		}
		return out
	}
	m := baseManifest()
	m.Dependencies = deps(MaxDependencies)
	if err := m.Validate(); err != nil {
		t.Fatalf("manifest at the dependency cap rejected: %v", err)
	}
	m.Dependencies = deps(MaxDependencies + 1)
	err := m.Validate()
	if err == nil || !strings.Contains(err.Error(), "the limit is 100") {
		t.Fatalf("expected dependency cap error, got %v", err)
	}
}

// TestParseRefusesUnknownKeys: a manifest round trips, and any key that is not
// part of Manifest is refused.
func TestParseRefusesUnknownKeys(t *testing.T) {
	m := baseManifest()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(b)
	if err != nil {
		t.Fatalf("manifest rejected: %v", err)
	}
	if got.ContentHash != m.ContentHash {
		t.Fatalf("content hash changed: %s != %s", got.ContentHash, m.ContentHash)
	}
	for _, key := range []string{"author", "license", "unknownKey"} {
		var raw map[string]any
		if err := json.Unmarshal(b, &raw); err != nil {
			t.Fatal(err)
		}
		raw[key] = "x"
		bad, _ := json.Marshal(raw)
		if _, err := Parse(bad); err == nil {
			t.Fatalf("key %q accepted", key)
		}
	}
}

func TestValidEntryPathRejectsHiddenNames(t *testing.T) {
	bad := []string{
		"content/ a.html", "content/a.html ", "content/a /b.html", "content/\u00a0x",
		"content/evil\u202egnp.html", "content/a\u200bb", "content/a\ufeffb", "content/a\u2028b",
		"content/\xff.html", "content/./a", "content/../a", "content//a", "content/a/", "./content/a",
		"content/.", "content/..",
	}
	for _, p := range bad {
		if ValidEntryPath(p) {
			t.Errorf("ValidEntryPath(%q) = true", p)
		}
	}
	for _, p := range []string{"content/a b.html", "assets/.well/x", "content/日本.txt"} {
		if !ValidEntryPath(p) {
			t.Errorf("ValidEntryPath(%q) = false", p)
		}
	}
}

func TestValidateRejectsCaseOnlyDuplicates(t *testing.T) {
	m := baseManifest()
	m.Entries = []Entry{{Path: "content/Index.html", SHA256: fakeSHA}, {Path: "content/index.html", SHA256: fakeSHA}}
	m.ContentHash = ComputeContentHash(m.Entries)
	if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "case") {
		t.Fatalf("entries differing only by case: %v", err)
	}
}

func TestValidatePickRules(t *testing.T) {
	def := "mine"
	cases := []struct {
		name string
		v    Variable
		ok   bool
	}{
		{"required pick", Variable{Name: "OWN_SMTP", Type: VarText, Required: true, Pick: "smtpConfiguration"}, true},
		{"optional pick", Variable{Name: "OWN_PAGE", Type: VarText, Pick: "page"}, true},
		{"pick with default", Variable{Name: "OWN_PAGE", Type: VarText, Pick: "page", Default: &def}, false},
		{"unknown kind", Variable{Name: "OWN_X", Type: VarText, Required: true, Pick: "webhook"}, false},
		{"kind case differs", Variable{Name: "OWN_X", Type: VarText, Required: true, Pick: "Domain"}, false},
		{"list pick", Variable{Name: "ALLOW_DENY_LIST", Type: VarText, Required: true, Pick: PickAllowDeny}, true},
		{"optional list pick", Variable{Name: "ALLOW_DENY_LIST", Type: VarText, Pick: PickAllowDeny}, false},
		{"list kind case differs", Variable{Name: "ALLOW_DENY_LIST", Type: VarText, Required: true, Pick: "allowdeny"}, false},
		{"split list kind", Variable{Name: "DENY_LIST", Type: VarText, Required: true, Pick: "denyList"}, false},
	}
	for _, c := range cases {
		m := baseManifest()
		m.Variables = []Variable{c.v}
		err := m.Validate()
		if c.ok && err != nil {
			t.Errorf("%s: rejected: %v", c.name, err)
		}
		if !c.ok && err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
	for k := range validPickKinds {
		m := baseManifest()
		m.Variables = []Variable{{Name: "OWN_X", Type: VarText, Required: true, Pick: k}}
		if err := m.Validate(); err != nil {
			t.Errorf("kind %s rejected: %v", k, err)
		}
	}
}
