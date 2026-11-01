package service

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/phishingclub/baitbox/manifest"
)

// goodAssetDoc is a data.yaml with a full assets block that uses a list of a
// dependency and a pick variable, in the shape the editor writes it.
const goodAssetDoc = `name: Logo kit
assets:
  - path: acme/login/logo.svg
    name: Logo
    description: "Company logo: dark"
    contentType: image/svg+xml
    headers:
      - key: Cache-Control
        value: no-store
      - key: Set-Cookie
        value: "a=b; Path=/"
    allowDeny:
      - Known scanners
  - path: acme/login/app.js
    allowDeny:
      - "@@SCANNER_LIST@@"
`

func assetFilesFor(doc string, assets ...string) map[string][]byte {
	files := map[string][]byte{"content/kit/data.yaml": []byte(doc)}
	for _, a := range assets {
		files["assets/"+a] = []byte("x")
	}
	return files
}

func TestValidateAssetBlocksGood(t *testing.T) {
	files := assetFilesFor(goodAssetDoc, "acme/login/logo.svg", "acme/login/app.js")
	if err := validateFileAssetBlocks(manifest.TypeAsset, files); err != nil {
		t.Fatalf("good assets block refused: %v", err)
	}
	// a package with no assets block, and one with an empty one, pass too.
	if err := validateFileAssetBlocks(manifest.TypeAsset, assetFilesFor("name: x\n", "a.png")); err != nil {
		t.Fatalf("no assets block refused: %v", err)
	}
	if err := validateFileAssetBlocks(manifest.TypeAsset, assetFilesFor("name: x\nassets: []\n")); err != nil {
		t.Fatalf("empty assets block refused: %v", err)
	}
}

func TestValidateAssetBlocksBad(t *testing.T) {
	entry := func(body string) string { return "assets:\n  - path: a.png\n" + body }
	long := strings.Repeat("a", 2049)
	cases := []struct {
		name, doc, want string
	}{
		{"no path", "assets:\n  - name: x\n", "has no path"},
		{"missing file", "assets:\n  - path: b.png\n", `"b.png" is not a file`},
		{"traversal path", "assets:\n  - path: ../a.png\n", "is not a file"},
		{"duplicate path", "assets:\n  - path: a.png\n  - path: a.png\n", "already described"},
		{"bad content type", entry("    contentType: text\n"), "type and subtype"},
		{"content type params broken", entry("    contentType: \"text/html; charset\"\n"), "invalid content type"},
		{"content type control char", entry("    contentType: \"text/html\\u0001\"\n"), "invalid characters"},
		{"content type too long", entry("    contentType: text/" + strings.Repeat("a", 260) + "\n"), "longer than 255"},
		{"blocked header", entry("    headers:\n      - key: Content-Length\n        value: \"1\"\n"), "Content-Length header cannot"},
		{"blocked header any case", entry("    headers:\n      - key: transfer-encoding\n        value: chunked\n"), "Transfer-Encoding header cannot"},
		{"te header", entry("    headers:\n      - key: TE\n        value: trailers\n"), "Te header cannot"},
		{"content type header", entry("    headers:\n      - key: Content-Type\n        value: text/html\n"), "use contentType"},
		{"bad header name", entry("    headers:\n      - key: \"X Bad\"\n        value: v\n"), "invalid header name"},
		{"empty header name", entry("    headers:\n      - value: v\n"), "needs a name"},
		{"long header name", entry("    headers:\n      - key: X" + strings.Repeat("a", 127) + "\n        value: v\n"), "longer than 127"},
		{"empty header value", entry("    headers:\n      - key: X-A\n"), "needs a value"},
		{"header value newline", entry("    headers:\n      - key: X-A\n        value: \"a\\r\\nX-B: c\"\n"), "invalid characters"},
		{"header value nul", entry("    headers:\n      - key: X-A\n        value: \"a\\0b\"\n"), "invalid characters"},
		{"header value control", entry("    headers:\n      - key: X-A\n        value: \"a\\u0007b\"\n"), "invalid characters"},
		{"header value too long", entry("    headers:\n      - key: X-A\n        value: " + long + "\n"), "longer than 2048"},
		{"empty list name", entry("    allowDeny:\n      - \"\"\n"), "empty list name"},
		{"duplicate list name", entry("    allowDeny:\n      - A\n      - A\n"), "twice"},
		{"list as a map", entry("    allowDeny:\n      - {name: A}\n"), "not valid"},
		{"name too long", entry("    name: " + strings.Repeat("n", 128) + "\n"), "name is longer"},
		{"description too long", entry("    description: " + strings.Repeat("d", 256) + "\n"), "description is longer"},
		{"assets not a list", "assets:\n  path: a.png\n", "not valid"},
		{"not yaml", "assets: [unclosed\n", "not valid"},
		{"lists outside an allow deny package", "allowDenies:\n  - name: Office\n    allowed: true\n" + entry(""),
			"only an allow / deny package can declare"},
	}
	for _, c := range cases {
		err := validateFileAssetBlocks(manifest.TypeAsset, assetFilesFor(c.doc, "a.png"))
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q, want it to contain %q", c.name, err, c.want)
		}
	}
}

func TestValidateAssetBlocksErrorNamesPath(t *testing.T) {
	doc := "assets:\n  - path: img/a.png\n    contentType: nope\n"
	err := validateFileAssetBlocks(manifest.TypeAsset, assetFilesFor(doc, "img/a.png"))
	if err == nil || !strings.Contains(err.Error(), `content/kit/data.yaml: asset "img/a.png"`) {
		t.Fatalf("error does not name the data.yaml and asset: %v", err)
	}
}

func TestValidateAssetBlocksAcrossFolders(t *testing.T) {
	files := assetFilesFor("assets:\n  - path: a.png\n", "a.png")
	files["content/other/data.yaml"] = []byte("assets:\n  - path: a.png\n")
	if err := validateFileAssetBlocks(manifest.TypeAsset, files); err == nil || !strings.Contains(err.Error(), "already described") {
		t.Fatalf("a path described in two folders: %v", err)
	}
}

func TestValidateAssetHeaderAllows(t *testing.T) {
	for _, h := range [][2]string{
		{"Set-Cookie", "session=1; HttpOnly"},
		{"Cache-Control", "no-store"},
		{"X-Tab", "a\tb"},
		{"Access-Control-Allow-Origin", "*"},
	} {
		if err := ValidateAssetHeader(h[0], h[1]); err != nil {
			t.Errorf("%s refused: %v", h[0], err)
		}
	}
	for _, ct := range []string{"", "text/html", "text/html; charset=utf-8", "image/svg+xml", "application/vnd.ms-excel"} {
		if err := ValidateAssetContentType(ct); err != nil {
			t.Errorf("content type %q refused: %v", ct, err)
		}
	}
}

func TestPackageAssets(t *testing.T) {
	files := assetFilesFor(goodAssetDoc, "acme/login/logo.svg", "acme/login/app.js")
	files["content/bad/data.yaml"] = []byte("assets: [unclosed")
	got := PackageAssets(files)
	want := []PackageAsset{
		{
			Path: "acme/login/logo.svg", File: "assets/acme/login/logo.svg", Name: "Logo",
			Description: "Company logo: dark", ContentType: "image/svg+xml",
			Headers:   []assetHeaderYAML{{Key: "Cache-Control", Value: "no-store"}, {Key: "Set-Cookie", Value: "a=b; Path=/"}},
			AllowDeny: []string{"Known scanners"},
		},
		{Path: "acme/login/app.js", File: "assets/acme/login/app.js", Headers: []assetHeaderYAML{}, AllowDeny: []string{"@@SCANNER_LIST@@"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	if out := PackageAssets(nil); out == nil || len(out) != 0 {
		t.Fatalf("empty input gave %#v, want an empty list", out)
	}
}

// TestInspectArchiveChecksAssets proves a raw upload cannot skip the checks the
// author flow runs: the archive inspection every publish and import goes
// through refuses a bad assets block.
func TestInspectArchiveChecksAssets(t *testing.T) {
	build := func(doc string) string {
		payload := map[string][]byte{
			"content/kit/data.yaml": []byte(doc),
			"assets/a.png":          []byte("png"),
		}
		entries := map[string][]byte{"baitbox.json": validManifestFor(payload)}
		for k, v := range payload {
			entries[k] = v
		}
		return writeArchive(t, entries)
	}
	lim := ArchiveLimits{MaxFile: 1 << 20}
	if _, err := inspectManifest(build("assets:\n  - path: a.png\n    contentType: image/png\n"), lim); err != nil {
		t.Fatalf("good archive refused: %v", err)
	}
	bad := []string{
		"assets:\n  - path: a.png\n    headers:\n      - key: Connection\n        value: close\n",
		"assets:\n  - path: missing.png\n",
		"assets: [unclosed\n",
	}
	for _, doc := range bad {
		if _, err := inspectManifest(build(doc), lim); err == nil {
			t.Errorf("archive with %q accepted", doc)
		}
	}
}

// TestPublishRefusesBadAssets runs the raw upload path end to end.
func TestPublishRefusesBadAssets(t *testing.T) {
	svc := newTestRegistry(t)
	files := map[string][]byte{
		"content/kit/data.yaml": []byte("assets:\n  - path: a.png\n    contentType: bad\n"),
		"assets/a.png":          []byte("png"),
	}
	// build the archive without the author checks, as an outside tool could.
	archive, _, err := buildArchiveUnchecked(PackageSpec{ID: "acme/kit", Type: manifest.TypeAsset, Version: "1.0.0"}, files)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Publish("acme", "kit", "1.0.0", "application/gzip", bytes.NewReader(archive))
	if err == nil || !IsValidation(err) || !strings.Contains(err.Error(), `asset "a.png"`) {
		t.Fatalf("publish of a bad assets block: %v", err)
	}
	// the author flow refuses it before building.
	_, _, err = svc.AuthorPackage(AuthoredPackage{Namespace: "acme", Name: "kit", Type: manifest.TypeAsset, Version: "1.0.0", Files: files})
	if err == nil || !IsValidation(err) {
		t.Fatalf("author of a bad assets block: %v", err)
	}
	// a good one publishes and its settings read back. Its list comes from an
	// allow deny package it depends on, and its pick variable is declared.
	authorList(t, svc, "acme", "scanners", "1.0.0", "Known scanners", false)
	files["content/kit/data.yaml"] = []byte(goodAssetDoc)
	files["assets/acme/login/logo.svg"] = []byte("<svg/>")
	files["assets/acme/login/app.js"] = []byte("1")
	v, _, err := svc.AuthorPackage(AuthoredPackage{
		Namespace: "acme", Name: "kit", Type: manifest.TypeAsset, Version: "1.0.0", Files: files,
		Dependencies: []manifest.Dependency{{ID: "acme/scanners", Range: "*"}},
		Variables:    []manifest.Variable{scannerPick},
	})
	if err != nil {
		t.Fatalf("author of a good assets block: %v", err)
	}
	_, _, got, err := svc.VersionContent("acme", "kit", v.Version)
	if err != nil {
		t.Fatal(err)
	}
	if as := PackageAssets(got); len(as) != 2 || as[0].ContentType != "image/svg+xml" {
		t.Fatalf("assets read back %+v", as)
	}
}

// buildArchiveUnchecked packs files into an archive with a valid manifest but
// none of the author checks, the way a tool outside Bait Box could.
func buildArchiveUnchecked(spec PackageSpec, files map[string][]byte) ([]byte, *manifest.Manifest, error) {
	es := make([]manifest.Entry, 0, len(files))
	for n, b := range files {
		es = append(es, manifest.Entry{Path: n, SHA256: shaHex(b)})
	}
	m := &manifest.Manifest{
		Format: manifest.Format, ID: spec.ID, Type: spec.Type, Version: spec.Version,
		Entries: es, ContentHash: manifest.ComputeContentHash(es),
	}
	mj, err := json.Marshal(m)
	if err != nil {
		return nil, nil, err
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	write := func(name string, b []byte) {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(b)
	}
	write(manifest.FileName, mj)
	for n, b := range files {
		write(n, b)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes(), m, nil
}

// TestValidateAssetBlocksPhishingClubParity checks values Phishing Club would
// refuse on install, so a package that publishes also installs.
func TestValidateAssetBlocksPhishingClubParity(t *testing.T) {
	entry := func(body string) string { return "assets:\n  - path: a.png\n" + body }
	var many strings.Builder
	many.WriteString("    headers:\n")
	for i := 0; i < maxAssetHeaders+1; i++ {
		many.WriteString("      - key: X-H" + strings.Repeat("a", i%3) + "\n        value: v\n")
	}
	lists := "    allowDeny:\n      - Office\n"
	bad := []struct {
		name, doc, want string
	}{
		{"name bytes", entry("    name: " + strings.Repeat("é", 64) + "\n"), "name is longer than 127 bytes"},
		{"description bytes", entry("    description: " + strings.Repeat("é", 128) + "\n"), "description is longer than 255 bytes"},
		{"blank header value", entry("    headers:\n      - key: X-A\n        value: \"   \"\n"), "needs a value"},
		{"list name bytes", entry("    allowDeny:\n      - " + strings.Repeat("a", 128) + "\n"), "longer than 127 bytes"},
		{"too many headers", entry(many.String()), "at most 50"},
		{"public cache", entry("    headers:\n      - key: Cache-Control\n        value: \"public, max-age=60\"\n" + lists), "Cache-Control"},
		{"cache no directive", entry("    headers:\n      - key: cache-control\n        value: max-age=60\n" + lists), "Cache-Control"},
		{"cache s-maxage", entry("    headers:\n      - key: Cache-Control\n        value: \"private, s-maxage=9\"\n" + lists), "Cache-Control"},
		{"allowed not a bool", "allowDenies:\n  - name: Office\n    allowed: maybe\n" + entry(""), "allowed must be true or false"},
		{"allowed quoted true", "allowDenies:\n  - name: Office\n    allowed: \"true\"\n" + entry(""), "allowed must be true or false"},
		{"allowed number", "allowDenies:\n  - name: Office\n    allowed: 1\n" + entry(""), "allowed must be true or false"},
	}
	for _, c := range bad {
		err := validateFileAssetBlocks(manifest.TypeAllowDeny, assetFilesFor(c.doc, "a.png"))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %v, want it to contain %q", c.name, err, c.want)
		}
	}
	good := []struct{ name, doc string }{
		{"name 127 bytes", entry("    name: " + strings.Repeat("a", 127) + "\n")},
		{"name trimmed", entry("    name: \"  " + strings.Repeat("a", 127) + "  \"\n")},
		{"private cache", entry("    headers:\n      - key: Cache-Control\n        value: \"private, max-age=60\"\n" + lists)},
		{"public cache without lists", entry("    headers:\n      - key: Cache-Control\n        value: public\n")},
		{"50 headers", entry(strings.Join(strings.Split(many.String(), "\n")[:1+2*maxAssetHeaders], "\n") + "\n")},
	}
	for _, c := range good {
		if err := validateFileAssetBlocks(manifest.TypeAsset, assetFilesFor(c.doc, "a.png")); err != nil {
			t.Errorf("%s: refused: %v", c.name, err)
		}
	}
}

// TestDeclaredListsAllowedSpellings checks that the kind of a list is read the
// way Phishing Club reads it, and that a list name is trimmed.
func TestDeclaredListsAllowedSpellings(t *testing.T) {
	for _, spelling := range []string{"True", "TRUE", "yes", "Yes", "on", "ON", "y", "\"yes\""} {
		doc := "allowDenies:\n  - name: \" Home \"\n    allowed: " + spelling + "\n"
		got, err := declaredLists(map[string][]byte{"content/l/data.yaml": []byte(doc)})
		if err != nil || !got["Home"] {
			t.Errorf("allowed %s: got %v, %v, want an allow list named Home", spelling, got, err)
		}
	}
	for _, spelling := range []string{"False", "no", "OFF", "n", ""} {
		doc := "allowDenies:\n  - name: Home\n    allowed: " + spelling + "\n"
		got, err := declaredLists(map[string][]byte{"content/l/data.yaml": []byte(doc)})
		if allowed, ok := got["Home"]; err != nil || !ok || allowed {
			t.Errorf("allowed %q: got %v, %v, want a deny list", spelling, got, err)
		}
	}
	if _, err := declaredLists(map[string][]byte{"content/l/data.yaml": []byte("allowDenies:\n  - name: A\n    allowed: maybe\n")}); err == nil {
		t.Errorf("allowed maybe accepted")
	}
}
