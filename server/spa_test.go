package server

import (
	"testing"
	"testing/fstest"
)

// Only regular files that are not dot named are handed to the file server, so a
// directory is never listed and the build placeholder is never served.
func TestIsServableFile(t *testing.T) {
	fsys := fstest.MapFS{
		".gitkeep":                 {},
		"index.html":               {Data: []byte("<html></html>")},
		"favicon.svg":              {Data: []byte("<svg/>")},
		"_app/immutable/app.js":    {Data: []byte("x")},
		"_app/.hidden/secret.js":   {Data: []byte("x")},
		"_app/immutable/.map.json": {Data: []byte("x")},
	}
	cases := map[string]bool{
		"favicon.svg":              true,
		"_app/immutable/app.js":    true,
		"_app":                     false,
		"_app/immutable":           false,
		".gitkeep":                 false,
		"_app/.hidden/secret.js":   false,
		"_app/immutable/.map.json": false,
		"missing.js":               false,
	}
	for rel, want := range cases {
		if got := isServableFile(fsys, rel); got != want {
			t.Errorf("%s: got %v, want %v", rel, got, want)
		}
	}
}
