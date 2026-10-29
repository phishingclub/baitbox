// Package frontend embeds the built admin SPA so the Go binary serves it in
// production. In dev the SPA is served by vite. build/.gitkeep is tracked so a
// fresh clone compiles before `vite build` fills build/; the all: prefix makes
// the pattern match that dot file, and the server never serves dot files. The
// svelte sources alongside this file are not embedded.
package frontend

import (
	"embed"
	"html"
	"io/fs"
	"regexp"
	"strings"
)

//go:embed all:build
var buildFS embed.FS

// FS returns the embedded built SPA rooted at the build directory.
func FS() fs.FS {
	sub, err := fs.Sub(buildFS, "build")
	if err != nil {
		panic(err)
	}
	return sub
}

// cspMetaRe matches the content security policy meta tag SvelteKit bakes into
// index.html in hash mode.
var cspMetaRe = regexp.MustCompile(`(?is)<meta[^>]+http-equiv=["']content-security-policy["'][^>]*>`)

// cspContentRe pulls the policy out of the meta tag's content attribute. A csp
// policy contains single quotes but never double quotes, so the content
// attribute is double quoted and its value runs to the next double quote.
var cspContentRe = regexp.MustCompile(`(?is)content="([^"]*)"`)

// ExtractCSPFromIndex reads build/index.html, pulls the policy out of the
// SvelteKit content security policy meta tag, and returns that policy, the html
// with the meta tag removed, and whether a tag was found. With only the
// placeholder embedded there is no index.html, so indexHTML is nil and ok is
// false. A document without the meta is returned unchanged with ok false.
func ExtractCSPFromIndex() (policy string, indexHTML []byte, ok bool) {
	data, err := buildFS.ReadFile("build/index.html")
	if err != nil {
		return "", nil, false
	}
	tag := cspMetaRe.Find(data)
	if tag == nil {
		return "", data, false
	}
	m := cspContentRe.FindSubmatch(tag)
	if m == nil {
		return "", data, false
	}
	policy = strings.TrimSpace(html.UnescapeString(string(m[1])))
	if policy == "" {
		return "", data, false
	}
	return policy, cspMetaRe.ReplaceAll(data, nil), true
}
