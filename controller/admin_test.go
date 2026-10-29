package controller

import (
	"strings"
	"testing"
)

func TestAttachmentDisposition(t *testing.T) {
	cases := map[string]string{
		"pkg-1.2.3.tar.gz":         `attachment; filename="pkg-1.2.3.tar.gz"`,
		"a\"b\r\nX-Evil: 1.tar.gz": `attachment; filename="a_b__X-Evil__1.tar.gz"`,
		"../../etc/passwd":         `attachment; filename=".._.._etc_passwd"`,
		"":                         `attachment; filename="download"`,
		"café.tar.gz":              `attachment; filename="caf__.tar.gz"`,
	}
	for in, want := range cases {
		if got := attachmentDisposition(in); got != want {
			t.Errorf("attachmentDisposition(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRawImageType(t *testing.T) {
	png := []byte("\x89PNG\r\n\x1a\n0000000000000000")
	gif := []byte("GIF89a000000000000")
	svg := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"assets/a.png", png, "image/png"},
		{"assets/a.PNG", png, "image/png"},
		{"assets/a.gif", gif, "image/gif"},
		{"assets/a.png", gif, ""},
		{"assets/a.png", svg, ""},
		{"assets/a.svg", svg, ""},
		{"content/index.html", []byte("<html><script>x</script>"), ""},
		{"assets/a.jpg", png, ""},
	}
	for _, tc := range cases {
		if got := rawImageType(tc.name, tc.data); got != tc.want {
			t.Errorf("rawImageType(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestPreviewCSPAllowsRemoteLooksBlocksScriptsAndExfil(t *testing.T) {
	dirs := map[string]string{}
	for _, d := range strings.Split(previewCSP, ";") {
		d = strings.TrimSpace(d)
		if i := strings.IndexByte(d, ' '); i > 0 {
			dirs[d[:i]] = d[i+1:]
		}
	}
	for _, k := range []string{"img-src", "font-src", "style-src", "media-src"} {
		if !strings.Contains(dirs[k], "https:") {
			t.Errorf("%s lacks https: (%q)", k, dirs[k])
		}
	}
	if strings.Contains(dirs["script-src"], "https:") || strings.Contains(dirs["script-src"], "*") || strings.Contains(dirs["default-src"], "https:") {
		t.Errorf("remote scripts allowed: script-src %q default-src %q", dirs["script-src"], dirs["default-src"])
	}
	for k, want := range map[string]string{
		"connect-src": "'none'", "form-action": "'none'", "object-src": "'none'", "base-uri": "'none'",
		"frame-ancestors": "'self'",
	} {
		if dirs[k] != want {
			t.Errorf("%s = %q, want %q", k, dirs[k], want)
		}
	}
	if dirs["sandbox"] != "allow-scripts allow-forms allow-popups" {
		t.Errorf("sandbox = %q", dirs["sandbox"])
	}
	// package dialogs must not pop over the admin tab, and the document must keep
	// its opaque origin.
	for _, flag := range []string{"allow-modals", "allow-same-origin", "allow-top-navigation"} {
		if strings.Contains(previewCSP, flag) {
			t.Errorf("previewCSP grants %s", flag)
		}
	}
	if strings.Contains(rawFileCSP, "allow-same-origin") || strings.Contains(rawFileCSP, "allow-scripts") {
		t.Errorf("rawFileCSP = %q", rawFileCSP)
	}
}
