package controller

import (
	"bytes"
	"image"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/phishingclub/baitbox/manifest"
	"github.com/phishingclub/baitbox/middleware"
	"github.com/phishingclub/baitbox/service"
)

func tinyPNG(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, image.NewRGBA(image.Rect(0, 0, 2, 2))); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func serve(r *gin.Engine, path, auth string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	r.ServeHTTP(w, req)
	return w
}

// TestRegistryFilesAndCaching: package html is never served with an active type
// and every reply, preview images included, stays out of shared caches. The server tests check the admin listener has no file read.
func TestRegistryFilesAndCaching(t *testing.T) {
	reg, tokens := tagFixture(t)
	ctl := NewRegistry(reg, tokens)
	public := gin.New()
	public.Group("/api/v1", middleware.NoSharedCache).
		GET("/index", ctl.Index).
		GET("/packages/:ns/:name/:version/files/*path", ctl.Files).
		GET("/previews/:ns/:name/:sha", ctl.Preview)

	w := serve(public, "/api/v1/packages/open/lure/1.0.0/files/content/index.html", "")
	if w.Code != http.StatusOK {
		t.Fatalf("files: %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("html served as %q", ct)
	}
	if !strings.HasPrefix(w.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("html not an attachment: %q", w.Header().Get("Content-Disposition"))
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("nosniff missing")
	}
	w = serve(public, "/api/v1/index", "")
	if cc := w.Header().Get("Cache-Control"); cc != "private, no-store" || w.Header().Get("Vary") != "Authorization" {
		t.Fatalf("index cache headers %q vary %q", cc, w.Header().Get("Vary"))
	}

	pubSHA, err := reg.AddPreviewImage("open", "lure", tinyPNG(t))
	if err != nil {
		t.Fatal(err)
	}
	privSHA, err := reg.AddPreviewImage("hidden", "kit", tinyPNG(t))
	if err != nil {
		t.Fatal(err)
	}
	w = serve(public, "/api/v1/previews/open/lure/"+pubSHA, "")
	// a public preview stays out of shared caches too, so making the namespace
	// private takes effect at once.
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("public preview %d %q", w.Code, w.Header().Get("Cache-Control"))
	}
	clear, _, err := tokens.Create("reader", []string{"hidden"}, nil, nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	w = serve(public, "/api/v1/previews/hidden/kit/"+privSHA, "Bearer "+clear)
	if w.Code != http.StatusOK {
		t.Fatalf("private preview with token: %d", w.Code)
	}
	if cc := w.Header().Get("Cache-Control"); strings.Contains(cc, "public") || w.Header().Get("Vary") != "Authorization" {
		t.Fatalf("private preview cache headers %q vary %q", cc, w.Header().Get("Vary"))
	}
}

// TestRegistryFilesSniffsImages: an image extension is trusted only when the
// bytes sniff as that image, and a file over the serve cap is refused.
func TestRegistryFilesSniffsImages(t *testing.T) {
	reg, tokens := tagFixture(t)
	if _, _, err := reg.AuthorPackage(service.AuthoredPackage{
		Namespace: "open", Name: "pics", Type: manifest.TypePage, Version: "1.0.0", Title: "pics",
		Files: map[string][]byte{
			"content/index.html": []byte("<h1>x</h1>"),
			"assets/real.png":    tinyPNG(t),
			"assets/fake.png":    []byte("<html><script>alert(1)</script></html>"),
			"assets/big.png":     append(tinyPNG(t), make([]byte, maxServedFile)...),
		},
	}); err != nil {
		t.Fatal(err)
	}
	public := gin.New()
	public.GET("/api/v1/packages/:ns/:name/:version/files/*path", NewRegistry(reg, tokens).Files)
	base := "/api/v1/packages/open/pics/1.0.0/files/assets/"

	w := serve(public, base+"real.png", "")
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "image/png" ||
		w.Header().Get("Content-Disposition") != "" || !bytes.Equal(w.Body.Bytes(), tinyPNG(t)) {
		t.Fatalf("real png: %d %q %q", w.Code, w.Header().Get("Content-Type"), w.Header().Get("Content-Disposition"))
	}
	w = serve(public, base+"fake.png", "")
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/octet-stream" ||
		!strings.HasPrefix(w.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("html named png: %d %q %q", w.Code, w.Header().Get("Content-Type"), w.Header().Get("Content-Disposition"))
	}
	if w.Header().Get("Content-Security-Policy") != "sandbox" {
		t.Fatalf("csp %q", w.Header().Get("Content-Security-Policy"))
	}
	w = serve(public, base+"big.png", "")
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("file over the serve cap: %d", w.Code)
	}
}
