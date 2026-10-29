package controller

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// slowPost sends parts as the request body, pausing between them, and returns
// the status and body of the reply.
func slowPost(url string, parts []string) (int, []byte, error) {
	pr, pw := io.Pipe()
	go func() {
		for _, p := range parts {
			_, _ = pw.Write([]byte(p))
			time.Sleep(200 * time.Millisecond)
		}
		pw.Close()
	}()
	resp, err := http.Post(url, "application/json", pr)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, body, nil
}

// TestImportExtendsReadDeadline: under a short listener read timeout a slow body
// is cut off, unless the handler extends its own deadline as the imports do.
func TestImportExtendsReadDeadline(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	read := func(c *gin.Context) {
		n, err := io.Copy(io.Discard, c.Request.Body)
		if err != nil {
			c.String(http.StatusBadRequest, "short read after %d bytes", n)
			return
		}
		c.String(http.StatusOK, "%d", n)
	}
	r.POST("/plain", read)
	r.POST("/import", func(c *gin.Context) { extendRead(c, importReadTimeout); read(c) })
	srv := httptest.NewUnstartedServer(r)
	srv.Config.ReadTimeout = 300 * time.Millisecond
	srv.Start()
	defer srv.Close()

	parts := []string{"chunk", "chunk", "chunk", "chunk"}
	if code, _, err := slowPost(srv.URL+"/plain", parts); err == nil && code == http.StatusOK {
		t.Fatal("slow body read in full under the short timeout")
	}
	code, _, err := slowPost(srv.URL+"/import", parts)
	if err != nil || code != http.StatusOK {
		t.Fatalf("import with extended deadline: %d %v", code, err)
	}
}

// TestDraftSaveExtendsReadDeadline: a draft body sent slowly is read in full
// under a short listener read timeout. A full read reaches the name check; a
// cut body fails earlier as an invalid request.
func TestDraftSaveExtendsReadDeadline(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/drafts", (&AdminAPI{}).DraftSave)
	srv := httptest.NewUnstartedServer(r)
	srv.Config.ReadTimeout = 300 * time.Millisecond
	srv.Start()
	defer srv.Close()

	code, body, err := slowPost(srv.URL+"/drafts", []string{`{"pad":"`, "chunk", "chunk", "chunk", `"}`})
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	var out map[string]any
	_ = json.Unmarshal(body, &out)
	if code != http.StatusBadRequest || out["error"] != "namespace and name are required" {
		t.Fatalf("slow draft body was not read in full: %d %s", code, body)
	}
}
