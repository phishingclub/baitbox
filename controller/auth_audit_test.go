package controller

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/phishingclub/baitbox/middleware"
	"github.com/phishingclub/baitbox/service"
)

// auditLines decodes every audit line written so far.
func (h *stepUpHarness) auditLines() []map[string]any {
	h.t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(h.auditLog.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			h.t.Fatalf("audit line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

// auditCount counts the audit lines for action that also match every check.
func (h *stepUpHarness) auditCount(action string, checks ...func(map[string]any) bool) int {
	h.t.Helper()
	n := 0
next:
	for _, l := range h.auditLines() {
		if l["name"] != action {
			continue
		}
		for _, ok := range checks {
			if !ok(l) {
				continue next
			}
		}
		n++
	}
	return n
}

// post sends a JSON body to an unguarded auth route with the given cookies.
func (h *stepUpHarness) post(path string, body any, cookies ...*http.Cookie) int {
	h.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(http.MethodPost, path, &buf)
	req.RemoteAddr = "192.0.2.1:4000"
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.engine.ServeHTTP(w, req)
	return w.Code
}

// A passkey finish with no live challenge checked nothing, so it writes no audit
// line. A logout is audited only for a valid session.
func TestAuthRoutesAuditOnlyRealEvents(t *testing.T) {
	h := newStepUpHarness(t)

	if code := h.post("/api/v1/login/passkey/finish", map[string]string{}); code != http.StatusUnauthorized {
		t.Fatalf("finish without a challenge: want 401, got %d", code)
	}
	unknown := &http.Cookie{Name: passkeyChallengeCookie, Value: "no-such-challenge"}
	if code := h.post("/api/v1/login/passkey/finish", map[string]string{}, unknown); code != http.StatusUnauthorized {
		t.Fatalf("finish with an unknown challenge: want 401, got %d", code)
	}
	if n := h.auditCount("Operator.LoginPasskeyFailed"); n != 0 {
		t.Fatalf("finish without a challenge wrote %d audit lines", n)
	}

	junk := &http.Cookie{Name: middleware.SessionCookieName, Value: "junk"}
	if code := h.post("/api/v1/logout", nil, junk); code != http.StatusOK {
		t.Fatalf("logout with a junk cookie: want 200, got %d", code)
	}
	if code := h.post("/api/v1/logout", nil); code != http.StatusOK {
		t.Fatalf("logout without a cookie: want 200, got %d", code)
	}
	if n := h.auditCount("Operator.Logout"); n != 0 {
		t.Fatalf("logout without a valid session wrote %d audit lines", n)
	}
	valid := &http.Cookie{Name: middleware.SessionCookieName, Value: h.cookie}
	if code := h.post("/api/v1/logout", nil, valid); code != http.StatusOK {
		t.Fatalf("logout: want 200, got %d", code)
	}
	if n := h.auditCount("Operator.Logout"); n != 1 {
		t.Fatalf("logout of a valid session: want 1 audit line, got %d", n)
	}
}

// An oversized login username gets the usual failed login reply and is never
// written to the audit log.
func TestLongLoginUsernameNotLogged(t *testing.T) {
	h := newStepUpHarness(t)
	long := strings.Repeat("a", service.MaxUsernameBytes+1)

	code, _, out := h.loginReply(long, "whatever", "192.0.2.9")
	if code != http.StatusUnauthorized || out["error"] != "invalid username or password" {
		t.Fatalf("long username on login: %d %v", code, out)
	}
	if code := h.post("/api/v1/login/passkey/begin", map[string]string{"username": long, "password": "whatever"}); code != http.StatusUnauthorized {
		t.Fatalf("long username on passkey begin: want 401, got %d", code)
	}
	if strings.Contains(h.auditLog.String(), long) {
		t.Fatal("long username written to the audit log")
	}

	// a wrong password with a normal username is still audited.
	if code, _, _ := h.loginReply("nobody", "whatever", "192.0.2.9"); code != http.StatusUnauthorized {
		t.Fatalf("wrong login: want 401, got %d", code)
	}
	if n := h.auditCount("Operator.LoginFailed"); n != 1 {
		t.Fatalf("wrong login: want 1 audit line, got %d", n)
	}
}
