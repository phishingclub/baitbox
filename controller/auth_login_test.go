package controller

import (
	"net/http"
	"testing"

	"github.com/phishingclub/baitbox/middleware"
)

// A login that still sends an old session cookie ends that session.
func TestLoginEndsPresentedSession(t *testing.T) {
	h := newStepUpHarness(t)
	if _, err := h.sessions.Validate(h.cookie, "192.0.2.1"); err != nil {
		t.Fatalf("old session not valid before the login: %v", err)
	}
	old := &http.Cookie{Name: middleware.SessionCookieName, Value: h.cookie}
	body := map[string]string{"username": "xena", "password": testPassword}
	if code := h.post("/api/v1/login", body, old); code != http.StatusOK {
		t.Fatalf("login: want 200, got %d", code)
	}
	if _, err := h.sessions.Validate(h.cookie, "192.0.2.1"); err == nil {
		t.Fatal("the old session still works after a new login")
	}
}
