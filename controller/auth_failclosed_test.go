package controller

import (
	"net/http"
	"strings"
	"testing"

	"github.com/phishingclub/baitbox/database"
)

// TestLoginFailsClosedWhenPasskeysUnknown: when the passkey count cannot be
// read, a correct password does not start a session as if no passkey existed.
func TestLoginFailsClosedWhenPasskeysUnknown(t *testing.T) {
	h := newStepUpHarness(t)
	if err := h.db.Migrator().DropTable(&database.OperatorCredential{}); err != nil {
		t.Fatal(err)
	}
	before := h.count(h.db.Model(&database.Session{}))
	code, _, out := h.loginReply("xena", testPassword, "192.0.2.50")
	if code != http.StatusInternalServerError {
		t.Fatalf("login with an unreadable passkey table: %d %v", code, out)
	}
	if h.count(h.db.Model(&database.Session{})) != before {
		t.Fatal("a session was started")
	}
}

// TestTokenCreateRefusesUnknownNamespace: a token scope naming a namespace that
// does not exist is a 400 that names it, and no grant is spent on it.
func TestTokenCreateRefusesUnknownNamespace(t *testing.T) {
	h := newStepUpHarness(t)
	code, out := h.do(http.MethodPost, "/tokens", map[string]any{"name": "ci", "namespaces": []string{"ghost"}})
	if code != http.StatusBadRequest {
		t.Fatalf("token for a missing namespace: %d %v", code, out)
	}
	if msg, _ := out["error"].(string); !strings.Contains(msg, "ghost") {
		t.Fatalf("refusal does not name the namespace: %v", out)
	}
	if h.count(h.db.Model(&database.Token{})) != 0 {
		t.Fatal("token created")
	}
}
