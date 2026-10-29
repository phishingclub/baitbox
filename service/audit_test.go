package service

import (
	"bufio"
	"bytes"
	"encoding/json"
	"testing"
)

// auditLines decodes every JSON line written to buf.
func auditLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	sc := bufio.NewScanner(bytes.NewReader(buf.Bytes()))
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("audit line %q: %v", sc.Text(), err)
		}
		out = append(out, m)
	}
	return out
}

// TestAuditLineShape: one JSON line with the Phishing Club audit fields, the
// username, success and the details.
func TestAuditLineShape(t *testing.T) {
	var buf bytes.Buffer
	a := NewAuditServiceTo(&buf)
	a.Record("Operator.Login", "op1", "alice", "10.0.0.1", true, map[string]any{"method": "passkey"})
	a.Record("Operator.LoginFailed", "", "bob", "10.0.0.2", false, nil)
	lines := auditLines(t, &buf)
	if len(lines) != 2 {
		t.Fatalf("lines = %v", lines)
	}
	l := lines[0]
	if l["level"] != "info" || l["msg"] != "audit" || l["name"] != "Operator.Login" || l["ip"] != "10.0.0.1" ||
		l["userId"] != "op1" || l["username"] != "alice" || l["success"] != true {
		t.Fatalf("line = %v", l)
	}
	if ts, ok := l["ts"].(float64); !ok || ts < 1e9 {
		t.Fatalf("ts = %v", l["ts"])
	}
	if _, ok := l["time"]; ok {
		t.Fatal("time key left in the line")
	}
	if d, _ := l["details"].(map[string]any); d["method"] != "passkey" {
		t.Fatalf("details = %v", l["details"])
	}
	if _, ok := l["authorized"]; ok {
		t.Fatal("authorized key in the line")
	}
	if lines[1]["success"] != false || lines[1]["details"] != nil || lines[1]["userId"] != "" {
		t.Fatalf("failed line = %v", lines[1])
	}
}
