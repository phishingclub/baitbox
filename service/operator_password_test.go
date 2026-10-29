package service

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/repository"
)

// A login username over the column size is refused like a wrong password and
// never becomes a throttle key.
func TestLongLoginUsernameRefused(t *testing.T) {
	db := newTestDB(t)
	svc := NewOperatorService(repository.NewOperatorRepository(db))
	long := strings.Repeat("u", MaxUsernameBytes+1)
	if _, err := svc.AuthenticatePassword(long, "whatever", testIP); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("long username: got %v", err)
	}
	if _, err := svc.Authenticate(long, "whatever", "", testIP); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("long username with code path: got %v", err)
	}
	svc.passwords.mu.Lock()
	n := len(svc.passwords.subjects)
	svc.passwords.mu.Unlock()
	if n != 0 {
		t.Fatalf("long username was kept as a throttle key (%d subjects)", n)
	}
	// a name at the limit is still checked and counted.
	atLimit := strings.Repeat("u", MaxUsernameBytes)
	if _, err := svc.AuthenticatePassword(atLimit, "whatever", testIP); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("username at the limit: got %v", err)
	}
	svc.passwords.mu.Lock()
	n = len(svc.passwords.subjects)
	svc.passwords.mu.Unlock()
	if n != 1 {
		t.Fatalf("username at the limit: want 1 throttle subject, got %d", n)
	}
}

func TestIssuedPasswordsMustBeChanged(t *testing.T) {
	db := newTestDB(t)
	svc := NewOperatorService(repository.NewOperatorRepository(db))

	_, pw, created, err := svc.EnsureOperator()
	if err != nil || !created {
		t.Fatalf("seed: created=%v err=%v", created, err)
	}
	op, err := svc.AuthenticatePassword(defaultOperatorUsername, pw, testIP)
	if err != nil {
		t.Fatalf("login with seeded password: %v", err)
	}
	if !op.MustChangePassword {
		t.Fatal("seeded operator is not flagged to change the password")
	}

	if _, err := svc.ChangePassword(op.ID, pw, pw, ""); !errors.Is(err, ErrPasswordUnchanged) {
		t.Fatalf("reusing the current password: got %v", err)
	}
	if _, err := svc.ChangePassword(op.ID, "wrong", "a new password 123", ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong current password: got %v", err)
	}
	for _, bad := range []string{"Admin", "ab", strings.Repeat("x", 65)} {
		if _, err := svc.ChangePassword(op.ID, pw, "a new password 123", bad); !errors.Is(err, ErrInvalidUsername) {
			t.Fatalf("rename to %q: got %v", bad, err)
		}
	}
	if _, err := svc.CreateOperator("taken", "another password 1"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := svc.ChangePassword(op.ID, pw, "a new password 123", "taken"); !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("rename to a taken name: got %v", err)
	}
	if _, err := svc.ChangePassword(op.ID, pw, "a new password 123", "owner"); err != nil {
		t.Fatalf("change: %v", err)
	}
	op, _ = svc.GetOperator(op.ID)
	if op.MustChangePassword {
		t.Fatal("flag still set after changing the password")
	}
	if op.Username != "owner" || HasDefaultUsername(op) {
		t.Fatalf("rename not applied: %q", op.Username)
	}

	// with no username, reset finds the seeded operator even after the rename
	name, reset, err := svc.resetOperatorName("")
	if err != nil || name != "owner" {
		t.Fatalf("reset: name=%q err=%v", name, err)
	}
	op, err = svc.AuthenticatePassword("owner", reset, testIP)
	if err != nil || !op.MustChangePassword {
		t.Fatalf("reset operator not flagged: err=%v", err)
	}
	if _, _, err := svc.resetOperatorName("nobody"); err == nil {
		t.Fatal("reset of an unknown username succeeded")
	}
	if _, err := svc.CreateOperator("ADMIN", "another password 1"); err == nil {
		t.Fatal("created an operator with the reserved name")
	}

	created2, err := svc.CreateOperator("second", "set by another operator")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !created2.MustChangePassword {
		t.Fatal("operator created by another operator is not flagged")
	}
}

func TestUsernamesIgnoreCase(t *testing.T) {
	db := newTestDB(t)
	svc := NewOperatorService(repository.NewOperatorRepository(db))

	alice, err := svc.CreateOperator("Alice", "alice password 1")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := svc.CreateOperator("alice", "alice password 2"); err == nil {
		t.Fatal("created a second operator differing only in case")
	}
	op, err := svc.AuthenticatePassword("ALICE", "alice password 1", testIP)
	if err != nil || op.ID != alice.ID {
		t.Fatalf("login with other case: err=%v", err)
	}
	if op.Username != "Alice" {
		t.Fatalf("stored case changed: %q", op.Username)
	}

	// a case only rename of yourself is allowed, a clash with someone else is not
	if _, err := svc.ChangePassword(alice.ID, "alice password 1", "alice password 3", "aLiCe"); err != nil {
		t.Fatalf("case only rename: %v", err)
	}
	if _, err := svc.CreateOperator("Bobby", "bobby password 1"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := svc.ChangePassword(alice.ID, "alice password 3", "alice password 4", "BOBBY"); !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("rename onto another operator in other case: got %v", err)
	}

	// failures in any case count toward the same throttle
	for i := 0; i < passwordThrottle.free+1; i++ {
		name := "bobby"
		if i%2 == 0 {
			name = "BOBBY"
		}
		_, _ = svc.AuthenticatePassword(name, "wrong", testIP)
	}
	if _, err := svc.AuthenticatePassword("Bobby", "bobby password 1", testIP); !errors.Is(err, ErrThrottled) {
		t.Fatalf("throttle bypassed by changing case: got %v", err)
	}
}

func TestCaseVariantIndexEnforced(t *testing.T) {
	db := newTestDB(t)
	repo := repository.NewOperatorRepository(db)
	if err := repo.Create(&database.Operator{Username: "Carol", PasswordHash: "x"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := repo.Create(&database.Operator{Username: "carol", PasswordHash: "x"}); err == nil {
		t.Fatal("database accepted a username differing only in case")
	}
}

func TestResetOperatorAuditedRecords(t *testing.T) {
	db := newTestDB(t)
	svc := NewOperatorService(repository.NewOperatorRepository(db))
	var buf bytes.Buffer
	audit := NewAuditServiceTo(&buf)
	// no operator yet: the reset seeds one and says so.
	name, pw, err := svc.ResetOperatorAudited(audit, "")
	if err != nil || name == "" || pw == "" {
		t.Fatalf("reseed: %q %v", name, err)
	}
	if _, _, err := svc.ResetOperatorAudited(audit, name); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if _, _, err := svc.ResetOperatorAudited(audit, "nobody"); err == nil {
		t.Fatal("reset of an unknown operator succeeded")
	}
	if strings.Contains(buf.String(), pw) {
		t.Fatal("the password is in the audit log")
	}
	lines := auditLines(t, &buf)
	if len(lines) != 3 {
		t.Fatalf("audit lines = %v", lines)
	}
	for i, want := range []bool{true, true, false} {
		l := lines[i]
		d, _ := l["details"].(map[string]any)
		if l["name"] != "Operator.ResetPassword" || l["success"] != want || d["source"] != "cli" {
			t.Fatalf("audit line %d = %v", i, l)
		}
	}
	d0, _ := lines[0]["details"].(map[string]any)
	d2, _ := lines[2]["details"].(map[string]any)
	if lines[0]["userId"] == "" || d0["reseeded"] != true || d2["reason"] != "operator not found" {
		t.Fatalf("audit lines = %v", lines)
	}
}
