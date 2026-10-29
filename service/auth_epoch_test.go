package service

import (
	"bytes"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/phishingclub/baitbox/crypto"
	"github.com/phishingclub/baitbox/repository"
)

// A login checks the credentials, then creates its session. These tests put a
// credential change between the two and check the session is refused.

func TestSessionFromLoginBeforePasswordChangeIsRefused(t *testing.T) {
	db := newTestDB(t)
	const pw = "password-12345"
	opID := seedOperatorWithPassword(t, db, "mia", pw)
	ops := NewOperatorService(repository.NewOperatorRepository(db))
	sessions := NewSessionService(repository.NewSessionRepository(db))

	// the login checks the old password.
	op, err := ops.Authenticate("mia", pw, "", testIP)
	if err != nil {
		t.Fatal(err)
	}
	// the password changes before the login stores its session.
	epoch, err := ops.ChangePassword(opID, pw, "another password 1", "")
	if err != nil {
		t.Fatal(err)
	}
	if epoch == op.AuthEpoch {
		t.Fatal("the password change did not raise the auth epoch")
	}
	raw, err := sessions.Create(op.ID, op.AuthEpoch, testIP)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sessions.Validate(raw, testIP); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("a session from the old password was accepted: %v", err)
	}
	if got := sessionsOf(t, db, opID); got[crypto.HashToken(raw)] {
		t.Fatal("the refused session was not deleted")
	}

	// the session the change hands out, and a login with the new password, work.
	reissued, err := sessions.Create(opID, epoch, testIP)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sessions.Validate(reissued, testIP); err != nil {
		t.Fatalf("the reissued session was refused: %v", err)
	}
	op, err = ops.Authenticate("mia", "another password 1", "", testIP)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := sessions.Create(op.ID, op.AuthEpoch, testIP)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sessions.Validate(fresh, testIP); err != nil {
		t.Fatalf("a login with the new password was refused: %v", err)
	}
}

func TestSessionFromLoginBeforePasskeyRemovalIsRefused(t *testing.T) {
	db := newTestDB(t)
	const pw = "password-12345"
	opID := seedOperatorWithPassword(t, db, "mia", pw)
	seedPasskey(t, db, opID, "cred-1")
	ops := NewOperatorService(repository.NewOperatorRepository(db))
	sessions := NewSessionService(repository.NewSessionRepository(db))
	wa := &WebAuthnService{repo: repository.NewWebAuthnRepository(db), store: newChallengeStore()}

	// a signed in session that removes the passkey and stays.
	current, err := sessions.Create(opID, 0, testIP)
	if err != nil {
		t.Fatal(err)
	}
	op, err := ops.Authenticate("mia", pw, "", testIP)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := wa.List(opID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("list: %v %d", err, len(rows))
	}
	if err := wa.Delete(opID, rows[0].ID, current); err != nil {
		t.Fatal(err)
	}
	raw, err := sessions.Create(op.ID, op.AuthEpoch, testIP)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sessions.Validate(raw, testIP); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("a session from before the passkey removal was accepted: %v", err)
	}
	// the session that made the change moved to the new epoch.
	if _, err := sessions.Validate(current, testIP); err != nil {
		t.Fatalf("the kept session was refused: %v", err)
	}
}

func TestPasskeyLoginRefusedAfterCredentialChange(t *testing.T) {
	f := newPasskeyFixture(t, false)
	opts, token, err := f.svc.BeginLogin(f.op, testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	// a second passkey is added and removed between the begin and the finish.
	other := newSoftKey(t)
	seedPasskey(t, f.gdb, f.op.ID, string(other.id))
	rows, err := f.db.ListByOperator(f.op.ID)
	if err != nil || len(rows) != 2 {
		t.Fatalf("list: %v %d", err, len(rows))
	}
	if err := f.svc.Delete(f.op.ID, rows[1].ID, ""); err != nil {
		t.Fatal(err)
	}
	body := f.key.assert(t, opts.Response.Challenge.String(), f.op.ID, false, false)
	req := httptest.NewRequest("POST", "/login/passkey/finish", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if _, _, err := f.svc.FinishLogin(testOrigin, token, req, nil); !errors.Is(err, ErrNoChallenge) {
		t.Fatalf("a passkey login begun before the change finished: %v", err)
	}
}
