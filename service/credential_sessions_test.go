package service

import (
	"bytes"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/phishingclub/baitbox/crypto"
	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/repository"
	"gorm.io/gorm"
)

// sessionsOf returns the stored ids of an operator's sessions.
func sessionsOf(t *testing.T, db *gorm.DB, opID string) map[string]bool {
	t.Helper()
	var ids []string
	if err := db.Model(&database.Session{}).Where("operator_id = ?", opID).Pluck("id", &ids).Error; err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, id := range ids {
		out[id] = true
	}
	return out
}

// twoSessions starts two sessions for the operator and returns their raw ids.
func twoSessions(t *testing.T, db *gorm.DB, opID string) (string, string) {
	t.Helper()
	sessions := NewSessionService(repository.NewSessionRepository(db))
	current, err := sessions.Create(opID, 0, testIP)
	if err != nil {
		t.Fatal(err)
	}
	other, err := sessions.Create(opID, 0, "198.51.100.9")
	if err != nil {
		t.Fatal(err)
	}
	return current, other
}

// wantOnlySession checks the operator has exactly the session raw left.
func wantOnlySession(t *testing.T, db *gorm.DB, opID, raw string) {
	t.Helper()
	got := sessionsOf(t, db, opID)
	if len(got) != 1 || !got[crypto.HashToken(raw)] {
		t.Fatalf("sessions left %v, want only the current one", got)
	}
}

// failSessionDeletes makes every session delete fail, so the tests can check a
// credential change rolls back with it.
func failSessionDeletes(t *testing.T, db *gorm.DB) {
	t.Helper()
	err := db.Exec(`CREATE TRIGGER fail_session_delete BEFORE DELETE ON sessions
		BEGIN SELECT RAISE(ABORT, 'session delete refused'); END`).Error
	if err != nil {
		t.Fatal(err)
	}
}

func TestDisableMFADropsOtherSessions(t *testing.T) {
	db := newTestDB(t)
	opID := seedOperatorWithPassword(t, db, "mia", "password-12345")
	repo := repository.NewOperatorRepository(db)
	svc := NewOperatorService(repo)
	secret := enableTOTP(t, db, opID)
	current, _ := twoSessions(t, db, opID)
	code, _ := totpCodeForNow(t, secret)
	if err := svc.DisableMFA(opID, code, current); err != nil {
		t.Fatal(err)
	}
	wantOnlySession(t, db, opID, current)
}

func TestDisableMFARollsBackWhenSessionsStay(t *testing.T) {
	db := newTestDB(t)
	opID := seedOperatorWithPassword(t, db, "mia", "password-12345")
	repo := repository.NewOperatorRepository(db)
	svc := NewOperatorService(repo)
	secret := enableTOTP(t, db, opID)
	current, _ := twoSessions(t, db, opID)
	failSessionDeletes(t, db)
	code, _ := totpCodeForNow(t, secret)
	if err := svc.DisableMFA(opID, code, current); err == nil {
		t.Fatal("disable succeeded although the sessions could not be dropped")
	}
	op, err := svc.GetOperator(opID)
	if err != nil {
		t.Fatal(err)
	}
	if !op.MFAEnabled || op.MFASecret != secret {
		t.Fatal("two factor was turned off although the sessions stayed")
	}
}

func TestChangePasswordRollsBackWhenSessionsStay(t *testing.T) {
	db := newTestDB(t)
	const pw = "password-12345"
	opID := seedOperatorWithPassword(t, db, "mia", pw)
	svc := NewOperatorService(repository.NewOperatorRepository(db))
	twoSessions(t, db, opID)
	failSessionDeletes(t, db)
	if _, err := svc.ChangePassword(opID, pw, "another password 1", ""); err == nil {
		t.Fatal("password change succeeded although the sessions could not be dropped")
	}
	if err := svc.VerifyPassword(opID, pw); err != nil {
		t.Fatalf("old password no longer works: %v", err)
	}
	if len(sessionsOf(t, db, opID)) != 2 {
		t.Fatal("sessions changed")
	}
}

func TestConfirmMFARollsBackWhenSessionsStay(t *testing.T) {
	db := newTestDB(t)
	opID := seedOperatorWithPassword(t, db, "mia", "password-12345")
	svc := NewOperatorService(repository.NewOperatorRepository(db))
	twoSessions(t, db, opID)
	secret, _, err := svc.BeginMFAEnroll(opID)
	if err != nil {
		t.Fatal(err)
	}
	failSessionDeletes(t, db)
	code, _ := totpCodeForNow(t, secret)
	if _, err := svc.ConfirmMFAEnroll(opID, code); err == nil {
		t.Fatal("enable succeeded although the sessions could not be dropped")
	}
	op, err := svc.GetOperator(opID)
	if err != nil {
		t.Fatal(err)
	}
	if op.MFAEnabled {
		t.Fatal("two factor was turned on although the sessions stayed")
	}
}

func TestPasskeyDeleteDropsOtherSessions(t *testing.T) {
	db := newTestDB(t)
	opID := seedOperatorWithPassword(t, db, "mia", "password-12345")
	seedPasskey(t, db, opID, "cred-1")
	wa := &WebAuthnService{repo: repository.NewWebAuthnRepository(db), store: newChallengeStore()}
	current, _ := twoSessions(t, db, opID)
	// an unknown passkey changes nothing.
	if err := wa.Delete(opID, "missing", current); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete of an unknown passkey: %v", err)
	}
	if len(sessionsOf(t, db, opID)) != 2 {
		t.Fatal("a refused delete dropped sessions")
	}
	rows, err := wa.List(opID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("list: %v %d", err, len(rows))
	}
	if err := wa.Delete(opID, rows[0].ID, current); err != nil {
		t.Fatal(err)
	}
	wantOnlySession(t, db, opID, current)
}

func TestPasskeyAddDropsOtherSessions(t *testing.T) {
	db := newTestDB(t)
	opID := seedOperatorWithPassword(t, db, "mia", "password-12345")
	current, _ := twoSessions(t, db, opID)
	repo := repository.NewWebAuthnRepository(db)
	row := &database.OperatorCredential{OperatorID: opID, Name: "key", CredentialID: []byte("cred-2")}
	if err := repo.CreateDropSessions(row, crypto.HashToken(current)); err != nil {
		t.Fatal(err)
	}
	wantOnlySession(t, db, opID, current)

	// a failed session drop leaves no passkey behind.
	failSessionDeletes(t, db)
	if _, err := twoSessionsOne(t, db, opID); err != nil {
		t.Fatal(err)
	}
	row = &database.OperatorCredential{OperatorID: opID, Name: "key", CredentialID: []byte("cred-3")}
	if err := repo.CreateDropSessions(row, crypto.HashToken(current)); err == nil {
		t.Fatal("passkey stored although the sessions could not be dropped")
	}
	if n := countRows(t, db.Model(&database.OperatorCredential{}).Where("operator_id = ?", opID)); n != 1 {
		t.Fatalf("passkeys %d, want 1", n)
	}
}

// twoSessionsOne adds one more session for the operator.
func twoSessionsOne(t *testing.T, db *gorm.DB, opID string) (string, error) {
	t.Helper()
	return NewSessionService(repository.NewSessionRepository(db)).Create(opID, 0, "203.0.113.4")
}

// TestPasskeyLoginsDoNotAddUpToAWait: every good passkey login is recorded as a
// passed second factor, so many of them never hold the operator, while the same
// logins without that record would.
func TestPasskeyLoginsDoNotAddUpToAWait(t *testing.T) {
	run := func(record bool) error {
		f := newPasskeyFixture(t, false)
		ops := NewOperatorService(repository.NewOperatorRepository(f.gdb))
		for i := 0; i < 2*secondFactorThrottle.globalFree; i++ {
			opts, token, err := f.svc.BeginLogin(f.op, testOrigin)
			if err != nil {
				t.Fatal(err)
			}
			body := f.key.assert(t, opts.Response.Challenge.String(), f.op.ID, false, false)
			req := httptest.NewRequest("POST", "/login/passkey/finish", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			gate := func(id string) error { return ops.BeginSecondFactor(id, testIP) }
			op, _, err := f.svc.FinishLogin(testOrigin, token, req, gate)
			if err != nil {
				return err
			}
			if record {
				ops.SecondFactorPassed(op.ID, testIP)
			}
			ops.CompleteLogin(op, testIP)
		}
		return ops.SecondFactorWait(f.op.ID, "198.51.100.77")
	}
	if err := run(true); err != nil {
		t.Fatalf("good passkey logins put the operator in a wait: %v", err)
	}
	if err := run(false); !errors.Is(err, ErrThrottled) {
		t.Fatalf("control: unrecorded logins should add up to a wait, got %v", err)
	}
}

func TestHasPasskeysReportsErrors(t *testing.T) {
	db := newTestDB(t)
	opID := seedOperatorWithPassword(t, db, "mia", "password-12345")
	wa := &WebAuthnService{repo: repository.NewWebAuthnRepository(db), store: newChallengeStore()}
	if has, err := wa.HasPasskeys(opID); err != nil || has {
		t.Fatalf("no passkeys: %v %v", has, err)
	}
	if err := db.Migrator().DropTable(&database.OperatorCredential{}); err != nil {
		t.Fatal(err)
	}
	if _, err := wa.HasPasskeys(opID); err == nil {
		t.Fatal("a failed count was reported as no passkeys")
	}
}

func TestValidateNewOperatorRefusalsAreValidation(t *testing.T) {
	db := newTestDB(t)
	seedOperator(t, db, "vera")
	svc := NewOperatorService(repository.NewOperatorRepository(db))
	for _, c := range [][2]string{{"ab", "password-12345"}, {"admin", "password-12345"},
		{"walt", "short"}, {"VERA", "password-12345"}} {
		if err := svc.ValidateNewOperator(c[0], c[1]); !IsValidation(err) {
			t.Errorf("%v: %v is not a validation refusal", c, err)
		}
	}
	if err := svc.ValidateNewOperator("VERA", "password-12345"); !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("taken name: %v", err)
	}
}
