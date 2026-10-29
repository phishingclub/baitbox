package service

import (
	"errors"
	"fmt"
	"testing"

	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/repository"
	"gorm.io/gorm"
)

// enableTOTP turns on TOTP for an operator with a fixed secret.
func enableTOTP(t *testing.T, db *gorm.DB, opID string) string {
	t.Helper()
	secret := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	setOperatorFields(t, db, opID, map[string]any{"mfa_secret": secret, "mfa_enabled": true})
	return secret
}

func seedPasskey(t *testing.T, db *gorm.DB, opID, credID string) {
	t.Helper()
	if err := db.Create(&database.OperatorCredential{OperatorID: opID, Name: "key", CredentialID: []byte(credID)}).Error; err != nil {
		t.Fatalf("seed passkey: %v", err)
	}
}

func countRows(t *testing.T, q *gorm.DB) int64 {
	t.Helper()
	var n int64
	if err := q.Count(&n).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// Wrong codes and passwords given from a signed in session must not slow the
// operator's login at all.
func TestSessionProofFailuresDoNotTouchLogin(t *testing.T) {
	db := newTestDB(t)
	const pw = "password-12345"
	opID := seedOperatorWithPassword(t, db, "nora", pw)
	repo := repository.NewOperatorRepository(db)
	svc := NewOperatorService(repo)
	secret := enableTOTP(t, db, opID)
	bad := wrongCode(t, secret)

	for i := 0; i < 20; i++ {
		if err := svc.StepUp(opID, bad, ""); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("wrong step up code %d: got %v", i, err)
		}
		if err := svc.DisableMFA(opID, bad, ""); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("wrong disable code %d: got %v", i, err)
		}
	}
	if err := svc.SecondFactorWait(opID, testIP); err != nil {
		t.Fatalf("session side wrong codes throttled the login: %v", err)
	}
	good, _ := totpCodeForNow(t, secret)
	op, err := svc.Authenticate("nora", pw, good, testIP)
	if err != nil {
		t.Fatalf("login after session side failures: %v", err)
	}
	svc.CompleteLogin(op, testIP)

	// a password only operator: wrong step up, change and verify passwords do not
	// touch the login throttle.
	opID2 := seedOperatorWithPassword(t, db, "omar", pw)
	for i := 0; i < passwordThrottle.free+3; i++ {
		if err := svc.StepUp(opID2, "", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("wrong step up password %d: got %v", i, err)
		}
		if err := svc.VerifyPassword(opID2, "wrong"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("wrong verify password %d: got %v", i, err)
		}
		if _, err := svc.ChangePassword(opID2, "wrong", "a new password 123", ""); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("wrong current password %d: got %v", i, err)
		}
	}
	if _, err := svc.AuthenticatePassword("omar", pw, testIP); err != nil {
		t.Fatalf("login after wrong session passwords: %v", err)
	}
	if err := svc.StepUp(opID2, "", pw); err != nil {
		t.Fatalf("right step up password: %v", err)
	}
}

// Wrong login codes slow down the login only; a signed in session can still
// step up with a right code.
func TestLoginThrottleDoesNotBlockStepUp(t *testing.T) {
	db := newTestDB(t)
	const pw = "password-12345"
	opID := seedOperatorWithPassword(t, db, "pia", pw)
	repo := repository.NewOperatorRepository(db)
	svc := NewOperatorService(repo)
	secret := enableTOTP(t, db, opID)
	bad := wrongCode(t, secret)
	for i := 0; i < secondFactorThrottle.free+1; i++ {
		_, _ = svc.Authenticate("pia", pw, bad, testIP)
	}
	if err := svc.SecondFactorWait(opID, testIP); !errors.Is(err, ErrThrottled) {
		t.Fatalf("login side wrong codes did not throttle: %v", err)
	}
	good, _ := totpCodeForNow(t, secret)
	if err := svc.StepUp(opID, good, ""); err != nil {
		t.Fatalf("step up refused by the login throttle: %v", err)
	}
}

func TestSessionProofFailedRevokesAtLimit(t *testing.T) {
	db := newTestDB(t)
	opID := seedOperator(t, db, "quin")
	sessions := NewSessionService(repository.NewSessionRepository(db))
	raw, err := sessions.Create(opID, 0, "10.0.0.1")
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	other, err := sessions.Create(opID, 0, "10.0.0.1")
	if err != nil {
		t.Fatalf("session: %v", err)
	}

	// a correct proof clears the count, so only consecutive failures add up.
	for i := 0; i < SessionSecondFactorLimit-1; i++ {
		if revoked, err := sessions.ProofFailed(raw); revoked || err != nil {
			t.Fatalf("revoked early at %d: %v", i, err)
		}
	}
	sessions.ProofSucceeded(raw)
	for i := 0; i < SessionSecondFactorLimit-1; i++ {
		if revoked, _ := sessions.ProofFailed(raw); revoked {
			t.Fatalf("count not cleared by a success, revoked at %d", i)
		}
	}
	if _, err := sessions.Validate(raw, "10.0.0.1"); err != nil {
		t.Fatalf("session gone before the limit: %v", err)
	}
	sessions.GrantStepUp(raw, opID)
	revoked, err := sessions.ProofFailed(raw)
	if !revoked || err != nil {
		t.Fatalf("not revoked at the limit: revoked=%v err=%v", revoked, err)
	}
	if _, err := sessions.Validate(raw, "10.0.0.1"); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("revoked session still valid: %v", err)
	}
	if sessions.ConsumeStepUp(raw, opID) {
		t.Fatal("revoked session kept its step up grant")
	}
	// the count is per session: the operator's other session is untouched.
	if _, err := sessions.Validate(other, "10.0.0.1"); err != nil {
		t.Fatalf("other session revoked: %v", err)
	}
	if revoked, _ := sessions.ProofFailed(other); revoked {
		t.Fatal("other session shared the count")
	}
}

func TestDeleteOperatorCascade(t *testing.T) {
	db := newTestDB(t)
	keep := seedOperator(t, db, "rita")
	gone := seedOperator(t, db, "sam")
	repo := repository.NewOperatorRepository(db)
	svc := NewOperatorService(repo)
	sessions := NewSessionService(repository.NewSessionRepository(db))
	tokens := NewTokenService(repository.NewTokenRepository(db))
	for i, id := range []string{keep, gone} {
		seedPasskey(t, db, id, fmt.Sprintf("cred-%d", i))
		if _, err := sessions.Create(id, 0, "10.0.0.1"); err != nil {
			t.Fatalf("session: %v", err)
		}
		if _, _, err := tokens.Create("t", []string{"*"}, nil, nil, id, "x"); err != nil {
			t.Fatalf("token: %v", err)
		}
	}

	// a failing statement inside the transaction rolls the whole delete back.
	if err := db.Exec("ALTER TABLE `sessions` RENAME TO `sessions_away`").Error; err != nil {
		t.Fatalf("rename: %v", err)
	}
	if err := svc.DeleteOperator(gone); err == nil {
		t.Fatal("delete succeeded with the sessions table missing")
	}
	if err := db.Exec("ALTER TABLE `sessions_away` RENAME TO `sessions`").Error; err != nil {
		t.Fatalf("rename back: %v", err)
	}
	operatorRows := func(id string) int64 {
		return countRows(t, db.Model(&database.Operator{}).Where("id = ?", id))
	}
	tokenRows := func(opID string, revoked bool) int64 {
		return countRows(t, db.Model(&database.Token{}).
			Where("operator_id = ? AND revoked = ?", opID, revoked))
	}
	credRows := func(opID string) int64 {
		return countRows(t, db.Model(&database.OperatorCredential{}).Where("operator_id = ?", opID))
	}
	sessionRows := func(opID string) int64 {
		return countRows(t, db.Model(&database.Session{}).Where("operator_id = ?", opID))
	}
	if operatorRows(gone) != 1 {
		t.Fatal("operator row deleted by a rolled back transaction")
	}
	if tokenRows(gone, true) != 0 {
		t.Fatal("token revoked by a rolled back transaction")
	}
	if credRows(gone) != 1 {
		t.Fatal("passkey deleted by a rolled back transaction")
	}

	if err := svc.DeleteOperator(gone); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if operatorRows(gone) != 0 {
		t.Fatal("operator row kept")
	}
	if tokenRows(gone, false) != 0 {
		t.Fatal("token of the deleted operator still usable")
	}
	if credRows(gone) != 0 {
		t.Fatal("passkeys kept")
	}
	if sessionRows(gone) != 0 {
		t.Fatal("sessions kept")
	}
	// the other operator keeps everything.
	if credRows(keep) != 1 || sessionRows(keep) != 1 || tokenRows(keep, false) != 1 {
		t.Fatal("other operator lost data")
	}

	// an unknown id is not found, not the last operator.
	if err := svc.DeleteOperator("no-such-operator"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing operator: got %v", err)
	}
	if err := svc.DeleteOperator(gone); !errors.Is(err, ErrNotFound) {
		t.Fatalf("already deleted operator: got %v", err)
	}

	// the last operator is refused and nothing of it changes.
	if err := svc.DeleteOperator(keep); !errors.Is(err, ErrLastOperator) {
		t.Fatalf("last operator: got %v", err)
	}
	if credRows(keep) != 1 || sessionRows(keep) != 1 || tokenRows(keep, false) != 1 {
		t.Fatal("refused delete still changed the last operator")
	}
}

func TestResetSecondFactors(t *testing.T) {
	db := newTestDB(t)
	const pw = "password-12345"
	opID := seedOperatorWithPassword(t, db, "tara", pw)
	otherID := seedOperatorWithPassword(t, db, "uma", pw)
	repo := repository.NewOperatorRepository(db)
	svc := NewOperatorService(repo)
	sessions := NewSessionService(repository.NewSessionRepository(db))
	secret := enableTOTP(t, db, opID)
	enableTOTP(t, db, otherID)
	if _, err := repo.ClaimMFACounter(opID, 42); err != nil {
		t.Fatalf("claim: %v", err)
	}
	seedPasskey(t, db, opID, "cred-a")
	seedPasskey(t, db, opID, "cred-b")
	seedPasskey(t, db, otherID, "cred-c")
	raw, _ := sessions.Create(opID, 0, "10.0.0.1")
	otherRaw, _ := sessions.Create(otherID, 0, "10.0.0.1")
	if _, _, err := svc.BeginMFAEnroll(opID); err != nil {
		t.Fatalf("begin: %v", err)
	}
	bad := wrongCode(t, secret)
	for i := 0; i < secondFactorThrottle.free+1; i++ {
		_, _ = svc.Authenticate("tara", pw, bad, testIP)
	}
	if svc.SecondFactorWait(opID, testIP) == nil {
		t.Fatal("setup: operator not throttled")
	}

	if _, _, err := svc.ResetSecondFactors("nobody"); err == nil {
		t.Fatal("unknown operator accepted")
	}
	if _, _, err := svc.ResetSecondFactors("  "); err == nil {
		t.Fatal("empty username accepted")
	}

	op, removed, err := svc.ResetSecondFactors("TARA")
	if err != nil {
		t.Fatalf("reset: %v", err)
	}
	if op.ID != opID || removed != 2 {
		t.Fatalf("reset returned op=%s removed=%d", op.ID, removed)
	}
	fresh, _ := svc.GetOperator(opID)
	if fresh.MFAEnabled || fresh.MFASecret != "" {
		t.Fatal("totp still on")
	}
	if fresh.MFALastCounter != 42 {
		t.Fatalf("totp counter changed to %d", fresh.MFALastCounter)
	}
	if n, _ := repo.CountCredentialsByOperator(opID); n != 0 {
		t.Fatalf("%d passkeys kept", n)
	}
	if _, err := sessions.Validate(raw, "10.0.0.1"); err == nil {
		t.Fatal("session kept")
	}
	if _, ok := svc.pendingMFASecret(opID); ok {
		t.Fatal("pending enrollment kept")
	}
	if err := svc.SecondFactorWait(opID, testIP); err != nil {
		t.Fatalf("second factor throttle kept: %v", err)
	}
	// the password still works and is now the only factor.
	got, err := svc.Authenticate("tara", pw, "", testIP)
	if err != nil || got.ID != opID {
		t.Fatalf("password login after reset: %v", err)
	}
	totp, passkey, password, _ := svc.StepUpMethods(opID)
	if totp || passkey || !password {
		t.Fatalf("step up methods after reset: totp=%v passkey=%v password=%v", totp, passkey, password)
	}

	// the other operator is untouched.
	other, _ := svc.GetOperator(otherID)
	if !other.MFAEnabled {
		t.Fatal("other operator lost totp")
	}
	if n, _ := repo.CountCredentialsByOperator(otherID); n != 1 {
		t.Fatal("other operator lost passkeys")
	}
	if _, err := sessions.Validate(otherRaw, "10.0.0.1"); err != nil {
		t.Fatalf("other operator signed out: %v", err)
	}
}

func TestValidateNewOperator(t *testing.T) {
	db := newTestDB(t)
	seedOperator(t, db, "vera")
	svc := NewOperatorService(repository.NewOperatorRepository(db))
	cases := map[string][2]string{
		"short name":  {"ab", "password-12345"},
		"reserved":    {"Admin", "password-12345"},
		"short pw":    {"walt", "short"},
		"taken":       {"VERA", "password-12345"},
		"taken space": {" vera ", "password-12345"},
	}
	for name, c := range cases {
		if err := svc.ValidateNewOperator(c[0], c[1]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := svc.ValidateNewOperator("walt", "password-12345"); err != nil {
		t.Fatalf("valid input rejected: %v", err)
	}
}
