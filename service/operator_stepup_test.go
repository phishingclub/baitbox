package service

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/repository"
)

// totpCodeAt computes the TOTP code for a secret at a given time step, so a
// test can use a code for the next step after the current one was claimed.
func totpCodeAt(t *testing.T, secret string, counter uint64) string {
	t.Helper()
	b32 := base32.StdEncoding.WithPadding(base32.NoPadding)
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	return fmt.Sprintf("%06d", bin%1000000)
}

// wrongCode returns a 6 digit code that does not match the secret in the
// current window.
func wrongCode(t *testing.T, secret string) string {
	t.Helper()
	now := uint64(time.Now().Unix() / 30)
	valid := map[string]bool{}
	for _, c := range []uint64{now - 1, now, now + 1} {
		valid[totpCodeAt(t, secret, c)] = true
	}
	for i := 0; i < 1000000; i++ {
		code := fmt.Sprintf("%06d", i)
		if !valid[code] {
			return code
		}
	}
	t.Fatal("no wrong code found")
	return ""
}

func TestMFAEnrollUsesServerSecretAndDropsSessions(t *testing.T) {
	db := newTestDB(t)
	const pw = "password-12345"
	opID := seedOperatorWithPassword(t, db, "gina", pw)
	svc := NewOperatorService(repository.NewOperatorRepository(db))
	sessions := NewSessionService(repository.NewSessionRepository(db))

	if _, err := svc.ConfirmMFAEnroll(opID, "123456"); !errors.Is(err, ErrNoPendingMFA) {
		t.Fatalf("confirm without begin: got %v", err)
	}
	secret, _, err := svc.BeginMFAEnroll(opID)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	raw, err := sessions.Create(opID, 0, "10.0.0.1")
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	if _, err := svc.ConfirmMFAEnroll(opID, wrongCode(t, secret)); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong code: got %v", err)
	}
	code, counter := totpCodeForNow(t, secret)
	if _, err := svc.ConfirmMFAEnroll(opID, code); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	op, _ := svc.GetOperator(opID)
	if !op.MFAEnabled || op.MFASecret != secret {
		t.Fatal("mfa not enabled with the pending secret")
	}
	if _, err := sessions.Validate(raw, "10.0.0.1"); err == nil {
		t.Fatal("session survived enabling mfa")
	}
	// the pending secret is gone once used.
	if _, err := svc.ConfirmMFAEnroll(opID, code); !errors.Is(err, ErrNoPendingMFA) {
		t.Fatalf("second confirm: got %v", err)
	}

	// step up now needs a code, not the password, and the confirming code is spent.
	if err := svc.StepUp(opID, "", pw); !errors.Is(err, ErrStepUpRequired) {
		t.Fatalf("password step up with mfa on: got %v", err)
	}
	if err := svc.StepUp(opID, code, ""); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("replayed code step up: got %v", err)
	}
	if err := svc.StepUp(opID, totpCodeAt(t, secret, counter+1), ""); err != nil {
		t.Fatalf("fresh code step up: %v", err)
	}
}

func TestStepUpMethods(t *testing.T) {
	db := newTestDB(t)
	const pw = "password-12345"
	opID := seedOperatorWithPassword(t, db, "hank", pw)
	svc := NewOperatorService(repository.NewOperatorRepository(db))

	totp, passkey, password, err := svc.StepUpMethods(opID)
	if err != nil || totp || passkey || !password {
		t.Fatalf("no factor: totp=%v passkey=%v password=%v err=%v", totp, passkey, password, err)
	}
	if err := svc.StepUp(opID, "", ""); !errors.Is(err, ErrStepUpRequired) {
		t.Fatalf("empty step up: got %v", err)
	}
	if err := svc.StepUp(opID, "", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password step up: got %v", err)
	}
	if err := svc.StepUp(opID, "", pw); err != nil {
		t.Fatalf("password step up: %v", err)
	}

	if err := db.Create(&database.OperatorCredential{OperatorID: opID, Name: "key", CredentialID: []byte("cred-1")}).Error; err != nil {
		t.Fatalf("seed passkey: %v", err)
	}
	totp, passkey, password, _ = svc.StepUpMethods(opID)
	if totp || !passkey || password {
		t.Fatalf("passkey only: totp=%v passkey=%v password=%v", totp, passkey, password)
	}
	if err := svc.StepUp(opID, "", pw); !errors.Is(err, ErrStepUpPasskey) {
		t.Fatalf("password step up with a passkey: got %v", err)
	}
}

func TestStepUpGrantSingleUse(t *testing.T) {
	db := newTestDB(t)
	opID := seedOperator(t, db, "ivy")
	other := seedOperator(t, db, "jack")
	sessions := NewSessionService(repository.NewSessionRepository(db))
	raw, err := sessions.Create(opID, 0, "10.0.0.1")
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	if sessions.ConsumeStepUp(raw, opID) {
		t.Fatal("grant without a step up")
	}
	sessions.GrantStepUp(raw, opID)
	if sessions.ConsumeStepUp(raw, other) {
		t.Fatal("grant used by another operator")
	}
	sessions.GrantStepUp(raw, opID)
	if !sessions.ConsumeStepUp(raw, opID) {
		t.Fatal("grant not usable")
	}
	if sessions.ConsumeStepUp(raw, opID) {
		t.Fatal("grant used twice")
	}
	sessions.GrantStepUp(raw, opID)
	if sessions.ConsumeStepUp("another-session", opID) {
		t.Fatal("grant used from another session")
	}
}

func TestDeleteOperatorRemovesPasskeys(t *testing.T) {
	db := newTestDB(t)
	keep := seedOperator(t, db, "kate")
	gone := seedOperator(t, db, "liam")
	for i, id := range []string{keep, gone} {
		if err := db.Create(&database.OperatorCredential{OperatorID: id, Name: "key", CredentialID: []byte(fmt.Sprintf("cred-%d", i))}).Error; err != nil {
			t.Fatalf("seed passkey: %v", err)
		}
	}
	repo := repository.NewOperatorRepository(db)
	svc := NewOperatorService(repo)
	if err := svc.DeleteOperator(gone); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if n, _ := repo.CountCredentialsByOperator(gone); n != 0 {
		t.Fatalf("deleted operator still has %d passkeys", n)
	}
	if n, _ := repo.CountCredentialsByOperator(keep); n != 1 {
		t.Fatalf("other operator lost passkeys: %d", n)
	}
}

func TestPasskeyDeleteAndTokenNotFound(t *testing.T) {
	db := newTestDB(t)
	opID := seedOperator(t, db, "mona")
	wa := &WebAuthnService{repo: repository.NewWebAuthnRepository(db), store: newChallengeStore()}
	if err := wa.Delete(opID, "missing", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("passkey delete of unknown id: got %v", err)
	}
	tokens := NewTokenService(repository.NewTokenRepository(db))
	if err := tokens.Revoke("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("token revoke of unknown id: got %v", err)
	}
	if err := tokens.Delete("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("token delete of unknown id: got %v", err)
	}
}

func TestPasskeyNameLength(t *testing.T) {
	if n, err := ValidPasskeyName("  "); err != nil || n != "Passkey" {
		t.Fatalf("empty name: %q %v", n, err)
	}
	if _, err := ValidPasskeyName(strings.Repeat("é", MaxPasskeyNameLen)); err != nil {
		t.Fatalf("name at the limit rejected: %v", err)
	}
	if _, err := ValidPasskeyName(strings.Repeat("x", MaxPasskeyNameLen+1)); !errors.Is(err, ErrPasskeyName) {
		t.Fatalf("long name: got %v", err)
	}
}
