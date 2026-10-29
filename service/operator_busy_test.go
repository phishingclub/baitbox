package service

import (
	"errors"
	"testing"

	"github.com/phishingclub/baitbox/crypto"
	"github.com/phishingclub/baitbox/repository"
)

// TestChangePasswordBusyErrors: a busy hash of the current password is a
// throttle refusal, while a busy hash of the new one has its own error that does
// not match ErrThrottled.
func TestChangePasswordBusyErrors(t *testing.T) {
	db := newTestDB(t)
	svc := NewOperatorService(repository.NewOperatorRepository(db))
	op, err := svc.CreateOperator("busy", "a current password 1")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	release := crypto.HoldHashSlots()
	_, err = svc.ChangePassword(op.ID, "a current password 1", "a new password 123", "")
	release()
	if !errors.Is(err, ErrThrottled) || errors.Is(err, ErrNewPasswordBusy) {
		t.Fatalf("busy check of the current password: %v", err)
	}

	hashNewPassword = func(string) (string, error) { return "", crypto.ErrBusy }
	defer func() { hashNewPassword = crypto.HashPassword }()
	_, err = svc.ChangePassword(op.ID, "a current password 1", "a new password 123", "")
	if !errors.Is(err, ErrNewPasswordBusy) || errors.Is(err, ErrThrottled) {
		t.Fatalf("busy hash of the new password: %v", err)
	}
	if err := svc.VerifyPassword(op.ID, "a current password 1"); err != nil {
		t.Fatalf("password changed after a busy hash: %v", err)
	}
}

// TestDisableMFAWhenOff: with two factor off nothing is checked, which the caller
// must be able to tell apart from a correct code.
func TestDisableMFAWhenOff(t *testing.T) {
	db := newTestDB(t)
	svc := NewOperatorService(repository.NewOperatorRepository(db))
	op, err := svc.CreateOperator("nomfa", "a current password 1")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := svc.DisableMFA(op.ID, "000000", ""); !errors.Is(err, ErrMFANotEnabled) {
		t.Fatalf("disable with mfa off: %v", err)
	}
}

// TestLoginBusyCreatesNoThrottleEntry: a login refused because every password
// hash slot is taken neither counts nor creates a throttle entry, and the same
// login works once a slot is free.
func TestLoginBusyCreatesNoThrottleEntry(t *testing.T) {
	db := newTestDB(t)
	svc := NewOperatorService(repository.NewOperatorRepository(db))
	if _, err := svc.CreateOperator("busylogin", "a current password 1"); err != nil {
		t.Fatalf("create: %v", err)
	}
	entries := func() int {
		svc.passwords.mu.Lock()
		defer svc.passwords.mu.Unlock()
		return len(svc.passwords.subjects)
	}
	release := crypto.HoldHashSlots()
	for i := 0; i < 20; i++ {
		_, err := svc.Authenticate("busylogin", "wrong password", "", testIP)
		if !errors.Is(err, ErrThrottled) {
			release()
			t.Fatalf("busy login %d: %v", i, err)
		}
	}
	release()
	if n := entries(); n != 0 {
		t.Fatalf("busy refusals left %d throttle entries", n)
	}
	if _, err := svc.Authenticate("busylogin", "a current password 1", "", testIP); err != nil {
		t.Fatalf("login after busy: %v", err)
	}
}
