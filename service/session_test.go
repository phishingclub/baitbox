package service

import (
	"errors"
	"testing"
	"time"

	"github.com/phishingclub/baitbox/crypto"
	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/repository"
	"gorm.io/gorm"
)

// seedOperator inserts an operator row and returns its id.
func seedOperator(t *testing.T, db *gorm.DB, username string) string {
	t.Helper()
	op := database.Operator{Username: username, PasswordHash: "x"}
	if err := db.Create(&op).Error; err != nil {
		t.Fatalf("seed operator: %v", err)
	}
	return op.ID
}

func TestSessionCreateStoresHashNotRaw(t *testing.T) {
	db := newTestDB(t)
	opID := seedOperator(t, db, "admin")
	srepo := repository.NewSessionRepository(db)
	svc := NewSessionService(srepo)

	raw, err := svc.Create(opID, 0, "10.0.0.1")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// the stored id is the sha256 of the raw cookie, so a db read cannot resurrect
	// a live session. The raw value itself is not a key.
	if byHash, _ := srepo.FindByID(crypto.HashToken(raw)); byHash == nil {
		t.Fatal("session not found by hashed id")
	}
	if byRaw, _ := srepo.FindByID(raw); byRaw != nil {
		t.Fatal("session found by raw cookie value; raw should not be the stored id")
	}
}

func TestSessionValidate(t *testing.T) {
	db := newTestDB(t)
	opID := seedOperator(t, db, "admin")
	svc := NewSessionService(repository.NewSessionRepository(db))

	raw, err := svc.Create(opID, 0, "10.0.0.1")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// valid cookie from the bound IP returns the owning operator.
	op, err := svc.Validate(raw, "10.0.0.1")
	if err != nil || op == nil || op.ID != opID {
		t.Fatalf("validate: op=%v err=%v", op, err)
	}

	// an empty id is invalid.
	if _, err := svc.Validate("", "10.0.0.1"); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("empty id: want ErrSessionInvalid, got %v", err)
	}
}

func TestSessionIPBindingInvalidatesAndDeletes(t *testing.T) {
	db := newTestDB(t)
	opID := seedOperator(t, db, "admin")
	srepo := repository.NewSessionRepository(db)
	svc := NewSessionService(srepo)

	raw, err := svc.Create(opID, 0, "10.0.0.1")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// a request from a different IP is rejected, and the offending session is
	// deleted so it cannot be retried.
	if _, err := svc.Validate(raw, "10.0.0.99"); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("ip mismatch: want ErrSessionInvalid, got %v", err)
	}
	if s, _ := srepo.FindByID(crypto.HashToken(raw)); s != nil {
		t.Fatal("invalid session not deleted after IP mismatch")
	}
}

func TestSessionExpiryInvalidates(t *testing.T) {
	db := newTestDB(t)
	opID := seedOperator(t, db, "admin")
	srepo := repository.NewSessionRepository(db)
	svc := NewSessionService(srepo)

	raw, err := svc.Create(opID, 0, "10.0.0.1")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// force the idle window into the past.
	if err := srepo.Touch(crypto.HashToken(raw), map[string]any{"idle_expires_at": time.Now().Add(-time.Minute)}); err != nil {
		t.Fatalf("touch: %v", err)
	}
	if _, err := svc.Validate(raw, "10.0.0.1"); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("expired: want ErrSessionInvalid, got %v", err)
	}
}

func TestSessionDestroy(t *testing.T) {
	db := newTestDB(t)
	opID := seedOperator(t, db, "admin")
	srepo := repository.NewSessionRepository(db)
	svc := NewSessionService(srepo)

	raw, err := svc.Create(opID, 0, "10.0.0.1")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := svc.Destroy(raw); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if s, _ := srepo.FindByID(crypto.HashToken(raw)); s != nil {
		t.Fatal("session not removed by destroy")
	}
	// destroying an empty id is a no-op, not an error.
	if err := svc.Destroy(""); err != nil {
		t.Fatalf("destroy empty: %v", err)
	}
}
