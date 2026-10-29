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

	"github.com/phishingclub/baitbox/crypto"
	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/repository"
	"gorm.io/gorm"
)

// totpCodeForNow computes the current TOTP code for a secret the same way the
// crypto package does, so a test can drive the real MFA verification without an
// authenticator app. It is a local, test-only reimplementation (stdlib only).
func totpCodeForNow(t *testing.T, secret string) (string, uint64) {
	t.Helper()
	b32 := base32.StdEncoding.WithPadding(base32.NoPadding)
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	counter := uint64(time.Now().Unix() / 30)
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
	return fmt.Sprintf("%06d", bin%1000000), counter
}

func seedOperatorWithPassword(t *testing.T, db *gorm.DB, username, password string) string {
	t.Helper()
	hash, err := crypto.HashPassword(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	op := database.Operator{Username: username, PasswordHash: hash}
	if err := db.Create(&op).Error; err != nil {
		t.Fatalf("seed operator: %v", err)
	}
	return op.ID
}

func TestClaimMFACounterMonotonic(t *testing.T) {
	db := newTestDB(t)
	opID := seedOperator(t, db, "admin")
	repo := repository.NewOperatorRepository(db)

	// first claim of a higher step advances the counter.
	if n, err := repo.ClaimMFACounter(opID, 5); err != nil || n != 1 {
		t.Fatalf("claim 5: rows=%d err=%v", n, err)
	}
	// re-claiming the same step changes nothing (replay blocked).
	if n, err := repo.ClaimMFACounter(opID, 5); err != nil || n != 0 {
		t.Fatalf("re-claim 5: rows=%d err=%v want 0", n, err)
	}
	// a lower step is also refused.
	if n, err := repo.ClaimMFACounter(opID, 4); err != nil || n != 0 {
		t.Fatalf("claim 4: rows=%d err=%v want 0", n, err)
	}
	// a strictly higher step advances again.
	if n, err := repo.ClaimMFACounter(opID, 6); err != nil || n != 1 {
		t.Fatalf("claim 6: rows=%d err=%v want 1", n, err)
	}
}

// TestAuthenticateMFAReplayBlocked drives the full service path: the first use
// of a valid code authenticates and claims its time-step counter; a second use
// of the same code is rejected, so a captured code cannot be replayed.
func TestAuthenticateMFAReplayBlocked(t *testing.T) {
	db := newTestDB(t)
	const pw = "password-12345"
	opID := seedOperatorWithPassword(t, db, "admin", pw)
	repo := repository.NewOperatorRepository(db)
	svc := NewOperatorService(repo)

	secret := crypto.NewTOTPSecret()
	setOperatorFields(t, db, opID, map[string]any{
		"mfa_secret": secret, "mfa_enabled": true, "mfa_last_counter": 0,
	})

	code, _ := totpCodeForNow(t, secret)

	// password without a code reports ErrMFARequired.
	if _, err := svc.Authenticate("admin", pw, "", testIP); !errors.Is(err, ErrMFARequired) {
		t.Fatalf("no code: want ErrMFARequired, got %v", err)
	}

	// first use of the code succeeds.
	op, err := svc.Authenticate("admin", pw, code, testIP)
	if err != nil || op == nil {
		t.Fatalf("first auth: op=%v err=%v", op, err)
	}

	// replaying the same code (same time step) is rejected.
	if _, err := svc.Authenticate("admin", pw, code, testIP); !errors.Is(err, ErrMFARequired) {
		t.Fatalf("replay: want ErrMFARequired, got %v", err)
	}
}

func TestAuthenticateWrongPassword(t *testing.T) {
	db := newTestDB(t)
	seedOperatorWithPassword(t, db, "admin", "password-12345")
	svc := NewOperatorService(repository.NewOperatorRepository(db))

	if _, err := svc.Authenticate("admin", "wrong-password", "", testIP); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password: want ErrInvalidCredentials, got %v", err)
	}
	// an unknown username also reports the same generic error.
	if _, err := svc.Authenticate("ghost", "whatever-1234", "", testIP); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown user: want ErrInvalidCredentials, got %v", err)
	}
}
