package service

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/phishingclub/baitbox/repository"
	"gorm.io/gorm"
)

const testIP = "10.0.0.1"

// fakeClock is a settable time source for throttles.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }
func newFakeClock() *fakeClock               { return &fakeClock{t: time.Unix(1_700_000_000, 0)} }
func throttledFor(t *testing.T, err error) time.Duration {
	t.Helper()
	var te *ThrottledError
	if !errors.As(err, &te) {
		t.Fatalf("want a throttle refusal, got %v", err)
	}
	return te.RetryAfter
}

// newClockedOperatorService builds an OperatorService whose throttles use clock.
func newClockedOperatorService(t *testing.T, clock *fakeClock) (*OperatorService, *repository.OperatorRepository, *gorm.DB) {
	t.Helper()
	db := newTestDB(t)
	repo := repository.NewOperatorRepository(db)
	svc := NewOperatorService(repo)
	svc.passwords.now = clock.now
	svc.secondFactors.now = clock.now
	return svc, repo, db
}

func TestThrottleBackoffIsCapped(t *testing.T) {
	clock := newFakeClock()
	th := newThrottle(passwordThrottle)
	th.now = clock.now
	for i := 0; i < passwordThrottle.free; i++ {
		if err := th.begin("alice", testIP); err != nil {
			t.Fatalf("free attempt %d refused: %v", i, err)
		}
	}
	if err := th.begin("alice", testIP); err != nil {
		t.Fatalf("attempt after the free ones refused: %v", err)
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second, 30 * time.Second}
	for i, w := range want {
		got := throttledFor(t, th.begin("alice", testIP))
		if got != w {
			t.Fatalf("wait %d: got %v want %v", i, got, w)
		}
		// an attempt inside the wait is refused and does not make it longer.
		clock.advance(w / 2)
		if again := throttledFor(t, th.begin("alice", testIP)); again != w-w/2 {
			t.Fatalf("wait %d grew inside the wait: %v", i, again)
		}
		clock.advance(w - w/2)
		if err := th.begin("alice", testIP); err != nil {
			t.Fatalf("attempt after wait %d refused: %v", i, err)
		}
	}
	// the count is forgotten after the idle window.
	clock.advance(passwordThrottle.idle + passwordThrottle.max + time.Second)
	for i := 0; i < passwordThrottle.free+1; i++ {
		if err := th.begin("alice", testIP); err != nil {
			t.Fatalf("count kept after idle, attempt %d: %v", i, err)
		}
	}
}

// failPasswords makes n wrong logins, waiting out each throttle wait.
func failPasswords(t *testing.T, svc *OperatorService, clock *fakeClock, username, ip string, n int) {
	t.Helper()
	for i := 0; i < n; {
		_, err := svc.AuthenticatePassword(username, "wrong password", ip)
		if errors.Is(err, ErrThrottled) {
			clock.advance(throttledFor(t, err))
			continue
		}
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("wrong password %d: got %v", i, err)
		}
		i++
	}
}

func TestCorrectPasswordSucceedsAfterWait(t *testing.T) {
	clock := newFakeClock()
	svc, _, db := newClockedOperatorService(t, clock)
	const pw = "password-12345"
	seedOperatorWithPassword(t, db, "carol", pw)

	// stay under the total across clients, so only this client's backoff counts.
	failPasswords(t, svc, clock, "carol", testIP, passwordThrottle.globalFree-8)
	wait := throttledFor(t, svc.passwords.begin("carol", testIP))
	if wait != passwordThrottle.max {
		t.Fatalf("wait after many failures: %v", wait)
	}
	// inside the wait the right and the wrong password get the same refusal and
	// neither is checked or counted.
	clock.advance(time.Second)
	rightErr := throttledFor(t, func() error { _, err := svc.AuthenticatePassword("carol", pw, testIP); return err }())
	wrongErr := throttledFor(t, func() error { _, err := svc.AuthenticatePassword("carol", "nope", testIP); return err }())
	if rightErr != wrongErr || rightErr != wait-time.Second {
		t.Fatalf("throttled replies differ or grew: right %v wrong %v", rightErr, wrongErr)
	}
	// once the wait passes the right password is always accepted.
	clock.advance(rightErr)
	op, err := svc.AuthenticatePassword("carol", pw, testIP)
	if err != nil {
		t.Fatalf("right password after the wait: %v", err)
	}
	// the right password alone does not reset the count, a completed login does.
	_, err = svc.AuthenticatePassword("carol", "wrong", testIP)
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password right after a right one: %v", err)
	}
	if svc.passwords.wait("carol", testIP) == 0 {
		t.Fatal("count reset by a password only success")
	}
	clock.advance(passwordThrottle.max)
	op, err = svc.AuthenticatePassword("carol", pw, testIP)
	if err != nil {
		t.Fatalf("right password: %v", err)
	}
	svc.CompleteLogin(op, testIP)
	for i := 0; i < passwordThrottle.free; i++ {
		if _, err := svc.AuthenticatePassword("carol", "wrong", testIP); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("count not reset by a completed login, attempt %d: %v", i, err)
		}
	}
}

func TestUnknownUsernameThrottledAlike(t *testing.T) {
	clock := newFakeClock()
	svc, _, db := newClockedOperatorService(t, clock)
	seedOperatorWithPassword(t, db, "dave", "password-12345")
	n := passwordThrottle.free + 2
	failPasswords(t, svc, clock, "dave", testIP, n)
	real := throttledFor(t, func() error { _, err := svc.AuthenticatePassword("dave", "x", testIP); return err }())
	failPasswords(t, svc, clock, "ghost", testIP, n)
	ghost := throttledFor(t, func() error { _, err := svc.AuthenticatePassword("ghost", "x", testIP); return err }())
	if real != ghost {
		t.Fatalf("known and unknown usernames throttle differently: %v and %v", real, ghost)
	}
}

func TestThrottleIsPerClient(t *testing.T) {
	clock := newFakeClock()
	svc, _, db := newClockedOperatorService(t, clock)
	const pw = "password-12345"
	seedOperatorWithPassword(t, db, "erin", pw)

	// an attacker on one /64 hammers; addresses in the same /64 share its wait.
	failPasswords(t, svc, clock, "erin", "2001:db8:1:1::1", 10)
	if _, err := svc.AuthenticatePassword("erin", pw, "2001:db8:1:1::ffff"); !errors.Is(err, ErrThrottled) {
		t.Fatalf("same /64 escaped the wait: %v", err)
	}
	// the real user on another address is checked at once.
	op, err := svc.AuthenticatePassword("erin", pw, "2001:db8:2:2::1")
	if err != nil {
		t.Fatalf("real user on another /64: %v", err)
	}
	svc.CompleteLogin(op, "2001:db8:2:2::1")
	// that login hands the attacker no fresh attempts.
	if _, err := svc.AuthenticatePassword("erin", "x", "2001:db8:1:1::1"); !errors.Is(err, ErrThrottled) {
		t.Fatalf("attacker wait cleared by the real login: %v", err)
	}
}

func TestThrottleTotalAcrossClients(t *testing.T) {
	clock := newFakeClock()
	svc, _, db := newClockedOperatorService(t, clock)
	const pw = "password-12345"
	seedOperatorWithPassword(t, db, "finn", pw)

	// many addresses, one guess each, pass the total.
	for i := 0; i < passwordThrottle.globalFree+5; i++ {
		failPasswords(t, svc, clock, "finn", fmt.Sprintf("198.51.100.%d", i), 1)
	}
	// an address that already failed must now wait even on its second guess.
	if _, err := svc.AuthenticatePassword("finn", "x", "198.51.100.0"); !errors.Is(err, ErrThrottled) {
		t.Fatalf("total did not slow a failed address: %v", err)
	}
	// a fresh address is still checked at once, so the real user gets in.
	op, err := svc.AuthenticatePassword("finn", pw, "203.0.113.9")
	if err != nil {
		t.Fatalf("real user under a spread attack: %v", err)
	}
	// and a typo there waits at most the cap before the right password is checked.
	_, _ = svc.AuthenticatePassword("finn", "typo", "203.0.113.9")
	w := throttledFor(t, func() error { _, err := svc.AuthenticatePassword("finn", pw, "203.0.113.9"); return err }())
	if w > passwordThrottle.max {
		t.Fatalf("wait above the cap: %v", w)
	}
	clock.advance(w)
	if _, err := svc.AuthenticatePassword("finn", pw, "203.0.113.9"); err != nil {
		t.Fatalf("right password after the wait under attack: %v (waited %v)", err, w)
	}
	svc.CompleteLogin(op, "203.0.113.9")
}

func TestParallelAttemptsCountBeforeTheResult(t *testing.T) {
	clock := newFakeClock()
	th := newThrottle(passwordThrottle)
	th.now = clock.now
	// attempts begun but not yet finished count, so a burst cannot skip the wait.
	for i := 0; i < passwordThrottle.free+1; i++ {
		if err := th.begin("gail", testIP); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if err := th.begin("gail", testIP); !errors.Is(err, ErrThrottled) {
		t.Fatalf("burst skipped the wait: %v", err)
	}
	// a passed attempt gives its count back.
	th.passed("gail", testIP)
	if err := th.begin("gail", testIP); err != nil {
		t.Fatalf("passed attempt still counted: %v", err)
	}
}

func TestSecondFactorThrottle(t *testing.T) {
	clock := newFakeClock()
	svc, _, db := newClockedOperatorService(t, clock)
	const pw = "password-12345"
	opID := seedOperatorWithPassword(t, db, "hugo", pw)
	secret := enableTOTP(t, db, opID)
	bad := wrongCode(t, secret)

	for i := 0; i < secondFactorThrottle.free+1; i++ {
		if _, err := svc.Authenticate("hugo", pw, bad, testIP); !errors.Is(err, ErrMFARequired) {
			t.Fatalf("wrong code %d: %v", i, err)
		}
	}
	good, _ := totpCodeForNow(t, secret)
	w := throttledFor(t, func() error { _, err := svc.Authenticate("hugo", pw, good, testIP); return err }())
	// the passkey path shares the wait, and a passkey check inside it is refused.
	if err := svc.SecondFactorWait(opID, testIP); !errors.Is(err, ErrThrottled) {
		t.Fatalf("passkey path not throttled: %v", err)
	}
	if err := svc.BeginSecondFactor(opID, testIP); !errors.Is(err, ErrThrottled) {
		t.Fatalf("passkey check inside the wait: %v", err)
	}
	// the password step is not slowed by second factor failures.
	if _, err := svc.AuthenticatePassword("hugo", pw, testIP); err != nil {
		t.Fatalf("password step: %v", err)
	}
	clock.advance(w)
	op, err := svc.Authenticate("hugo", pw, good, testIP)
	if err != nil {
		t.Fatalf("right code after the wait: %v", err)
	}
	svc.CompleteLogin(op, testIP)
	if err := svc.SecondFactorWait(opID, testIP); err != nil {
		t.Fatalf("completed login kept the wait: %v", err)
	}
}

func TestSessionProofThrottle(t *testing.T) {
	db := newTestDB(t)
	opID := seedOperator(t, db, "iris")
	sessions := NewSessionService(repository.NewSessionRepository(db))
	clock := newFakeClock()
	sessions.proofs.now = clock.now
	raw, _ := sessions.Create(opID, 0, testIP)
	other, _ := sessions.Create(opID, 0, testIP)

	for i := 0; i < sessionProofThrottle.free+1; i++ {
		if err := sessions.BeginProof(raw); err != nil {
			t.Fatalf("proof %d: %v", i, err)
		}
		if revoked, _ := sessions.ProofFailed(raw); revoked {
			t.Fatalf("revoked at %d", i)
		}
	}
	w := throttledFor(t, sessions.BeginProof(raw))
	if err := sessions.ProofWait(raw); !errors.Is(err, ErrThrottled) {
		t.Fatalf("wait not reported: %v", err)
	}
	// another session of the same operator is not slowed.
	if err := sessions.BeginProof(other); err != nil {
		t.Fatalf("other session throttled: %v", err)
	}
	sessions.ProofSkipped(other)
	clock.advance(w)
	if err := sessions.BeginProof(raw); err != nil {
		t.Fatalf("proof after the wait: %v", err)
	}
	sessions.ProofSucceeded(raw)
	for i := 0; i < sessionProofThrottle.free; i++ {
		if err := sessions.BeginProof(raw); err != nil {
			t.Fatalf("wait kept after a right proof, %d: %v", i, err)
		}
		_, _ = sessions.ProofFailed(raw)
	}
}

func TestClientKey(t *testing.T) {
	cases := map[string]string{
		"192.0.2.7":            "192.0.2.7",
		"::ffff:192.0.2.7":     "192.0.2.7",
		"2001:db8:a:b:1:2:3:4": "2001:db8:a:b::/64",
		"2001:db8:a:b::9":      "2001:db8:a:b::/64",
		"garbage":              "garbage",
	}
	for in, want := range cases {
		if got := ClientKey(in); got != want {
			t.Errorf("ClientKey(%q) = %q want %q", in, got, want)
		}
	}
}

func TestSecondFactorHoldsFreshClients(t *testing.T) {
	clock := newFakeClock()
	th := newThrottle(secondFactorThrottle)
	th.now = clock.now
	// one guess from each fresh /64, one second apart, for many /64s.
	const tries = 15000
	checked := 0
	for i := 0; i < tries; i++ {
		ip := fmt.Sprintf("2001:db8:%x:%x::1", i/65536, i%65536)
		if err := th.begin("op1", ip); err == nil {
			checked++
		} else if !errors.Is(err, ErrThrottled) {
			t.Fatalf("attempt %d: %v", i, err)
		}
		clock.advance(time.Second)
	}
	// past the total a guess is checked about once per max wait, whatever the
	// address.
	limit := secondFactorThrottle.globalFree + 10 + tries/int(secondFactorThrottle.max/time.Second)
	if checked > limit {
		t.Fatalf("fresh /64s got %d checked guesses, want at most %d", checked, limit)
	}
	// the real user from a fresh address is checked once the wait passes.
	w := th.wait("op1", "198.51.100.77")
	if w <= 0 || w > secondFactorThrottle.max {
		t.Fatalf("wait for a fresh client: %v", w)
	}
	clock.advance(w)
	if err := th.begin("op1", "198.51.100.77"); err != nil {
		t.Fatalf("real user after the wait: %v", err)
	}
	th.passed("op1", "198.51.100.77")
}

func TestPasswordThrottleKeepsFreshClientsFree(t *testing.T) {
	clock := newFakeClock()
	th := newThrottle(passwordThrottle)
	th.now = clock.now
	for i := 0; i < passwordThrottle.globalFree+5; i++ {
		if err := th.begin("user", fmt.Sprintf("198.51.100.%d", i)); err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if w := th.wait("user", "203.0.113.1"); w != 0 {
		t.Fatalf("fresh client held by the password total: %v", w)
	}
}
