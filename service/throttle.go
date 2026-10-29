package service

import (
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"time"
)

// ErrThrottled is returned when an attempt comes before its wait has run out.
// The attempt was not checked, so the reply says nothing about the credential.
var ErrThrottled = errors.New("too many attempts")

// ThrottledError carries how long the caller must wait before the next attempt
// is checked. errors.Is(err, ErrThrottled) matches it.
type ThrottledError struct {
	RetryAfter time.Duration
}

func (e *ThrottledError) Error() string {
	if e.Seconds() == 1 {
		return "too many attempts, try again in 1 second"
	}
	return fmt.Sprintf("too many attempts, try again in %d seconds", e.Seconds())
}

// Is makes errors.Is(err, ErrThrottled) true for a ThrottledError.
func (e *ThrottledError) Is(target error) bool { return target == ErrThrottled }

// Seconds is the wait rounded up to whole seconds, at least 1, for a
// Retry-After header.
func (e *ThrottledError) Seconds() int {
	s := int(math.Ceil(e.RetryAfter.Seconds()))
	if s < 1 {
		s = 1
	}
	return s
}

// throttlePolicy sets how failed attempts slow down further attempts.
//
// A client may fail free times without any wait. After that each failure makes
// the next attempt from that client wait base, then twice as long, and so on up
// to max. A correct credential is checked as soon as the wait has passed, so the
// wait never grows into a lockout.
//
// The failures of every client for one subject also add up. Once that total
// passes globalFree, every client of the subject that already failed must wait
// the backoff of that total (capped at max) after its own last failure. A client
// that never failed is not held by the total, unless holdNewClients is set.
//
// With holdNewClients every client, new ones included, must also wait the backoff
// of the total after the last failure of the subject from any client. Fresh
// addresses then buy an attacker nothing, and the real user still gets checked
// once that wait has passed.
type throttlePolicy struct {
	free       int
	globalFree int
	base       time.Duration
	max        time.Duration
	// holdNewClients applies the subject wait to every client, see above.
	holdNewClients bool
	// idle is how long a subject or client must stay quiet before its count is
	// forgotten.
	idle time.Duration
}

// delay is the wait after n failures with free failures allowed for nothing.
func (p throttlePolicy) delay(n, free int) time.Duration {
	if n <= free {
		return 0
	}
	shift := n - free - 1
	if shift > 30 {
		return p.max
	}
	d := p.base << shift
	if d > p.max || d <= 0 {
		return p.max
	}
	return d
}

// throttleEntry is the count of one client of a subject. fails includes attempts
// still being checked, so parallel requests cannot skip the wait.
type throttleEntry struct {
	fails int
	next  time.Time
	last  time.Time
	// lastFail is when the client last failed, which the subject total measures
	// its wait from; prevFail is the value before the attempt being checked, put
	// back when that attempt passes.
	lastFail time.Time
	prevFail time.Time
}

// throttleSubject holds the total for one subject and the count per client.
type throttleSubject struct {
	total int
	last  time.Time
	// lastFail is the last failure of the subject from any client; prevFail is the
	// value before the attempt being checked, put back when that attempt passes.
	lastFail time.Time
	prevFail time.Time
	clients  map[string]*throttleEntry
}

// throttle slows down repeated failed attempts per subject (a username, an
// operator id or a session) and client (an address prefix). It is in memory and
// per process. It never refuses a correct credential once the wait has passed.
type throttle struct {
	mu       sync.Mutex
	policy   throttlePolicy
	subjects map[string]*throttleSubject
	now      func() time.Time
}

// newThrottle builds a throttle and starts dropping idle subjects.
func newThrottle(p throttlePolicy) *throttle {
	t := &throttle{policy: p, subjects: map[string]*throttleSubject{}, now: time.Now}
	go t.cleanup()
	return t
}

// ClientKey groups a client address: an IPv4 address as is, an IPv6 address by
// its /64, since one host usually holds a whole /64. The throttles and the
// login rate limiter both key on it.
func ClientKey(ip string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return ip
	}
	if v4 := parsed.To4(); v4 != nil {
		return v4.String()
	}
	return parsed.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// lookup returns the subject and client entries, forgetting counts that went
// idle. The caller holds t.mu.
func (t *throttle) lookup(subject, client string, create bool, now time.Time) (*throttleSubject, *throttleEntry) {
	s := t.subjects[subject]
	if s == nil {
		if !create {
			return nil, nil
		}
		s = &throttleSubject{clients: map[string]*throttleEntry{}}
		t.subjects[subject] = s
	}
	if !s.last.IsZero() && now.Sub(s.last) > t.policy.idle {
		s.total = 0
	}
	e := s.clients[client]
	if e != nil && now.Sub(e.last) > t.policy.idle && !now.Before(e.next) {
		delete(s.clients, client)
		e = nil
	}
	if e == nil && create {
		e = &throttleEntry{}
		s.clients[client] = e
	}
	return s, e
}

// waitFor is how long the client must still wait. e is nil for a client with
// no count. The caller holds t.mu.
func (t *throttle) waitFor(s *throttleSubject, e *throttleEntry, now time.Time) time.Duration {
	if s == nil {
		return 0
	}
	subjectWait := t.policy.delay(s.total, t.policy.globalFree)
	var allowed time.Time
	if e != nil {
		allowed = e.next
		if !e.lastFail.IsZero() {
			if floor := e.lastFail.Add(subjectWait); floor.After(allowed) {
				allowed = floor
			}
		}
	}
	if t.policy.holdNewClients && !s.lastFail.IsZero() {
		if floor := s.lastFail.Add(subjectWait); floor.After(allowed) {
			allowed = floor
		}
	}
	if now.Before(allowed) {
		return allowed.Sub(now)
	}
	return 0
}

// wait reports how long the client must wait before an attempt is checked,
// without counting anything.
func (t *throttle) wait(subject, ip string) time.Duration {
	subject = strings.ToLower(subject)
	client := ClientKey(ip)
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	s, e := t.lookup(subject, client, false, now)
	return t.waitFor(s, e, now)
}

// begin starts an attempt. Inside a wait it returns a ThrottledError and counts
// nothing, so the caller must not check the credential. Otherwise the attempt
// counts as a failure until passed is called, so parallel attempts see it.
func (t *throttle) begin(subject, ip string) error {
	subject = strings.ToLower(subject)
	client := ClientKey(ip)
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	s, e := t.lookup(subject, client, true, now)
	if w := t.waitFor(s, e, now); w > 0 {
		return &ThrottledError{RetryAfter: w}
	}
	e.fails++
	e.last = now
	e.prevFail = e.lastFail
	e.lastFail = now
	e.next = now.Add(t.policy.delay(e.fails, t.policy.free))
	s.total++
	s.last = now
	s.prevFail = s.lastFail
	s.lastFail = now
	return nil
}

// passed undoes the count of an attempt begun with begin whose credential was
// right.
func (t *throttle) passed(subject, ip string) {
	subject = strings.ToLower(subject)
	client := ClientKey(ip)
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.subjects[subject]
	if s == nil {
		return
	}
	if s.total > 0 {
		s.total--
	}
	e := s.clients[client]
	if e == nil {
		return
	}
	// put back the subject failure time only when no other attempt began since.
	if s.lastFail.Equal(e.lastFail) {
		s.lastFail = s.prevFail
	}
	if e.fails > 0 {
		e.fails--
	}
	e.next = time.Time{}
	e.lastFail = e.prevFail
}

// resetClient clears the count of one client of the subject after a full login
// from it. Other clients and the subject total keep counting, so a login by the
// real user does not hand an attacker on another address fresh attempts.
func (t *throttle) resetClient(subject, ip string) {
	subject = strings.ToLower(subject)
	client := ClientKey(ip)
	t.mu.Lock()
	defer t.mu.Unlock()
	if s := t.subjects[subject]; s != nil {
		delete(s.clients, client)
	}
}

// resetSubject forgets every count of the subject.
func (t *throttle) resetSubject(subject string) {
	subject = strings.ToLower(subject)
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.subjects, subject)
}

// cleanup drops subjects and clients that went idle, so the maps stay bounded.
func (t *throttle) cleanup() {
	ticker := time.NewTicker(t.policy.idle)
	defer ticker.Stop()
	for range ticker.C {
		t.sweep()
	}
}

// sweep is one pass of cleanup.
func (t *throttle) sweep() {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for k, s := range t.subjects {
		for c, e := range s.clients {
			if now.Sub(e.last) > t.policy.idle && !now.Before(e.next) {
				delete(s.clients, c)
			}
		}
		if len(s.clients) == 0 && now.Sub(s.last) > t.policy.idle {
			delete(t.subjects, k)
		}
	}
}
