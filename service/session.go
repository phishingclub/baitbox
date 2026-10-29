package service

import (
	"errors"
	"log"
	"math"
	"sync"
	"time"

	"github.com/phishingclub/baitbox/crypto"
	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/repository"
)

// Session lifetimes, matching the sibling projects: a sliding idle window and a
// hard maximum age.
const (
	SessionIdleTimeout = 24 * time.Hour
	SessionMaxAge      = 72 * time.Hour
)

// StepUpTTL is how long a step up grant stays usable after the operator proved
// their identity again.
const StepUpTTL = 5 * time.Minute

// SessionSecondFactorLimit is how many wrong proofs of identity in a row one
// signed in session may make before that session is revoked.
// These failures count per session, never per operator: revoking only ends the
// session that made the guesses, and the operator can still sign in.
const SessionSecondFactorLimit = 5

// sessionProofThrottle slows down wrong proofs within one session. It mainly stops
// parallel guesses from all being checked before the session is revoked.
var sessionProofThrottle = throttlePolicy{
	free: 2, globalFree: math.MaxInt, base: time.Second, max: 30 * time.Second, idle: time.Hour,
}

// ErrSessionInvalid is returned when a session is missing, expired or bound to
// a different client IP.
var ErrSessionInvalid = errors.New("session invalid")

// SessionService creates and validates operator sessions. Sessions are bound to
// the client IP: a request from a different IP invalidates the session.
type SessionService struct {
	repo *repository.SessionRepository
	// stepUps holds single use step up grants keyed by the session hash, so a
	// fresh proof of identity on one session unlocks one second factor change on
	// that session only. It is in memory; a restart drops pending grants.
	stepMu  sync.Mutex
	stepUps map[string]stepUpGrant
	// proofFails counts wrong proofs of identity per session hash. It is in
	// memory like the grants and guarded by stepMu.
	proofFails map[string]proofFailEntry
	// proofs throttles proofs of identity per session hash.
	proofs *throttle
}

// proofFailEntry is one session's count of wrong proofs and when it was last
// touched, so idle entries can be dropped.
type proofFailEntry struct {
	fails    int
	lastSeen time.Time
}

// stepUpGrant is one pending step up for the operator owning a session.
type stepUpGrant struct {
	operatorID string
	expires    time.Time
}

// NewSessionService returns a SessionService.
func NewSessionService(repo *repository.SessionRepository) *SessionService {
	return &SessionService{
		repo:       repo,
		stepUps:    map[string]stepUpGrant{},
		proofFails: map[string]proofFailEntry{},
		proofs:     newThrottle(sessionProofThrottle),
	}
}

// GrantStepUp records that the operator owning the session (raw cookie value)
// just proved their identity again. The grant lasts StepUpTTL and is used once.
func (s *SessionService) GrantStepUp(rawID, operatorID string) {
	if rawID == "" || operatorID == "" {
		return
	}
	now := time.Now()
	s.stepMu.Lock()
	defer s.stepMu.Unlock()
	for k, g := range s.stepUps {
		if now.After(g.expires) {
			delete(s.stepUps, k)
		}
	}
	s.stepUps[crypto.HashToken(rawID)] = stepUpGrant{operatorID: operatorID, expires: now.Add(StepUpTTL)}
}

// SweepExpired drops step up grants past their expiry and wrong proof counts
// idle for longer than a session can live, so the memory maps stay small even
// when nobody signs in for a while.
func (s *SessionService) SweepExpired() {
	now := time.Now()
	s.stepMu.Lock()
	defer s.stepMu.Unlock()
	for k, g := range s.stepUps {
		if now.After(g.expires) {
			delete(s.stepUps, k)
		}
	}
	for k, e := range s.proofFails {
		if now.Sub(e.lastSeen) > SessionMaxAge {
			delete(s.proofFails, k)
		}
	}
}

// ConsumeStepUp reports whether the session holds a live step up grant for the
// operator, and removes it so it cannot be used again.
func (s *SessionService) ConsumeStepUp(rawID, operatorID string) bool {
	if rawID == "" || operatorID == "" {
		return false
	}
	key := crypto.HashToken(rawID)
	s.stepMu.Lock()
	defer s.stepMu.Unlock()
	g, ok := s.stepUps[key]
	delete(s.stepUps, key)
	return ok && g.operatorID == operatorID && time.Now().Before(g.expires)
}

// BeginProof starts checking a proof of identity made from the session (raw
// cookie value). Inside the session's wait it returns a ThrottledError and the
// proof must not be checked. Otherwise the caller checks it and then calls
// ProofSucceeded or ProofFailed. Only this session is slowed down; the
// operator's login is not touched.
func (s *SessionService) BeginProof(rawID string) error {
	if rawID == "" {
		return nil
	}
	return s.proofs.begin(crypto.HashToken(rawID), "")
}

// ProofSkipped undoes BeginProof for a request that ended before any proof was
// checked, such as an empty code.
func (s *SessionService) ProofSkipped(rawID string) {
	if rawID == "" {
		return
	}
	s.proofs.passed(crypto.HashToken(rawID), "")
}

// ProofWait reports the session's remaining wait without counting anything.
func (s *SessionService) ProofWait(rawID string) error {
	if rawID == "" {
		return nil
	}
	if w := s.proofs.wait(crypto.HashToken(rawID), ""); w > 0 {
		return &ThrottledError{RetryAfter: w}
	}
	return nil
}

// ProofFailed records one wrong proof of identity made from the session (raw
// cookie value). Once the session reaches SessionSecondFactorLimit failures in a
// row it is deleted and ProofFailed reports true, so the caller signs the
// request out and audits it. The count belongs to the session only; the
// operator's login is not touched.
func (s *SessionService) ProofFailed(rawID string) (revoked bool, err error) {
	if rawID == "" {
		return false, nil
	}
	key := crypto.HashToken(rawID)
	now := time.Now()
	s.stepMu.Lock()
	for k, e := range s.proofFails {
		if now.Sub(e.lastSeen) > SessionMaxAge {
			delete(s.proofFails, k)
		}
	}
	e := s.proofFails[key]
	e.fails++
	e.lastSeen = now
	revoked = e.fails >= SessionSecondFactorLimit
	if revoked {
		delete(s.proofFails, key)
		// a revoked session keeps no step up grant.
		delete(s.stepUps, key)
		s.proofs.resetSubject(key)
	} else {
		s.proofFails[key] = e
	}
	s.stepMu.Unlock()
	if revoked {
		if err := s.repo.Delete(key); err != nil {
			// keep the count at the limit so the next wrong proof tries the delete again.
			s.stepMu.Lock()
			s.proofFails[key] = e
			s.stepMu.Unlock()
			return true, err
		}
	}
	return revoked, nil
}

// ProofSucceeded clears the session's count of wrong proofs and its wait after a
// correct one.
func (s *SessionService) ProofSucceeded(rawID string) {
	if rawID == "" {
		return
	}
	key := crypto.HashToken(rawID)
	s.stepMu.Lock()
	delete(s.proofFails, key)
	s.stepMu.Unlock()
	s.proofs.resetSubject(key)
}

// storedSessionID returns the id a session is stored under for its raw cookie
// value, or empty for an empty value.
func storedSessionID(raw string) string {
	if raw == "" {
		return ""
	}
	return crypto.HashToken(raw)
}

// Create starts a new session for an operator from a client IP and returns the
// opaque cookie value. Only the sha256 of that value is stored, as bearer tokens
// are, so a read of the database cannot resurrect a live session. authEpoch is
// the operator's AuthEpoch from the row the login checked, never a fresh read,
// so a credential change that commits during the login ends this session too.
func (s *SessionService) Create(operatorID string, authEpoch int64, ip string) (string, error) {
	now := time.Now()
	raw := crypto.Token()
	sess := database.Session{
		ID:            crypto.HashToken(raw),
		OperatorID:    operatorID,
		IP:            ip,
		IdleExpiresAt: now.Add(SessionIdleTimeout),
		MaxExpiresAt:  now.Add(SessionMaxAge),
		LastActiveAt:  now,
		CreatedAt:     now,
		AuthEpoch:     authEpoch,
	}
	if err := s.repo.Create(&sess); err != nil {
		return "", err
	}
	return raw, nil
}

// Validate loads a session by id, enforces the IP binding, expiry windows and
// auth epoch, extends the idle window, and returns the owning operator. An
// invalid session is deleted.
func (s *SessionService) Validate(id, ip string) (*database.Operator, error) {
	if id == "" {
		return nil, ErrSessionInvalid
	}
	id = crypto.HashToken(id)
	sess, err := s.repo.FindByID(id)
	if err != nil {
		return nil, err
	}
	if sess == nil {
		return nil, ErrSessionInvalid
	}
	now := time.Now()
	if sess.IP != ip || now.After(sess.IdleExpiresAt) || now.After(sess.MaxExpiresAt) {
		_ = s.repo.Delete(sess.ID)
		return nil, ErrSessionInvalid
	}
	op, err := s.repo.FindOperator(sess.OperatorID)
	if err != nil || op == nil {
		return nil, ErrSessionInvalid
	}
	// the operator's credentials changed after the login that made this session.
	if sess.AuthEpoch != op.AuthEpoch {
		_ = s.repo.Delete(sess.ID)
		return nil, ErrSessionInvalid
	}
	// Extend the idle window, capped at the hard maximum. Stamp activity hourly
	// to avoid a write on every request.
	newIdle := now.Add(SessionIdleTimeout)
	if newIdle.After(sess.MaxExpiresAt) {
		newIdle = sess.MaxExpiresAt
	}
	updates := map[string]any{"idle_expires_at": newIdle}
	if now.Sub(sess.LastActiveAt) > time.Hour {
		updates["last_active_at"] = now
	}
	if err := s.repo.Touch(sess.ID, updates); err != nil {
		log.Printf("session touch: %v", err)
	}
	return op, nil
}

// Destroy removes a session by id.
func (s *SessionService) Destroy(id string) error {
	if id == "" {
		return nil
	}
	key := crypto.HashToken(id)
	s.stepMu.Lock()
	delete(s.proofFails, key)
	delete(s.stepUps, key)
	s.stepMu.Unlock()
	s.proofs.resetSubject(key)
	return s.repo.Delete(key)
}
