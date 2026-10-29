package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/phishingclub/baitbox/config"
	"github.com/phishingclub/baitbox/crypto"
	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/repository"
)

// ErrNoPasskeys is returned when a passkey login is attempted for an operator
// that has none registered.
var ErrNoPasskeys = errors.New("no passkeys registered")

// ErrPasskeyClone is returned when an assertion's signature counter did not move
// forward, a sign the authenticator was copied. The passkey stays flagged and is
// refused until the operator removes it.
var ErrPasskeyClone = errors.New("passkey flagged as possibly cloned")

// ErrNoChallenge is returned when an assertion names no live challenge: the
// token is missing, unknown, expired or for another ceremony. Nothing was
// checked against an operator.
var ErrNoChallenge = errors.New("challenge expired, start again")

// ErrPasskeyName is returned when a passkey name is too long.
var ErrPasskeyName = errors.New("passkey name must be at most 64 characters")

// MaxPasskeyNameLen is the longest passkey name, in characters.
const MaxPasskeyNameLen = 64

// Challenge purposes, so a token from one ceremony cannot finish another.
const (
	challengeRegister = "register"
	challengeLogin    = "login"
	challengeStepUp   = "stepup"
)

// webAuthnOperator adapts an operator and its credentials to webauthn.User. The
// opaque 32 char operator id is the stable user handle.
type webAuthnOperator struct {
	op    *database.Operator
	creds []webauthn.Credential
}

func (u *webAuthnOperator) WebAuthnID() []byte                         { return []byte(u.op.ID) }
func (u *webAuthnOperator) WebAuthnName() string                       { return u.op.Username }
func (u *webAuthnOperator) WebAuthnDisplayName() string                { return u.op.Username }
func (u *webAuthnOperator) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// challengeEntry is one ceremony's webauthn.SessionData between its begin and
// finish.
type challengeEntry struct {
	data *webauthn.SessionData
	opID string
	// authEpoch is the operator's AuthEpoch when the ceremony began. For a login
	// it is the epoch the password was checked under.
	authEpoch int64
	purpose   string
	expires   time.Time
}

// challengeStore keeps challenge entries keyed by an opaque token carried in a
// cookie. Bait Box is a single instance, so an in memory store with a short TTL
// is enough.
type challengeStore struct {
	mu sync.Mutex
	m  map[string]challengeEntry
}

func newChallengeStore() *challengeStore { return &challengeStore{m: map[string]challengeEntry{}} }

func (s *challengeStore) put(data *webauthn.SessionData, op *database.Operator, purpose string) string {
	token := crypto.Token()
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.m {
		if now.After(v.expires) {
			delete(s.m, k)
		}
	}
	s.m[token] = challengeEntry{
		data: data, opID: op.ID, authEpoch: op.AuthEpoch, purpose: purpose, expires: now.Add(3 * time.Minute),
	}
	return token
}

// sweep drops challenges past their expiry.
func (s *challengeStore) sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.m {
		if now.After(v.expires) {
			delete(s.m, k)
		}
	}
}

// take removes the challenge for token and returns it, or nil when there is no
// live one of that purpose.
func (s *challengeStore) take(token, purpose string) *challengeEntry {
	if token == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[token]
	delete(s.m, token)
	if !ok || time.Now().After(e.expires) || e.purpose != purpose {
		return nil
	}
	return &e
}

// WebAuthnService runs the passkey registration and login ceremonies.
type WebAuthnService struct {
	repo  *repository.WebAuthnRepository
	cfg   *config.Config
	store *challengeStore
	fixed *webauthn.WebAuthn
}

// NewWebAuthnService builds the service. In prod the relying party is fixed to
// the configured admin host; in dev it is derived per request from the browser
// origin (so it works on localhost:8113 or any dev host behind the vite proxy).
func NewWebAuthnService(repo *repository.WebAuthnRepository, cfg *config.Config) (*WebAuthnService, error) {
	s := &WebAuthnService{repo: repo, cfg: cfg, store: newChallengeStore()}
	if cfg.Env != "dev" {
		w, err := webauthn.New(&webauthn.Config{
			RPDisplayName: "Bait Box",
			RPID:          cfg.Administration.TLSHost,
			RPOrigins:     cfg.AdminOrigins(),
		})
		if err != nil {
			return nil, err
		}
		s.fixed = w
	}
	return s, nil
}

func (s *WebAuthnService) instance(origin string) (*webauthn.WebAuthn, error) {
	if s.fixed != nil {
		return s.fixed, nil
	}
	if origin == "" {
		origin = "https://localhost:8113"
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return nil, errors.New("invalid origin")
	}
	return webauthn.New(&webauthn.Config{
		RPDisplayName: "Bait Box",
		RPID:          u.Hostname(),
		RPOrigins:     []string{origin},
	})
}

func toCredential(r *database.OperatorCredential) webauthn.Credential {
	var transports []protocol.AuthenticatorTransport
	if r.Transports != "" {
		_ = json.Unmarshal([]byte(r.Transports), &transports)
	}
	cred := webauthn.Credential{
		ID:              r.CredentialID,
		PublicKey:       r.PublicKey,
		AttestationType: r.AttestationType,
		Transport:       transports,
		Authenticator: webauthn.Authenticator{
			AAGUID:       r.AAGUID,
			SignCount:    r.SignCount,
			CloneWarning: r.CloneWarning,
		},
		Flags: webauthn.CredentialFlags{
			BackupEligible: r.BackupEligible,
			BackupState:    r.BackupState,
		},
	}
	return cred
}

func (s *WebAuthnService) load(opID string) ([]webauthn.Credential, []database.OperatorCredential, error) {
	rows, err := s.repo.ListByOperator(opID)
	if err != nil {
		return nil, nil, err
	}
	creds := make([]webauthn.Credential, 0, len(rows))
	for i := range rows {
		creds = append(creds, toCredential(&rows[i]))
	}
	return creds, rows, nil
}

// List returns an operator's registered passkeys.
func (s *WebAuthnService) List(opID string) ([]database.OperatorCredential, error) {
	_, rows, err := s.load(opID)
	return rows, err
}

// HasPasskeys reports whether an operator has at least one passkey. On an error
// the answer is unknown, and a login must not go on as if there were none.
func (s *WebAuthnService) HasPasskeys(opID string) (bool, error) {
	n, err := s.repo.CountByOperator(opID)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// Delete removes one of an operator's passkeys and drops every other session of
// the operator, keeping the one whose raw cookie value is currentSession. It
// returns ErrNotFound when the operator has no passkey with that id.
func (s *WebAuthnService) Delete(opID, rowID, currentSession string) error {
	n, err := s.repo.DeleteDropSessions(rowID, opID, storedSessionID(currentSession))
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// ValidPasskeyName trims a passkey name, defaults an empty one and rejects one
// longer than MaxPasskeyNameLen characters.
func ValidPasskeyName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "Passkey", nil
	}
	if utf8.RuneCountInString(name) > MaxPasskeyNameLen {
		return "", ErrPasskeyName
	}
	return name, nil
}

// BeginRegistration starts enrolling a new passkey and returns the creation
// options plus a challenge token to carry in a cookie.
func (s *WebAuthnService) BeginRegistration(
	op *database.Operator, origin string,
) (*protocol.CredentialCreation, string, error) {
	w, err := s.instance(origin)
	if err != nil {
		return nil, "", err
	}
	creds, _, err := s.load(op.ID)
	if err != nil {
		return nil, "", err
	}
	user := &webAuthnOperator{op: op, creds: creds}
	// exclude already registered credentials so the same authenticator is not added twice
	exclude := make([]protocol.CredentialDescriptor, 0, len(creds))
	for i := range creds {
		exclude = append(exclude, creds[i].Descriptor())
	}
	options, session, err := w.BeginRegistration(user, webauthn.WithExclusions(exclude))
	if err != nil {
		return nil, "", err
	}
	return options, s.store.put(session, op, challengeRegister), nil
}

// ErrEnrollmentExpired is returned when a passkey registration names no live
// challenge of the operator.
var ErrEnrollmentExpired = errors.New("enrollment expired, start again")

// FinishRegistration verifies the attestation, stores the new credential and
// drops every other session of the operator, keeping the one whose raw cookie
// value is currentSession. The challenge must have been started by the same
// operator.
func (s *WebAuthnService) FinishRegistration(
	op *database.Operator, origin, token, name string, req *http.Request, currentSession string,
) error {
	name, err := ValidPasskeyName(name)
	if err != nil {
		return err
	}
	w, err := s.instance(origin)
	if err != nil {
		return err
	}
	ch := s.store.take(token, challengeRegister)
	if ch == nil || ch.opID != op.ID {
		return ErrEnrollmentExpired
	}
	session := ch.data
	creds, _, err := s.load(op.ID)
	if err != nil {
		return err
	}
	user := &webAuthnOperator{op: op, creds: creds}
	cred, err := w.FinishRegistration(user, *session, req)
	if err != nil {
		return err
	}
	row := &database.OperatorCredential{
		OperatorID:      op.ID,
		Name:            name,
		CredentialID:    cred.ID,
		PublicKey:       cred.PublicKey,
		AttestationType: cred.AttestationType,
		AAGUID:          cred.Authenticator.AAGUID,
		SignCount:       cred.Authenticator.SignCount,
		CloneWarning:    cred.Authenticator.CloneWarning,
		BackupEligible:  cred.Flags.BackupEligible,
		BackupState:     cred.Flags.BackupState,
	}
	if b, e := json.Marshal(cred.Transport); e == nil {
		row.Transports = string(b)
	}
	return s.repo.CreateDropSessions(row, storedSessionID(currentSession))
}

// BeginLogin starts a passkey assertion for a login and returns the request
// options plus a challenge token to carry in a cookie.
func (s *WebAuthnService) BeginLogin(
	op *database.Operator, origin string,
) (*protocol.CredentialAssertion, string, error) {
	return s.beginAssertion(op, origin, challengeLogin)
}

// BeginStepUp starts a passkey assertion that proves a signed in operator is
// present before a second factor change.
func (s *WebAuthnService) BeginStepUp(
	op *database.Operator, origin string,
) (*protocol.CredentialAssertion, string, error) {
	return s.beginAssertion(op, origin, challengeStepUp)
}

func (s *WebAuthnService) beginAssertion(
	op *database.Operator, origin, purpose string,
) (*protocol.CredentialAssertion, string, error) {
	w, err := s.instance(origin)
	if err != nil {
		return nil, "", err
	}
	creds, _, err := s.load(op.ID)
	if err != nil {
		return nil, "", err
	}
	if len(creds) == 0 {
		return nil, "", ErrNoPasskeys
	}
	user := &webAuthnOperator{op: op, creds: creds}
	options, session, err := w.BeginLogin(user)
	if err != nil {
		return nil, "", err
	}
	return options, s.store.put(session, op, purpose), nil
}

// FinishLogin verifies a login passkey assertion, resolving the operator from
// the stored challenge token, and updates the credential's sign count. It
// returns the authenticated operator so the caller can start a session. gate,
// when set, runs with the operator id before the assertion is checked; an error
// from it is returned as is and nothing is checked, which is how the caller
// throttles. On a failed assertion it also returns the id of the operator the
// challenge was for (empty when the challenge was unknown or gate refused).
func (s *WebAuthnService) FinishLogin(
	origin, token string, req *http.Request, gate func(operatorID string) error,
) (*database.Operator, string, error) {
	return s.finishAssertion(origin, token, challengeLogin, req, gate)
}

// FinishStepUp verifies a step up passkey assertion like FinishLogin.
func (s *WebAuthnService) FinishStepUp(origin, token string, req *http.Request) (*database.Operator, string, error) {
	return s.finishAssertion(origin, token, challengeStepUp, req, nil)
}

func (s *WebAuthnService) finishAssertion(
	origin, token, purpose string,
	req *http.Request,
	gate func(operatorID string) error,
) (*database.Operator, string, error) {
	// the challenge is looked up first, so a request naming none is always
	// ErrNoChallenge whatever origin it claims.
	ch := s.store.take(token, purpose)
	if ch == nil {
		return nil, "", ErrNoChallenge
	}
	session := ch.data
	w, err := s.instance(origin)
	if err != nil {
		return nil, "", err
	}
	op, err := s.repo.FindOperator(ch.opID)
	if err != nil {
		return nil, "", err
	}
	if op == nil {
		return nil, "", errors.New("operator not found")
	}
	// the credentials changed since the ceremony began, so the password checked
	// at the begin may no longer be valid. The returned op keeps this epoch, which
	// the session is created with.
	if op.AuthEpoch != ch.authEpoch {
		return nil, "", ErrNoChallenge
	}
	if gate != nil {
		if err := gate(op.ID); err != nil {
			return nil, "", err
		}
	}
	creds, rows, err := s.load(op.ID)
	if err != nil {
		return nil, op.ID, err
	}
	parsed, err := protocol.ParseCredentialRequestResponse(req)
	if err != nil {
		return nil, op.ID, err
	}
	user := &webAuthnOperator{op: op, creds: creds}
	cred, err := w.ValidateLogin(user, *session, parsed)
	if err != nil {
		return nil, op.ID, err
	}
	for i := range rows {
		if bytes.Equal(rows[i].CredentialID, cred.ID) {
			fields := map[string]any{"clone_warning": cred.Authenticator.CloneWarning}
			if !cred.Authenticator.CloneWarning {
				now := time.Now()
				fields["sign_count"] = cred.Authenticator.SignCount
				fields["last_used_at"] = &now
				// the backup state may change over time (a passkey synced later); the
				// eligible flag never changes, the login check refuses that.
				fields["backup_state"] = cred.Flags.BackupState
			}
			_ = s.repo.UpdateCredential(rows[i].ID, fields)
			break
		}
	}
	// a counter that did not move forward means the key may have been copied:
	// refuse the assertion and keep the passkey flagged.
	if cred.Authenticator.CloneWarning {
		return nil, op.ID, ErrPasskeyClone
	}
	return op, "", nil
}

// SweepExpired drops passkey ceremony challenges that were never finished.
func (s *WebAuthnService) SweepExpired() {
	s.store.sweep()
}
