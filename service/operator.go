// Package service holds business logic over the repository and database layers:
// operator auth, sessions, packaging and integrity. Controllers call
// into here and never touch the database directly.
package service

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/phishingclub/baitbox/crypto"
	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/repository"
)

// passwordThrottle slows down wrong passwords at login, per username and client
// address. Three free failures cover typos; then the wait doubles from 1 second
// up to 30 seconds, so one address gets about 2 guesses a minute while the real
// user, even under attack, waits at most 30 seconds before a correct password is
// checked. Past 20 failures across all addresses within the idle window, every
// address that already failed must wait the same backoff after its own last
// failure. An address that never failed is checked at once, so spreading
// guesses over many addresses still costs the attacker one address per guess.
// Usernames are tracked whether or not they exist, so the throttle shows nothing
// about which do.
var passwordThrottle = throttlePolicy{
	free: 3, globalFree: 20, base: time.Second, max: 30 * time.Second, idle: 15 * time.Minute,
}

// secondFactorThrottle slows down wrong TOTP codes and passkey assertions at
// login, per operator and client address. A 6 digit code has a small space, so
// the wait grows longer and the total kicks in sooner than for passwords. Past
// 10 failures every address, new ones included, waits the backoff of the total
// after the last failure of the operator, so fresh addresses give no extra
// guesses: about one guess a minute in all. Only a caller that already gave the
// right password reaches it, and the real user is checked once the wait passes.
var secondFactorThrottle = throttlePolicy{
	free: 3, globalFree: 10, base: time.Second, max: 60 * time.Second, idle: 15 * time.Minute,
	holdNewClients: true,
}

// BusyWait is how long a client is asked to wait when every password hash slot
// is taken.
const BusyWait = time.Second

// hashBusy turns crypto.ErrBusy into a ThrottledError, so the client gets 429
// with Retry-After. Other errors pass through.
func hashBusy(err error) error {
	if errors.Is(err, crypto.ErrBusy) {
		return &ThrottledError{RetryAfter: BusyWait}
	}
	return err
}

// ErrNewPasswordBusy is returned by ChangePassword when the current password was
// right but every hash slot was taken while hashing the new one. It does not
// match ErrThrottled, so it is never mistaken for a proof that was not checked.
var ErrNewPasswordBusy = errors.New("too many password checks running, try again")

// hashNewPassword hashes a new password; tests swap it to force a busy hash.
var hashNewPassword = crypto.HashPassword

// pendingMFATTL is how long a TOTP secret handed out by BeginMFAEnroll stays
// valid for ConfirmMFAEnroll.
const pendingMFATTL = 10 * time.Minute

// ErrStepUpRequired is returned when an action needs a fresh proof of the
// operator's identity that was not given.
var ErrStepUpRequired = errors.New("confirm it is you first")

// ErrStepUpPasskey is returned when the operator's step up must be a passkey
// assertion, which runs through its own begin and finish calls.
var ErrStepUpPasskey = errors.New("confirm with your passkey")

// ErrNoPendingMFA is returned by ConfirmMFAEnroll when no enrollment was started
// or it has run out.
var ErrNoPendingMFA = errors.New("enrollment expired, start again")

// ErrMFANotEnabled is returned by DisableMFA when two factor is already off, so
// no code was checked.
var ErrMFANotEnabled = errors.New("two factor is not on")

// ErrInvalidCredentials is returned when a login does not match.
var ErrInvalidCredentials = errors.New("invalid credentials")

// ErrPasswordUnchanged is returned when a new password equals the current one.
var ErrPasswordUnchanged = errors.New("new password must differ from the current one")

// ErrInvalidUsername is returned when a chosen username breaks the rules.
var ErrInvalidUsername = errors.New("invalid username")

// ErrLastOperator is returned when deleting the only remaining operator.
var ErrLastOperator = errors.New("cannot delete the last operator")

// ErrUsernameTaken is returned when a chosen username belongs to another operator.
var ErrUsernameTaken = errors.New("an operator with that username already exists")

// defaultOperatorUsername is the seeded admin account name. Every install starts
// with it, so the first login must replace it and no operator may rename to it.
const defaultOperatorUsername = "admin"

// HasDefaultUsername reports whether the operator still uses the seeded name.
func HasDefaultUsername(op *database.Operator) bool {
	return op != nil && strings.EqualFold(op.Username, defaultOperatorUsername)
}

// OperatorService manages the server admin accounts for the html admin UI.
type OperatorService struct {
	repo *repository.OperatorRepository
	// passwords throttles wrong login passwords per lowercased username and client.
	passwords *throttle
	// secondFactors throttles wrong login second factor proofs per operator id and
	// client.
	secondFactors *throttle
	// pending holds the TOTP secret of an enrollment in progress per operator id,
	// so ConfirmMFAEnroll never trusts a secret sent by the client.
	pendingMu sync.Mutex
	pending   map[string]pendingMFA
}

// pendingMFA is one TOTP secret waiting for its confirming code.
type pendingMFA struct {
	secret  string
	expires time.Time
}

// NewOperatorService returns an OperatorService.
func NewOperatorService(repo *repository.OperatorRepository) *OperatorService {
	return &OperatorService{
		repo:          repo,
		passwords:     newThrottle(passwordThrottle),
		secondFactors: newThrottle(secondFactorThrottle),
		pending:       map[string]pendingMFA{},
	}
}

// EnsureOperator seeds the single admin account on first run. It returns the
// generated password and created=true on a fresh seed, or created=false when an
// operator already exists. The caller logs and persists the credentials.
func (s *OperatorService) EnsureOperator() (username, password string, created bool, err error) {
	count, err := s.repo.Count()
	if err != nil {
		return "", "", false, err
	}
	if count > 0 {
		return "", "", false, nil
	}
	password = crypto.String(20)
	hash, err := crypto.HashPassword(password)
	if err != nil {
		return "", "", false, err
	}
	op := database.Operator{Username: defaultOperatorUsername, PasswordHash: hash, MustChangePassword: true}
	if err := s.repo.Create(&op); err != nil {
		return "", "", false, err
	}
	return defaultOperatorUsername, password, true, nil
}

// ResetOperatorAudited resets an operator password to a fresh value and drops
// its sessions. With an empty username it resets the first operator created,
// which is the seeded admin even after a rename. It returns the operator's
// current username and the new password; the caller logs and persists them. It
// records Operator.ResetPassword with source cli, on success and on failure.
// The password is never part of the record.
func (s *OperatorService) ResetOperatorAudited(audit *AuditService, username string) (string, string, error) {
	id, u, p, reseeded, err := s.resetOperator(username)
	if err != nil {
		reason := "reset failed"
		if errors.Is(err, ErrNotFound) {
			reason = "operator not found"
		}
		audit.Record("Operator.ResetPassword", "", username, "local", false,
			map[string]any{"source": "cli", "reason": reason})
		return "", "", err
	}
	details := map[string]any{"source": "cli"}
	if reseeded {
		details["reseeded"] = true
	}
	audit.Record("Operator.ResetPassword", id, u, "local", true, details)
	return u, p, nil
}

// resetOperator does the reset and also returns the operator id and whether no
// operator existed, so the seeded one was created again.
func (s *OperatorService) resetOperator(username string) (id, name, password string, reseeded bool, err error) {
	var op *database.Operator
	if username != "" {
		op, err = s.repo.FindByUsername(username)
		if err == nil && op == nil {
			return "", "", "", false, fmt.Errorf("no operator named %q: %w", username, ErrNotFound)
		}
	} else {
		op, err = s.repo.FindOldest()
	}
	if err != nil {
		return "", "", "", false, err
	}
	if op == nil {
		u, p, _, cerr := s.EnsureOperator()
		if cerr != nil {
			return "", "", "", false, cerr
		}
		seeded, ferr := s.repo.FindByUsername(u)
		if ferr != nil || seeded == nil {
			return "", u, p, true, nil
		}
		return seeded.ID, u, p, true, nil
	}
	password = crypto.String(20)
	hash, err := crypto.HashPassword(password)
	if err != nil {
		return "", "", "", false, err
	}
	fields := map[string]any{"password_hash": hash, "must_change_password": true}
	if _, err := s.repo.UpdateFieldsDropSessions(op.ID, fields, ""); err != nil {
		return "", "", "", false, err
	}
	return op.ID, op.Username, password, false, nil
}

// ListOperators returns all operator accounts, ordered by username.
func (s *OperatorService) ListOperators() ([]database.Operator, error) {
	return s.repo.List()
}

// ValidateNewOperator runs before the controller asks for a step up, so a typo
// does not spend the grant. A refusal is a ValidationError; any other error is
// an internal fault.
func (s *OperatorService) ValidateNewOperator(username, password string) error {
	username = strings.TrimSpace(username)
	if len(username) < 3 || len(username) > 64 {
		return invalidf("username must be 3 to 64 characters")
	}
	if strings.EqualFold(username, defaultOperatorUsername) {
		return invalidf("the username %q is reserved", defaultOperatorUsername)
	}
	if len(password) < 12 {
		return invalidf("password must be at least 12 characters")
	}
	count, err := s.repo.CountByUsername(username)
	if err != nil {
		return err
	}
	if count > 0 {
		return invalid(ErrUsernameTaken)
	}
	return nil
}

// CreateOperator adds a new operator account with a hashed password after
// ValidateNewOperator passes. The new operator must change the password at first
// login, since another operator set it.
func (s *OperatorService) CreateOperator(username, password string) (*database.Operator, error) {
	username = strings.TrimSpace(username)
	if err := s.ValidateNewOperator(username, password); err != nil {
		return nil, err
	}
	hash, err := crypto.HashPassword(password)
	if err != nil {
		return nil, hashBusy(err)
	}
	op := database.Operator{Username: username, PasswordHash: hash, MustChangePassword: true}
	if err := s.repo.Create(&op); err != nil {
		// another create may have taken the name since the check.
		if repository.IsUniqueViolation(err) {
			return nil, invalid(ErrUsernameTaken)
		}
		return nil, err
	}
	return &op, nil
}

// DeleteOperator removes an operator account, revokes its tokens and deletes its
// passkeys and sessions in one transaction, so a removed operator never leaves a
// usable token or session behind. An unknown id gives ErrNotFound. The last
// remaining operator cannot be deleted (ErrLastOperator), so the instance always
// keeps a way in.
func (s *OperatorService) DeleteOperator(id string) error {
	deleted, found, err := s.repo.DeleteOperatorCascade(id)
	if err != nil {
		return err
	}
	if !found {
		return ErrNotFound
	}
	if !deleted {
		return ErrLastOperator
	}
	s.dropPendingMFA(id)
	s.secondFactors.resetSubject(id)
	return nil
}

// ResetSecondFactors clears every second factor of the named operator for
// account recovery: TOTP is turned off and its secret and any enrollment in
// progress in this process are dropped, every passkey is deleted, the second
// factor throttle kept by this process is cleared and every session is dropped.
// The password is left as it is. It returns the operator and how many passkeys
// were deleted.
func (s *OperatorService) ResetSecondFactors(username string) (*database.Operator, int64, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, 0, errors.New("a username is required")
	}
	op, err := s.repo.FindByUsername(username)
	if err != nil {
		return nil, 0, err
	}
	if op == nil {
		return nil, 0, fmt.Errorf("no operator named %q", username)
	}
	passkeys, err := s.repo.ResetSecondFactors(op.ID)
	if err != nil {
		return nil, 0, err
	}
	s.dropPendingMFA(op.ID)
	s.secondFactors.resetSubject(op.ID)
	return op, passkeys, nil
}

// ErrMFARequired is returned by Authenticate when the password is correct but a
// valid TOTP code was not supplied for an operator with MFA on.
var ErrMFARequired = errors.New("mfa required")

// GetOperator returns an operator by id.
func (s *OperatorService) GetOperator(id string) (*database.Operator, error) {
	op, err := s.repo.FindByID(id)
	if err != nil {
		return nil, err
	}
	if op == nil {
		return nil, ErrNotFound
	}
	return op, nil
}

// BeginMFAEnroll returns a fresh TOTP secret and its otpauth URI. The secret is
// kept server side, bound to the operator, until ConfirmMFAEnroll verifies the
// operator can produce a code for it. Starting again replaces it. The caller
// checks a fresh step up first.
func (s *OperatorService) BeginMFAEnroll(operatorID string) (secret, uri string, err error) {
	op, err := s.GetOperator(operatorID)
	if err != nil {
		return "", "", err
	}
	secret = crypto.NewTOTPSecret()
	uri = crypto.TOTPURI("Bait Box", op.Username, secret)
	now := time.Now()
	s.pendingMu.Lock()
	for k, v := range s.pending {
		if now.After(v.expires) {
			delete(s.pending, k)
		}
	}
	s.pending[op.ID] = pendingMFA{secret: secret, expires: now.Add(pendingMFATTL)}
	s.pendingMu.Unlock()
	return secret, uri, nil
}

// SweepExpired drops TOTP enrollments that were started but never confirmed.
func (s *OperatorService) SweepExpired() {
	now := time.Now()
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	for k, v := range s.pending {
		if now.After(v.expires) {
			delete(s.pending, k)
		}
	}
}

// pendingMFASecret returns the secret of the operator's enrollment in progress.
func (s *OperatorService) pendingMFASecret(operatorID string) (string, bool) {
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	p, ok := s.pending[operatorID]
	if !ok {
		return "", false
	}
	if time.Now().After(p.expires) {
		delete(s.pending, operatorID)
		return "", false
	}
	return p.secret, true
}

// dropPendingMFA forgets the operator's enrollment in progress.
func (s *OperatorService) dropPendingMFA(operatorID string) {
	s.pendingMu.Lock()
	delete(s.pending, operatorID)
	s.pendingMu.Unlock()
}

// ConfirmMFAEnroll stores the pending secret and enables MFA once the operator
// proves a valid code for it. It drops every session of the operator and
// returns the new auth epoch; the caller starts a fresh session with it for the
// request that enabled it.
func (s *OperatorService) ConfirmMFAEnroll(operatorID, code string) (int64, error) {
	secret, ok := s.pendingMFASecret(operatorID)
	if !ok {
		return 0, ErrNoPendingMFA
	}
	counter, ok := crypto.VerifyTOTPAt(secret, code)
	if !ok {
		return 0, ErrInvalidCredentials
	}
	op, err := s.GetOperator(operatorID)
	if err != nil {
		return 0, err
	}
	// record the counter so the confirming code cannot be replayed at first login.
	fields := map[string]any{"mfa_secret": secret, "mfa_enabled": true, "mfa_last_counter": counter}
	epoch, err := s.repo.UpdateFieldsDropSessions(op.ID, fields, "")
	if err != nil {
		return 0, err
	}
	s.dropPendingMFA(op.ID)
	return epoch, nil
}

// DisableMFA turns off MFA after verifying a current code, clears the secret and
// drops every other session of the operator, keeping the one whose raw cookie
// value is currentSession. It runs from a signed in session, so a wrong code
// never touches the login throttle; the caller throttles it per session. When
// MFA is already off it returns ErrMFANotEnabled and changes nothing.
func (s *OperatorService) DisableMFA(operatorID, code, currentSession string) error {
	op, err := s.GetOperator(operatorID)
	if err != nil {
		return err
	}
	if !op.MFAEnabled {
		return ErrMFANotEnabled
	}
	if err := s.verifyTOTP(op, code); err != nil {
		return err
	}
	_, err = s.repo.UpdateFieldsDropSessions(op.ID,
		map[string]any{"mfa_secret": "", "mfa_enabled": false}, storedSessionID(currentSession))
	return err
}

// verifyTOTP checks a code against the operator's TOTP secret and claims its
// time step so the code cannot be used again. Throttling is up to the caller.
func (s *OperatorService) verifyTOTP(op *database.Operator, code string) error {
	counter, ok := crypto.VerifyTOTPAt(op.MFASecret, code)
	// reject a code whose time step was already used, so an intercepted code cannot
	// be replayed within its window.
	if !ok || counter <= op.MFALastCounter {
		return ErrInvalidCredentials
	}
	// claim the counter atomically: the row advances only if no concurrent request
	// already consumed this step, so one captured code cannot be used twice at once.
	affected, err := s.repo.ClaimMFACounter(op.ID, counter)
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrInvalidCredentials
	}
	return nil
}

// SecondFactorWait reports how long a login second factor from the client must
// wait before it is checked, without counting anything. The passkey login uses
// it before starting a ceremony that would only be refused.
func (s *OperatorService) SecondFactorWait(operatorID, ip string) error {
	if w := s.secondFactors.wait(operatorID, ip); w > 0 {
		return &ThrottledError{RetryAfter: w}
	}
	return nil
}

// BeginSecondFactor starts a login second factor check (a passkey assertion)
// for the operator from the client. Inside a wait it returns a ThrottledError and
// the proof must not be checked. Otherwise the attempt counts as a failure until
// the login completes.
func (s *OperatorService) BeginSecondFactor(operatorID, ip string) error {
	return s.secondFactors.begin(operatorID, ip)
}

// SecondFactorPassed undoes the count BeginSecondFactor made once the proof was
// right, the same as a correct TOTP code, so good passkey logins never add up
// to a wait.
func (s *OperatorService) SecondFactorPassed(operatorID, ip string) {
	s.secondFactors.passed(operatorID, ip)
}

// StepUpMethods reports which proofs an operator can give before changing a
// second factor: a TOTP code when MFA is on, a passkey assertion when a passkey
// is registered, and the current password only when no second factor exists.
func (s *OperatorService) StepUpMethods(operatorID string) (totp, passkey, password bool, err error) {
	op, err := s.GetOperator(operatorID)
	if err != nil {
		return false, false, false, err
	}
	n, err := s.repo.CountCredentialsByOperator(op.ID)
	if err != nil {
		return false, false, false, err
	}
	totp = op.MFAEnabled
	passkey = n > 0
	return totp, passkey, !totp && !passkey, nil
}

// StepUp checks a fresh proof of identity with a code or a password. With MFA
// on it takes a current TOTP code. With only passkeys it returns
// ErrStepUpPasskey, as that proof runs through the passkey ceremony. With no
// second factor it takes the current password. It runs from a signed in session,
// so it never touches the login throttle; the caller throttles it per session.
func (s *OperatorService) StepUp(operatorID, code, password string) error {
	totp, passkey, _, err := s.StepUpMethods(operatorID)
	if err != nil {
		return err
	}
	if totp {
		if strings.TrimSpace(code) == "" {
			return ErrStepUpRequired
		}
		op, err := s.GetOperator(operatorID)
		if err != nil {
			return err
		}
		return s.verifyTOTP(op, code)
	}
	if passkey {
		return ErrStepUpPasskey
	}
	if password == "" {
		return ErrStepUpRequired
	}
	return s.VerifyPassword(operatorID, password)
}

// MFARequiredError reports a correct password for an operator that still owes a
// second factor. errors.Is(err, ErrMFARequired) matches it. OperatorID lets the
// caller say which second factors exist; it never starts a session.
type MFARequiredError struct {
	OperatorID string
}

func (e *MFARequiredError) Error() string { return ErrMFARequired.Error() }

// Is makes errors.Is(err, ErrMFARequired) true for an MFARequiredError.
func (e *MFARequiredError) Is(target error) bool { return target == ErrMFARequired }

// Authenticate verifies a username and password from the client and returns the
// operator. When the operator has MFA enabled, a valid TOTP code must also be
// supplied or an MFARequiredError is returned (so the caller can prompt for the
// second factor). Wrong passwords and wrong codes are throttled per client; an
// attempt inside its wait returns a ThrottledError without being checked. The
// caller calls CompleteLogin once every required factor has passed.
func (s *OperatorService) Authenticate(username, password, code, ip string) (*database.Operator, error) {
	op, err := s.authPassword(username, password, ip)
	if err != nil {
		return nil, err
	}
	if !op.MFAEnabled {
		return op, nil
	}
	if code == "" {
		return nil, &MFARequiredError{OperatorID: op.ID}
	}
	if err := s.secondFactors.begin(op.ID, ip); err != nil {
		return nil, err
	}
	if err := s.verifyTOTP(op, code); err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			return nil, &MFARequiredError{OperatorID: op.ID}
		}
		return nil, err
	}
	s.secondFactors.passed(op.ID, ip)
	return op, nil
}

// AuthenticatePassword verifies only the username and password (no second
// factor), used by the passkey login ceremony which carries the second factor
// in the assertion instead of a code. It is throttled like Authenticate.
func (s *OperatorService) AuthenticatePassword(username, password, ip string) (*database.Operator, error) {
	return s.authPassword(username, password, ip)
}

// CompleteLogin is called once a login from the client has passed the password
// and every required second factor. It clears the password and second factor
// counts of that client. Other clients and the totals keep counting, so the
// real user signing in hands an attacker elsewhere no fresh attempts. A correct
// password alone never clears anything.
func (s *OperatorService) CompleteLogin(op *database.Operator, ip string) {
	s.passwords.resetClient(op.Username, ip)
	s.secondFactors.resetClient(op.ID, ip)
}

// MaxUsernameBytes is the size of the username column. A login naming a longer
// username cannot match an operator.
const MaxUsernameBytes = 128

// UsernameTooLong reports whether a login username is over MaxUsernameBytes.
func UsernameTooLong(username string) bool { return len(username) > MaxUsernameBytes }

// dummyHash is verified for an unknown username, so a miss takes as long as a
// wrong password.
const dummyHash = "argon2id$v=19$m=65536,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$" +
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// authPassword verifies only the username and password from the client. It is
// the single chokepoint both the password and passkey login paths pass through.
// The throttle is keyed by the username as typed (lowercased), whether or not
// it exists, and every path reads the account, takes a slot and checks the
// throttle in the same order, so a reply shows nothing about the account.
func (s *OperatorService) authPassword(username, password, ip string) (*database.Operator, error) {
	// no stored username is this long, so refuse it before it becomes a throttle key.
	if UsernameTooLong(username) {
		return nil, ErrInvalidCredentials
	}
	// the account is read before a hash slot is taken, so a login waiting on the
	// database holds no slot.
	op, err := s.repo.FindByUsername(username)
	if err != nil {
		return nil, err
	}
	// the hash slot is taken before the throttle, so a busy refusal neither
	// counts nor creates a throttle entry.
	release, ok := crypto.TakeHashSlot()
	if !ok {
		return nil, hashBusy(crypto.ErrBusy)
	}
	defer release()
	if err := s.passwords.begin(username, ip); err != nil {
		return nil, err
	}
	hash := dummyHash
	if op != nil {
		hash = op.PasswordHash
	}
	ok, err = crypto.VerifyPasswordInSlot(password, hash)
	if op == nil {
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrInvalidCredentials
	}
	s.passwords.passed(username, ip)
	return op, nil
}

// VerifyPassword checks the password of a signed in operator before a
// sensitive action. It never touches the login throttle, so wrong guesses from
// a session cannot slow the real operator's login; the caller throttles it per
// session.
func (s *OperatorService) VerifyPassword(operatorID, password string) error {
	op, err := s.GetOperator(operatorID)
	if err != nil {
		return err
	}
	ok, err := crypto.VerifyPassword(password, op.PasswordHash)
	if err != nil {
		return hashBusy(err)
	}
	if !ok {
		return ErrInvalidCredentials
	}
	return nil
}

// ChangePassword sets a new password for the operator after verifying the
// current one with VerifyPassword, clears the must change flag and
// drops every session of that operator. A non empty newUsername renames the
// operator in the same update. It returns the new auth epoch; the caller starts a
// fresh session with it for the request that changed it.
func (s *OperatorService) ChangePassword(operatorID, current, next, newUsername string) (int64, error) {
	op, err := s.repo.FindByID(operatorID)
	if err != nil {
		return 0, err
	}
	if op == nil {
		return 0, ErrNotFound
	}
	if err := s.VerifyPassword(op.ID, current); err != nil {
		return 0, err
	}
	if current == next {
		return 0, ErrPasswordUnchanged
	}
	fields := map[string]any{"must_change_password": false}
	newUsername = strings.TrimSpace(newUsername)
	if newUsername != "" && newUsername != op.Username {
		if len(newUsername) < 3 || len(newUsername) > 64 || strings.EqualFold(newUsername, defaultOperatorUsername) {
			return 0, ErrInvalidUsername
		}
		// usernames ignore case, so changing only the case of your own name is fine
		if !strings.EqualFold(newUsername, op.Username) {
			taken, err := s.repo.CountByUsername(newUsername)
			if err != nil {
				return 0, err
			}
			if taken > 0 {
				return 0, ErrUsernameTaken
			}
		}
		fields["username"] = newUsername
	}
	hash, err := hashNewPassword(next)
	if errors.Is(err, crypto.ErrBusy) {
		return 0, ErrNewPasswordBusy
	}
	if err != nil {
		return 0, err
	}
	fields["password_hash"] = hash
	return s.repo.UpdateFieldsDropSessions(op.ID, fields, "")
}
