// Package controller holds the Gin HTTP handlers. Handlers validate input,
// check the session and call into the service layer. The admin UI is the
// SvelteKit SPA talking to the JSON API; there are no server rendered pages.
package controller

import (
	"errors"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/middleware"
	"github.com/phishingclub/baitbox/service"
)

// passkeyChallengeCookie carries the short lived WebAuthn login challenge token
// between the begin and finish of a passkey assertion (no session exists yet).
const passkeyChallengeCookie = "bs_pk_chal"

// Auth handles operator login, logout and the session check for the SPA.
type Auth struct {
	operators *service.OperatorService
	sessions  *service.SessionService
	audit     *service.AuditService
	passkeys  *service.WebAuthnService
	guard     *middleware.Auth
}

// AuthDeps is what NewAuth needs.
type AuthDeps struct {
	Operators *service.OperatorService
	Sessions  *service.SessionService
	Audit     *service.AuditService
	Passkeys  *service.WebAuthnService
	Guard     *middleware.Auth
}

// NewAuth returns the Auth controller.
func NewAuth(d AuthDeps) *Auth {
	return &Auth{
		operators: d.Operators,
		sessions:  d.Sessions,
		audit:     d.Audit,
		passkeys:  d.Passkeys,
		guard:     d.Guard,
	}
}

// setSessionCookie sets the operator session cookie: secure, HTTP only, strict.
func setSessionCookie(c *gin.Context, id string) {
	c.SetSameSite(http.SameSiteStrictMode)
	maxAge := int(service.SessionMaxAge.Seconds())
	c.SetCookie(middleware.SessionCookieName, id, maxAge, "/", "", true, true)
}

// requestOrigin returns the browser origin for the WebAuthn ceremony. In prod
// the relying party is fixed, so this is only used (and trusted) in dev.
func requestOrigin(c *gin.Context) string {
	return c.GetHeader("Origin")
}

// startSession completes the login (clearing the throttle counts of this
// client), ends the session of any cookie the client still sent, creates a
// session, sets the cookie, audits the login and replies. op is the row the
// login checked, so the session gets the auth epoch of those credentials.
func (a *Auth) startSession(c *gin.Context, op *database.Operator) {
	if old, err := c.Cookie(middleware.SessionCookieName); err == nil && old != "" {
		if err := a.sessions.Destroy(old); err != nil {
			a.loginFault(c, err)
			return
		}
	}
	a.operators.CompleteLogin(op, c.ClientIP())
	id, err := a.sessions.Create(op.ID, op.AuthEpoch, c.ClientIP())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not start a session"})
		return
	}
	setSessionCookie(c, id)
	a.audit.Record("Operator.Login", op.ID, op.Username, c.ClientIP(), true, nil)
	c.JSON(http.StatusOK, gin.H{"username": op.Username, "passwordChangeRequired": a.guard.PasswordChangeRequired(op)})
}

// loginThrottled audits and answers a login attempt refused by the throttle,
// reporting whether err was such a refusal.
func (a *Auth) loginThrottled(c *gin.Context, operatorID, username string, err error) bool {
	if !errors.Is(err, service.ErrThrottled) {
		return false
	}
	a.audit.Record("Operator.LoginFailed", operatorID, username, c.ClientIP(), false,
		map[string]any{"reason": "throttled"})
	return replyThrottled(c, err)
}

// loginFault answers a login that could not be checked because of a server
// fault. No session is started; the reason stays in the server log.
func (a *Auth) loginFault(c *gin.Context, err error) {
	log.Printf("login: %v", err)
	c.JSON(http.StatusInternalServerError, gin.H{"error": "could not sign in, try again"})
}

// refuseLongUsername answers a login naming a username longer than any stored
// one with the usual failed login reply, and reports whether it did. It runs
// before the throttle, the audit log and any logging, so the oversized value is
// never kept.
func refuseLongUsername(c *gin.Context, username string) bool {
	if !service.UsernameTooLong(username) {
		return false
	}
	c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
	return true
}

// LoginJSON authenticates from a JSON body and starts a session. It is a
// stateless two step: a correct password for an operator with a second factor
// returns mfaRequired (no session) until a TOTP code or a passkey is provided.
// Attempts inside a throttle wait get 429 with Retry-After and are not checked.
func (a *Auth) LoginJSON(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if refuseLongUsername(c, req.Username) {
		return
	}
	op, err := a.operators.Authenticate(req.Username, req.Password, req.Code, c.ClientIP())
	if a.loginThrottled(c, "", req.Username, err) {
		return
	}
	var mfa *service.MFARequiredError
	if errors.As(err, &mfa) {
		// password correct, TOTP needed; also say whether a passkey is an option
		hasPk, perr := a.passkeys.HasPasskeys(mfa.OperatorID)
		if perr != nil {
			a.loginFault(c, perr)
			return
		}
		stage := "awaiting_code"
		if req.Code != "" {
			stage = "wrong_code"
		}
		a.audit.Record("Operator.LoginMFA", mfa.OperatorID, req.Username, c.ClientIP(), false,
			map[string]any{"stage": stage})
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "enter your authenticator code", "mfaRequired": true,
			"passkeyAvailable": hasPk, "totpAvailable": true,
		})
		return
	}
	if err != nil {
		a.audit.Record("Operator.LoginFailed", "", req.Username, c.ClientIP(), false, nil)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
		return
	}
	// password correct and TOTP satisfied (or not enabled). If the operator has a
	// passkey but no TOTP, the second factor must be the passkey.
	hasPk := false
	if !op.MFAEnabled {
		if hasPk, err = a.passkeys.HasPasskeys(op.ID); err != nil {
			// without knowing whether a passkey is owed the login must not go on.
			a.loginFault(c, err)
			return
		}
	}
	if hasPk {
		a.audit.Record("Operator.LoginMFA", op.ID, req.Username, c.ClientIP(), false,
			map[string]any{"stage": "awaiting_passkey"})
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "use your passkey to finish signing in", "mfaRequired": true,
			"passkeyAvailable": true, "totpAvailable": false,
		})
		return
	}
	a.startSession(c, op)
}

// PasskeyLoginBegin verifies the password then returns a WebAuthn assertion
// challenge, stashing the challenge token in a short lived cookie. While the
// second factor of this client is inside a wait it answers 429 instead of
// starting a ceremony that would be refused.
func (a *Auth) PasskeyLoginBegin(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if refuseLongUsername(c, req.Username) {
		return
	}
	op, err := a.operators.AuthenticatePassword(req.Username, req.Password, c.ClientIP())
	if a.loginThrottled(c, "", req.Username, err) {
		return
	}
	if err != nil {
		a.audit.Record("Operator.LoginFailed", "", req.Username, c.ClientIP(), false, nil)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
		return
	}
	if a.loginThrottled(c, op.ID, op.Username, a.operators.SecondFactorWait(op.ID, c.ClientIP())) {
		return
	}
	options, token, err := a.passkeys.BeginLogin(op, requestOrigin(c))
	if errors.Is(err, service.ErrNoPasskeys) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no passkeys registered for this account"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not start passkey login"})
		return
	}
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(passkeyChallengeCookie, token, 180, "/", "", true, true)
	c.JSON(http.StatusOK, options)
}

// PasskeyLoginFinish verifies the assertion and, on success, starts a session.
// The assertion is throttled per operator and client like a TOTP code: inside a
// wait it is not checked and 429 is sent, and a failed one makes the next wait
// longer. A passkey flagged as possibly cloned is refused.
func (a *Auth) PasskeyLoginFinish(c *gin.Context) {
	token, _ := c.Cookie(passkeyChallengeCookie)
	ip := c.ClientIP()
	var gatedOpID string
	gate := func(operatorID string) error {
		gatedOpID = operatorID
		return a.operators.BeginSecondFactor(operatorID, ip)
	}
	op, failedOpID, err := a.passkeys.FinishLogin(requestOrigin(c), token, c.Request, gate)
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(passkeyChallengeCookie, "", -1, "/", "", true, true)
	if a.loginThrottled(c, gatedOpID, "", err) {
		return
	}
	// with no live challenge nothing was checked against an operator, so there is
	// no attempt to audit.
	if errors.Is(err, service.ErrNoChallenge) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "passkey verification failed"})
		return
	}
	if err != nil {
		details := map[string]any{}
		if errors.Is(err, service.ErrPasskeyClone) {
			details["reason"] = "clone warning"
		}
		a.audit.Record("Operator.LoginPasskeyFailed", failedOpID, "", c.ClientIP(), false, details)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "passkey verification failed"})
		return
	}
	if gatedOpID == op.ID {
		a.operators.SecondFactorPassed(op.ID, ip)
	}
	a.startSession(c, op)
}

// LogoutJSON destroys the session and clears the cookie. Only the logout of a
// valid session is audited, so requests with junk cookies write no audit line.
func (a *Auth) LogoutJSON(c *gin.Context) {
	if cookie, err := c.Cookie(middleware.SessionCookieName); err == nil && cookie != "" {
		// resolve the operator before dropping the session so the logout event is
		// attributable to the account that signed out.
		op, verr := a.sessions.Validate(cookie, c.ClientIP())
		_ = a.sessions.Destroy(cookie)
		if verr == nil && op != nil {
			a.audit.Record("Operator.Logout", op.ID, op.Username, c.ClientIP(), true, nil)
		}
	}
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(middleware.SessionCookieName, "", -1, "/", "", true, true)
	c.JSON(http.StatusOK, gin.H{"status": "logged out"})
}

// Me returns the current operator, for the SPA to check the session.
func (a *Auth) Me(c *gin.Context) {
	op := middleware.OperatorFromContext(c)
	c.JSON(http.StatusOK, gin.H{"username": op.Username, "passwordChangeRequired": a.guard.PasswordChangeRequired(op)})
}
