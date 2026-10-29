package controller

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/phishingclub/baitbox/middleware"
	"github.com/phishingclub/baitbox/service"
)

// replyThrottled answers 429 with a Retry-After header when err is a throttle
// refusal and reports whether it did. The attempt was never checked, so the
// reply is the same whatever the credential was.
func replyThrottled(c *gin.Context, err error) bool {
	var te *service.ThrottledError
	if !errors.As(err, &te) {
		return false
	}
	secs := te.Seconds()
	c.Header("Retry-After", strconv.Itoa(secs))
	c.JSON(http.StatusTooManyRequests, gin.H{"error": te.Error(), "retryAfter": secs})
	return true
}

// auditFunc records an audit event for the request.
type auditFunc func(c *gin.Context, action string, success bool, details map[string]any)

// sessionBeginProof starts checking a proof of identity (TOTP code, passkey
// assertion or password) made from the request's session. Inside the session's
// wait it audits the refusal, answers 429 and reports false; the proof must then
// not be checked. Only this session is slowed down, never the operator's login.
func sessionBeginProof(c *gin.Context, sessions *service.SessionService, action string, audit auditFunc) bool {
	err := sessions.BeginProof(sessionCookie(c))
	if err == nil {
		return true
	}
	audit(c, action, false, map[string]any{"reason": "throttled"})
	if !replyThrottled(c, err) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not check the proof"})
	}
	return false
}

// sessionProofFailed counts a wrong proof of identity against the request's
// session. These failures never touch the operator's login throttle, so a stolen
// session cannot slow the real operator down. Once the session reaches
// service.SessionSecondFactorLimit wrong proofs in a row it is revoked: that only
// ends the session that made the guesses, and the operator can sign in again.
// The event is audited, the cookie is cleared, 401 is sent and it reports true
// so the caller stops.
func sessionProofFailed(c *gin.Context, sessions *service.SessionService, audit auditFunc) bool {
	revoked, err := sessions.ProofFailed(sessionCookie(c))
	if !revoked {
		return false
	}
	details := map[string]any{"reason": "too many wrong proofs of identity", "limit": service.SessionSecondFactorLimit}
	if err != nil {
		details["error"] = "session could not be deleted"
	}
	audit(c, "Operator.SessionRevoked", err == nil, details)
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(middleware.SessionCookieName, "", -1, "/", "", true, true)
	c.JSON(http.StatusUnauthorized, gin.H{"error": "signed out after too many failed attempts", "signedOut": true})
	return true
}
