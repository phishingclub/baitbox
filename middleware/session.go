package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/service"
)

// SessionCookieName is the operator session cookie.
const SessionCookieName = "baitbox_session"

// contextOperatorKey is where the authenticated operator is stored on the Gin
// context.
const contextOperatorKey = "operator"

// Auth guards routes using the operator session cookie.
type Auth struct {
	sessions *service.SessionService
	// forcePasswordChange blocks an operator whose password was issued rather
	// than chosen from everything except the routes in passwordChangeAllowed.
	forcePasswordChange bool
}

// passwordChangeAllowed are the guarded routes an operator who must change the
// password can still reach: the session check and the change itself.
var passwordChangeAllowed = map[string]bool{
	"/api/v1/me":                    true,
	"/api/v1/admin/change-password": true,
}

// NewAuth constructs an Auth guard. With forcePasswordChange set, an operator
// flagged MustChangePassword is held to the change password routes.
func NewAuth(sessions *service.SessionService, forcePasswordChange bool) *Auth {
	return &Auth{sessions: sessions, forcePasswordChange: forcePasswordChange}
}

// PasswordChangeRequired reports whether the operator must set a new password
// before using anything else.
func (a *Auth) PasswordChangeRequired(op *database.Operator) bool {
	return a.forcePasswordChange && op != nil && op.MustChangePassword
}

// blockedByPasswordChange aborts with 403 when the operator must change the
// password and the matched route is not one of the allowed ones. It matches on
// the route pattern, so path tricks cannot reach another handler.
func (a *Auth) blockedByPasswordChange(c *gin.Context, op *database.Operator) bool {
	if !a.PasswordChangeRequired(op) || passwordChangeAllowed[c.FullPath()] {
		return false
	}
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
		"error": "change your password to continue", "passwordChangeRequired": true,
	})
	return true
}

// operator validates the session cookie and returns the operator, or nil.
func (a *Auth) operator(c *gin.Context) *database.Operator {
	cookie, err := c.Cookie(SessionCookieName)
	if err != nil || cookie == "" {
		return nil
	}
	op, err := a.sessions.Validate(cookie, c.ClientIP())
	if err != nil {
		return nil
	}
	return op
}

// HasSession reports whether the request carries a valid operator session. It is
// used to gate assets like the favicon that would otherwise let an anonymous
// scanner fingerprint the admin interface.
func (a *Auth) HasSession(c *gin.Context) bool {
	return a.operator(c) != nil
}

// RequireHTML guards the operator routes outside the JSON API, redirecting to
// the login page when unauthenticated.
func (a *Auth) RequireHTML() gin.HandlerFunc {
	return func(c *gin.Context) {
		op := a.operator(c)
		if op == nil {
			c.Redirect(http.StatusSeeOther, "/login")
			c.Abort()
			return
		}
		if a.blockedByPasswordChange(c, op) {
			return
		}
		c.Set(contextOperatorKey, op)
		c.Next()
	}
}

// RequireAPI guards admin JSON endpoints, returning 401 when unauthenticated.
func (a *Auth) RequireAPI() gin.HandlerFunc {
	return func(c *gin.Context) {
		op := a.operator(c)
		if op == nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		if a.blockedByPasswordChange(c, op) {
			return
		}
		c.Set(contextOperatorKey, op)
		c.Next()
	}
}

// OperatorFromContext returns the operator set by a guard, or nil.
func OperatorFromContext(c *gin.Context) *database.Operator {
	if v, ok := c.Get(contextOperatorKey); ok {
		if op, ok := v.(*database.Operator); ok {
			return op
		}
	}
	return nil
}
