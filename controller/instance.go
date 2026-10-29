package controller

import (
	"errors"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/phishingclub/baitbox/middleware"
	"github.com/phishingclub/baitbox/service"
)

// Instance serves facts about this install that the admin UI shows, and turns
// admin access off.
type Instance struct {
	registryURL    string
	registryPublic bool
	access         *service.AdminAccess
	operators      *service.OperatorService
	sessions       *service.SessionService
	audit          *service.AuditService
}

// InstanceDeps is what NewInstance needs. RegistryURL is the address shown to
// the operator for Phishing Club installs. RegistryPublic is the registry.public
// config flag.
type InstanceDeps struct {
	RegistryURL    string
	RegistryPublic bool
	Access         *service.AdminAccess
	Operators      *service.OperatorService
	Sessions       *service.SessionService
	Audit          *service.AuditService
}

// NewInstance returns the Instance controller.
func NewInstance(d InstanceDeps) *Instance {
	return &Instance{
		registryURL:    d.RegistryURL,
		registryPublic: d.RegistryPublic,
		access:         d.Access,
		operators:      d.Operators,
		sessions:       d.Sessions,
		audit:          d.Audit,
	}
}

// logAudit records an audit event attributed to the signed in operator.
func (i *Instance) logAudit(c *gin.Context, action string, success bool, details map[string]any) {
	op := middleware.OperatorFromContext(c)
	i.audit.Record(action, op.ID, op.Username, c.ClientIP(), success, details)
}

// Info returns the registry URL Phishing Club installs connect to, and whether
// the registry allows anonymous reads of public namespaces.
func (i *Instance) Info(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"registryUrl": i.registryURL, "registryPublic": i.registryPublic})
}

// DisableAdmin turns the admin listener off after checking the operator's
// password. The check is throttled per session and a wrong password counts
// against this session only. The registry keeps serving.
func (i *Instance) DisableAdmin(c *gin.Context) {
	op := middleware.OperatorFromContext(c)
	var body struct {
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "enter your password to confirm"})
		return
	}
	if !sessionBeginProof(c, i.sessions, "Admin.Disable", i.logAudit) {
		return
	}
	if err := i.operators.VerifyPassword(op.ID, body.Password); err != nil {
		if errors.Is(err, service.ErrThrottled) {
			// the server was too busy to check it, so it does not count.
			i.sessions.ProofSkipped(sessionCookie(c))
			replyThrottled(c, err)
			return
		}
		i.audit.Record("Admin.Disable", op.ID, op.Username, c.ClientIP(), false,
			map[string]any{"error": "wrong password"})
		if errors.Is(err, service.ErrInvalidCredentials) {
			if sessionProofFailed(c, i.sessions, i.logAudit) {
				return
			}
			c.JSON(http.StatusForbidden, gin.H{"error": "wrong password"})
			return
		}
		i.sessions.ProofSkipped(sessionCookie(c))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not check the password"})
		return
	}
	i.sessions.ProofSucceeded(sessionCookie(c))
	if err := i.access.Disable(); err != nil {
		log.Printf("disable admin: %v", err)
		i.audit.Record("Admin.Disable", op.ID, op.Username, c.ClientIP(), false,
			map[string]any{"error": "config not writable"})
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "could not write the config file, admin access is unchanged; see the server log",
		})
		return
	}
	i.audit.Record("Admin.Disable", op.ID, op.Username, c.ClientIP(), true, nil)
	c.JSON(http.StatusOK, gin.H{"status": "disabled"})
}
