package controller

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/phishingclub/baitbox/middleware"
	"github.com/phishingclub/baitbox/service"
)

// Update serves the software update status and runs an in app update. It is
// mounted under the session guarded, IP allowlisted admin API.
type Update struct {
	updates *service.UpdateService
	audit   *service.AuditService
}

// NewUpdate returns the Update controller.
func NewUpdate(updates *service.UpdateService, audit *service.AuditService) *Update {
	return &Update{updates: updates, audit: audit}
}

// Status returns the result of the last release check without asking GitHub.
func (u *Update) Status(c *gin.Context) {
	c.JSON(http.StatusOK, u.updates.Status())
}

// Check asks GitHub for the latest release now.
func (u *Update) Check(c *gin.Context) {
	c.JSON(http.StatusOK, u.updates.Check())
}

// Run installs the latest signed release and restarts the service.
func (u *Update) Run(c *gin.Context) {
	op := middleware.OperatorFromContext(c)
	id, username := op.ID, op.Username
	tag, err := u.updates.Run()
	switch {
	case err == nil:
		u.audit.Record("Update.Run", id, username, c.ClientIP(), true, map[string]any{"version": tag})
		c.JSON(http.StatusOK, gin.H{"status": "updated", "version": tag})
	case errors.Is(err, service.ErrUpdateRunning):
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	case errors.Is(err, service.ErrNoUpdate), errors.Is(err, service.ErrUpdateNotInApp):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	default:
		u.audit.Record("Update.Run", id, username, c.ClientIP(), false, map[string]any{"error": err.Error()})
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "update failed, the current version keeps running; see the server log",
		})
	}
}
