package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/phishingclub/baitbox/controller"
	"github.com/phishingclub/baitbox/middleware"
)

// maxAdminBody caps admin JSON request bodies. Generous: a package author request
// carries every file base64 encoded, but it is still bounded.
const maxAdminBody = 256 << 20

// maxLoginBody caps login bodies: credentials or a passkey assertion are tiny.
const maxLoginBody = 64 << 10

// controllers holds every controller the routes call.
type controllers struct {
	registry *controller.Registry
	admin    *controller.Admin
	adminAPI *controller.AdminAPI
	auth     *controller.Auth
	update   *controller.Update
	instance *controller.Instance
}

// adminMiddleware holds the middleware of the admin listener.
type adminMiddleware struct {
	allow        *middleware.IPAllow
	guard        *middleware.Auth
	loginLimiter *middleware.RateLimiter
}

// registryRoutes sets up the registry listener: the registry protocol (catalog
// and download) only, so no admin route exists on it. When the registry is not
// public every request needs a valid token, checked before routing so unknown
// paths get 401 too.
func registryRoutes(r *gin.Engine, c *controllers, public bool) {
	if !public {
		r.Use(c.registry.RequireToken)
	}
	r.Group("/api/v1", middleware.NoSharedCache).
		GET("/info", c.registry.Info).
		GET("/index", c.registry.Index).
		GET("/packages/:ns/:name", c.registry.GetPackage).
		GET("/packages/:ns/:name/:version", c.registry.GetVersion).
		GET("/packages/:ns/:name/:version/download", c.registry.Download).
		GET("/packages/:ns/:name/:version/files/*path", c.registry.Files).
		// preview images live under their own path so they do not collide with the
		// version param of the package routes.
		GET("/previews/:ns/:name/:sha", c.registry.Preview)

	r.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
	})
}

// adminRoutes sets up the admin listener: the operator routes, the registry
// protocol for a signed in operator, login, the admin JSON API and the SPA.
func adminRoutes(r *gin.Engine, c *controllers, m *adminMiddleware, spa gin.HandlerFunc) {
	// operator routes the SPA uses outside the JSON API, IP allowlisted and
	// session guarded.
	r.Group("/", m.allow.Middleware()).
		Group("/", m.guard.RequireHTML()).
		GET("/admin/export", c.admin.Export).
		POST("/admin/import", c.admin.Import).
		GET("/admin/packages/:ns/:name/export", c.admin.ExportPackage).
		POST("/admin/import-package", c.admin.ImportPackage).
		POST("/preview", c.admin.Preview).
		GET("/packages/:ns/:name/:version/rawfile/*path", c.admin.RawFile)

	// the registry protocol for a signed in operator. The SPA does not use it; the
	// registry listener is where consumers read. The single package file
	// read is left out, so no package file is served from this origin.
	r.Group("/api/v1", m.allow.Middleware(), m.guard.RequireAPI(), middleware.NoSharedCache).
		GET("/info", c.registry.Info).
		GET("/index", c.registry.Index).
		GET("/packages/:ns/:name", c.registry.GetPackage).
		GET("/packages/:ns/:name/:version", c.registry.GetVersion).
		GET("/packages/:ns/:name/:version/download", c.registry.Download).
		GET("/previews/:ns/:name/:sha", c.registry.Preview)

	// login is rate limited with a small body cap; me is session guarded.
	loginBody := middleware.BodyLimit(maxLoginBody)
	r.Group("/api/v1").
		POST("/login",
			m.allow.Middleware(), loginBody, m.loginLimiter.Middleware(), c.auth.LoginJSON).
		POST("/login/passkey/begin",
			m.allow.Middleware(), loginBody, m.loginLimiter.Middleware(), c.auth.PasskeyLoginBegin).
		POST("/login/passkey/finish",
			m.allow.Middleware(), loginBody, m.loginLimiter.Middleware(), c.auth.PasskeyLoginFinish).
		POST("/logout",
			m.allow.Middleware(), loginBody, m.loginLimiter.Middleware(), c.auth.LogoutJSON).
		GET("/me", m.allow.Middleware(), m.guard.RequireAPI(), c.auth.Me)

	// the admin JSON API: IP allowlisted and session guarded, with a body cap so
	// authoring a package (base64 files in JSON) cannot allocate without bound.
	r.Group("/api/v1/admin",
		m.allow.Middleware(), m.guard.RequireAPI(), middleware.BodyLimit(maxAdminBody)).
		GET("/stats", c.adminAPI.Stats).
		POST("/change-password", c.adminAPI.ChangePassword).
		GET("/mfa", c.adminAPI.MFAStatus).
		POST("/mfa/begin", c.adminAPI.MFABegin).
		POST("/mfa/confirm", c.adminAPI.MFAConfirm).
		POST("/mfa/disable", c.adminAPI.MFADisable).
		GET("/stepup", c.adminAPI.StepUpStatus).
		POST("/stepup", c.adminAPI.StepUp).
		POST("/stepup/passkey/begin", c.adminAPI.StepUpPasskeyBegin).
		POST("/stepup/passkey/finish", c.adminAPI.StepUpPasskeyFinish).
		GET("/passkeys", c.adminAPI.PasskeysList).
		POST("/passkeys/register/begin", c.adminAPI.PasskeyRegisterBegin).
		POST("/passkeys/register/finish", c.adminAPI.PasskeyRegisterFinish).
		DELETE("/passkeys/:id", c.adminAPI.PasskeyDelete).
		GET("/operators", c.adminAPI.OperatorsList).
		POST("/operators", c.adminAPI.OperatorCreate).
		DELETE("/operators/:id", c.adminAPI.OperatorDelete).
		GET("/namespaces", c.adminAPI.NamespacesList).
		POST("/namespaces", c.adminAPI.NamespaceCreate).
		PATCH("/namespaces/:id", c.adminAPI.NamespaceUpdate).
		GET("/namespaces/:id/rename-impact", c.adminAPI.NamespaceRenameImpact).
		POST("/namespaces/:id/rename", c.adminAPI.NamespaceRename).
		DELETE("/namespaces/:id", c.adminAPI.NamespaceDelete).
		GET("/tokens", c.adminAPI.TokensList).
		POST("/tokens", c.adminAPI.TokenCreate).
		PATCH("/tokens/:id", c.adminAPI.TokenUpdate).
		POST("/tokens/:id/revoke", c.adminAPI.TokenRevoke).
		DELETE("/tokens/:id", c.adminAPI.TokenDelete).
		GET("/tags", c.adminAPI.TagsList).
		POST("/tags", c.adminAPI.TagSetColor).
		GET("/drafts", c.adminAPI.DraftsList).
		POST("/drafts", c.adminAPI.DraftSave).
		GET("/drafts/:ns/:name", c.adminAPI.DraftGet).
		DELETE("/drafts/:ns/:name", c.adminAPI.DraftDelete).
		GET("/packages", c.adminAPI.PackagesList).
		POST("/packages", c.adminAPI.PackageAuthor).
		GET("/packages/:ns/:name", c.adminAPI.PackageDetail).
		GET("/packages/:ns/:name/dependents", c.adminAPI.PackageDependents).
		POST("/packages/:ns/:name/move", c.adminAPI.PackageMove).
		PATCH("/packages/:ns/:name/meta", c.adminAPI.PackageMetaUpdate).
		DELETE("/packages/:ns/:name", c.adminAPI.PackageDelete).
		GET("/packages/:ns/:name/versions/:version/source", c.adminAPI.PackageSource).
		GET("/packages/:ns/:name/versions/:version/archive", c.adminAPI.PackageArchive).
		POST("/packages/:ns/:name/versions/:version/yank", c.adminAPI.VersionYank).
		DELETE("/packages/:ns/:name/versions/:version", c.adminAPI.VersionDelete).
		GET("/packages/:ns/:name/previews", c.adminAPI.PreviewsList).
		POST("/packages/:ns/:name/previews", c.adminAPI.PreviewAdd).
		PATCH("/packages/:ns/:name/previews/order", c.adminAPI.PreviewReorder).
		GET("/packages/:ns/:name/previews/:sha", c.adminAPI.PreviewServe).
		DELETE("/packages/:ns/:name/previews/:sha", c.adminAPI.PreviewDelete).
		GET("/update", c.update.Status).
		POST("/update/check", c.update.Check).
		POST("/update/run", c.update.Run).
		GET("/instance", c.instance.Info).
		POST("/instance/disable-admin", c.instance.DisableAdmin)

	// everything else is the embedded admin SPA, IP allowlisted.
	r.NoRoute(m.allow.Middleware(), spa)
}
