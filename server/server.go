// Package server builds the Gin engine, registers routes and starts the HTTPS
// listener via the acme package. It wires the controllers to the services.
package server

import (
	"context"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/phishingclub/baitbox/acme"
	"github.com/phishingclub/baitbox/config"
	"github.com/phishingclub/baitbox/controller"
	"github.com/phishingclub/baitbox/frontend"
	"github.com/phishingclub/baitbox/middleware"
	"github.com/phishingclub/baitbox/repository"
	"github.com/phishingclub/baitbox/service"
	"gorm.io/gorm"
)

// Engines holds the two Gin engines Bait Box serves: the registry API and the
// operator admin surface, each on its own listener.
type Engines struct {
	Public *gin.Engine
	Admin  *gin.Engine
	// AdminStop is closed when admin access is turned off from the admin UI.
	AdminStop <-chan struct{}
	// Cleanup deletes expired sessions and memory entries. The caller starts it
	// with the shutdown context and waits for it before closing the database.
	Cleanup *service.CleanupService
}

// New assembles the services, controllers and middleware and returns the
// registry and admin engines with their routes registered. The registry engine
// carries only the read only registry API, so no admin route exists on the
// registry listener.
func New(cfg *config.Config, configPath string, db *gorm.DB, version string) (*Engines, error) {
	operators := service.NewOperatorService(repository.NewOperatorRepository(db))
	sessions := service.NewSessionService(repository.NewSessionRepository(db))
	stats := service.NewStatsService(repository.NewStatsRepository(db))
	tokens := service.NewTokenService(repository.NewTokenRepository(db))

	blobs, err := service.NewBlobStore(cfg.Blobs.Path)
	if err != nil {
		return nil, err
	}
	reg := service.NewRegistryService(service.RegistryDeps{
		Repo:        repository.NewRegistry(db),
		Blobs:       blobs,
		MaxDownload: cfg.Registry.MaxDownload,
		MaxFile:     cfg.Registry.MaxFile,
		Public:      cfg.Registry.Public,
	})
	reg.SetArchiveLimits(cfg.Registry.MaxUnpacked, cfg.Registry.MaxFiles)
	privatized, err := reg.PrivatizeStoredPublic()
	if err != nil {
		return nil, fmt.Errorf("make public namespaces private: %w", err)
	}
	if privatized > 0 {
		log.Printf("registry.public is off: %d namespace(s) stored as public are now private", privatized)
	}
	audit := service.NewAuditService()
	passkeys, err := service.NewWebAuthnService(repository.NewWebAuthnRepository(db), cfg)
	if err != nil {
		return nil, err
	}

	cleanup := service.NewCleanupService(repository.NewCleanupRepository(db),
		sessions.SweepExpired, passkeys.SweepExpired, operators.SweepExpired)

	// in prod an operator with an issued password must set their own before
	// anything else; dev skips it so the stack and tests stay quick to use.
	guard := middleware.NewAuth(sessions, cfg.IsProd())
	auth := controller.NewAuth(controller.AuthDeps{
		Operators: operators,
		Sessions:  sessions,
		Audit:     audit,
		Passkeys:  passkeys,
		Guard:     guard,
	})
	updates := service.NewUpdateService(version)
	updates.StartBackgroundCheck()
	access := service.NewAdminAccess(configPath)
	ctl := &controllers{
		registry: controller.NewRegistry(reg, tokens),
		admin:    controller.NewAdmin(reg, audit),
		adminAPI: controller.NewAdminAPI(controller.AdminAPIDeps{
			Registry:  reg,
			Tokens:    tokens,
			Stats:     stats,
			Operators: operators,
			Audit:     audit,
			Passkeys:  passkeys,
			Sessions:  sessions,
			Guard:     guard,
		}),
		auth:   auth,
		update: controller.NewUpdate(updates, audit),
		instance: controller.NewInstance(controller.InstanceDeps{
			RegistryURL:    cfg.RegistryURL(),
			RegistryPublic: cfg.Registry.Public,
			Access:         access,
			Operators:      operators,
			Sessions:       sessions,
			Audit:          audit,
		}),
	}
	mw := &adminMiddleware{
		allow:        middleware.NewIPAllow(cfg.IPSecurity.AdminAllowed),
		guard:        guard,
		loginLimiter: middleware.NewRateLimiter(1, 5, 10*time.Minute),
	}

	if cfg.IsProd() {
		gin.SetMode(gin.ReleaseMode)
	}

	spa, err := spaHandler(cfg, guard)
	if err != nil {
		return nil, err
	}
	public := newEngine(cfg)
	registryRoutes(public, ctl, cfg.Registry.Public)
	admin := newEngine(cfg)
	adminRoutes(admin, ctl, mw, spa)

	if cfg.IPSecurity.TrustedIPHeader != "" && len(cfg.IPSecurity.TrustedProxies) == 0 {
		log.Printf("warning: ip_security.trusted_ip_header %q ignored because "+
			"ip_security.trusted_proxies is empty; set it to the front's IP ranges to use the header",
			cfg.IPSecurity.TrustedIPHeader)
	}

	return &Engines{Public: public, Admin: admin, AdminStop: access.Stopped(), Cleanup: cleanup}, nil
}

// spaHandler serves the embedded admin SPA, with an index.html fallback so
// client side routes resolve. In dev the SPA is served by vite; this serves the
// embedded build in production.
func spaHandler(cfg *config.Config, guard *middleware.Auth) (gin.HandlerFunc, error) {
	spa := frontend.FS()
	fileServer := http.FileServer(http.FS(spa))
	// SvelteKit bakes the SPA's content security policy, including the hash of its
	// own inline bootstrap script, into a meta tag in index.html (hash mode). Lift
	// that policy into a response header and serve the document with the meta removed,
	// so the policy lives in one place. frame-ancestors and form-action cannot be
	// expressed in a meta tag, so append them here. In dev the embedded build may be
	// only the placeholder, with no index.html, or a local build; with no meta the
	// document gets devSPACSP, which sets no resource rules (dev serves the real SPA
	// from vite anyway).
	spaCSP, indexHTML, haveCSP := frontend.ExtractCSPFromIndex()
	if haveCSP {
		spaCSP += "; frame-ancestors 'none'; form-action 'self'"
	} else if cfg.IsProd() {
		// in prod the embedded build must carry the hashed CSP meta. without it the
		// SPA would lose the inline script XSS backstop, so refuse to start instead.
		return nil, fmt.Errorf("embedded SPA build has no content security policy meta; " +
			"rebuild the frontend so the hashed CSP is present")
	}
	return func(c *gin.Context) {
		p := c.Request.URL.Path
		if strings.HasPrefix(p, "/api/") {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		rel := strings.TrimPrefix(path.Clean(p), "/")
		// the favicon is served only to an authenticated operator; an anonymous request
		// gets 404, so a scanner probing common paths cannot fingerprint this as a Bait
		// Box admin from the icon. the admin IP allowlist is off by default, so this does
		// not rely on it.
		if isFaviconPath(rel) && !guard.HasSession(c) {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
		// only regular files go to the file server, which would list a directory.
		if rel != "" && rel != "index.html" && isServableFile(spa, rel) {
			fileServer.ServeHTTP(c.Writer, c.Request)
			return
		}
		// serving the SPA document (root, index.html, or a client side route fallback):
		// override the baseline CSP with the policy carrying the bootstrap script hash.
		if indexHTML == nil {
			// only the placeholder is embedded (dev without a build).
			c.String(http.StatusNotFound, "admin SPA is not built into this binary")
			return
		}
		if haveCSP {
			c.Header("Content-Security-Policy", spaCSP)
		} else {
			c.Header("Content-Security-Policy", devSPACSP)
		}
		c.Data(http.StatusOK, "text/html; charset=utf-8", indexHTML)
	}, nil
}

// devSPACSP covers a dev build of the SPA that has no CSP meta. The baseline
// policy loads nothing, which would leave that document blank.
const devSPACSP = "frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'"

// isFaviconPath reports whether a cleaned, leading slash trimmed request path is a
// favicon or touch icon asset, which is gated behind an operator session so it does
// not fingerprint the admin interface to an anonymous probe.
func isFaviconPath(rel string) bool {
	base := strings.ToLower(path.Base(rel))
	return strings.HasPrefix(base, "favicon") || strings.HasPrefix(base, "apple-touch-icon")
}

// isServableFile reports whether rel names a regular file in fsys that may be
// served. A dot named file or directory is never served: the build directory
// keeps a tracked placeholder that is embedded too.
func isServableFile(fsys fs.FS, rel string) bool {
	for _, seg := range strings.Split(rel, "/") {
		if strings.HasPrefix(seg, ".") {
			return false
		}
	}
	info, err := fs.Stat(fsys, rel)
	return err == nil && info.Mode().IsRegular()
}

// newEngine returns a Gin engine with recovery, client IP resolution and the
// baseline security headers, shared by the registry and admin listeners.
func newEngine(cfg *config.Config) *gin.Engine {
	engine := gin.New()
	// gin answers a trailing slash redirect before any middleware runs, so the
	// token check and the IP allowlist would never see that request.
	engine.RedirectTrailingSlash = false
	engine.Use(middleware.LogServerErrors(), gin.Recovery())

	// Read the real client IP from a forwarded header only when a trusted proxy list
	// is set, so Gin validates the request actually arrived from that proxy before
	// honouring the header. Without a trusted proxy list the header is ignored (any
	// client could set it), and ClientIP falls back to the direct peer. Never use
	// TrustedPlatform for a custom header: it returns the header value unchecked.
	if err := engine.SetTrustedProxies(cfg.IPSecurity.TrustedProxies); err != nil {
		// a malformed entry means gin trusts only the entries it could parse, so a
		// forwarded header from the real proxy may be ignored and ClientIP falls back
		// to the direct peer. surface it instead of running with a silent half config.
		log.Printf("warning: ip_security.trusted_proxies has an invalid entry (%v); "+
			"fix the config so the real client IP is read correctly", err)
	}
	if cfg.IPSecurity.TrustedIPHeader != "" && len(cfg.IPSecurity.TrustedProxies) > 0 {
		engine.ForwardedByClientIP = true
		engine.RemoteIPHeaders = []string{cfg.IPSecurity.TrustedIPHeader}
	} else {
		// trust a forwarded header only when both a header and a trusted proxy list are
		// set; otherwise turn off gin's default header parsing so no header (not even
		// X-Forwarded-For) can influence the client IP.
		engine.ForwardedByClientIP = false
		engine.RemoteIPHeaders = nil
	}

	engine.Use(middleware.SecurityHeaders())
	return engine
}

// Start serves the registry engine on cfg.Registry.Address and the admin engine on
// cfg.Administration.Address, both over HTTPS. Certificate challenges are
// answered by certmagic on its own listeners, the issuer alternate ports in dev
// and the standard ports in prod. A plain HTTP to HTTPS redirect, where wanted,
// is the job of the front in production; it is not bound here so the process
// needs no privileged port inside the container. When ctx is done every
// listener shuts down, letting requests in flight finish, and Start returns nil.
func Start(ctx context.Context, cfg *config.Config, e *Engines) error {
	certStorage := filepath.Join(filepath.Dir(cfg.Database.Path), "certs", "acme")
	listeners := []acme.Listener{{Addr: cfg.Registry.Address, Handler: e.Public}}
	if cfg.Administration.Disabled {
		log.Printf("admin access is disabled (administration.disabled in the config); " +
			"set it to false or run -enable-admin to turn it back on")
	} else {
		// the import handlers and the handlers that take large bodies extend the
		// read timeout of their own request once the session is checked.
		listeners = append(listeners, acme.Listener{
			Addr:    cfg.Administration.Address,
			Handler: e.Admin,
			Stop:    e.AdminStop,
		})
	}
	return acme.ListenAndServe(
		ctx, cfg.HostList(), listeners, certStorage, cfg.ACME.Email, !cfg.TLSAuto,
	)
}
