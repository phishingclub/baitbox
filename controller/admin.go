package controller

import (
	"errors"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/phishingclub/baitbox/middleware"
	"github.com/phishingclub/baitbox/service"
	"github.com/phishingclub/baitbox/utils"
)

// Admin holds the operator routes that back the SPA but are not plain JSON:
// the whole registry export/import and the package preview file server.
type Admin struct {
	reg   *service.RegistryService
	audit *service.AuditService
}

// NewAdmin returns the Admin controller.
func NewAdmin(reg *service.RegistryService, audit *service.AuditService) *Admin {
	return &Admin{reg: reg, audit: audit}
}

// logAudit records an export or import performed by the current operator.
func (a *Admin) logAudit(c *gin.Context, action string, success bool, details map[string]any) {
	op := middleware.OperatorFromContext(c)
	a.audit.Record(action, op.ID, op.Username, c.ClientIP(), success, details)
}

// previewMaxBody caps the html a single live preview request may carry. Generous
// because an editor preview can inline images as data URIs.
const previewMaxBody = 32 << 20

// previewCSP runs the posted html in an opaque origin sandbox so it looks like
// the real page. Images, fonts, stylesheets and media may load from any https
// host as well as data and blob urls, so a template that links a CDN font or a
// remote logo renders as it would when sent. Scripts run only from inline code
// and data or blob urls, never from a remote host. fetch, xhr, websockets, form
// posts, plugins and base changes are blocked. The origin is opaque (no
// allow-same-origin), so nothing in the document can read the admin session or
// reach the admin app. A remote image or stylesheet request does reach its host,
// and a click can still navigate the frame or open a popup, the same as opening
// the page in a browser.
//
// The sandbox leaves out allow-modals, so alert, confirm, prompt and print in a
// package do nothing instead of opening a dialog over the admin tab.
// allow-forms stays: without it the browser stops a form submission before the
// submit event fires, so a template's own submit handlers (validation, a multi
// step login drawn in script) would not run in the preview. form-action 'none'
// still blocks the request the submission would send. frame-ancestors 'self'
// lets only the admin app frame the preview.
const previewCSP = "sandbox allow-scripts allow-forms allow-popups; " +
	"default-src data: blob:; " +
	"script-src 'unsafe-inline' 'unsafe-eval' data: blob:; " +
	"style-src 'unsafe-inline' data: https:; " +
	"img-src data: blob: https:; " +
	"font-src data: https:; " +
	"media-src data: blob: https:; " +
	"connect-src 'none'; " +
	"form-action 'none'; " +
	"object-src 'none'; " +
	"base-uri 'none'; " +
	"frame-ancestors 'self'"

// rawFileCSP covers a raster image served from a package archive. The SPA loads
// it with an <img>, which a CSP sandbox does not affect. Opened on its own the
// image document gets an opaque origin with no scripts and cannot be framed.
const rawFileCSP = "sandbox; " +
	"default-src 'none'; " +
	"img-src 'self' data:; " +
	"style-src 'unsafe-inline'; " +
	"form-action 'none'; " +
	"base-uri 'none'; " +
	"frame-ancestors 'none'"

// rawImageTypes maps the file extensions the rawfile route serves to the media
// type the bytes must sniff as.
var rawImageTypes = map[string]string{
	".png":  "image/png",
	".jpg":  "image/jpeg",
	".jpeg": "image/jpeg",
	".gif":  "image/gif",
	".webp": "image/webp",
}

// rawImageType returns the media type to serve a package file with, or empty
// when the file is not a raster image whose bytes match its extension.
func rawImageType(name string, data []byte) string {
	want := rawImageTypes[strings.ToLower(filepath.Ext(name))]
	if want == "" || http.DetectContentType(data) != want {
		return ""
	}
	return want
}

// attachmentDisposition builds a Content-Disposition attachment header value.
// Any byte outside letters, digits, dot, dash and underscore becomes an
// underscore, so a name cannot break out of the quoted filename or inject a
// header.
func attachmentDisposition(name string) string {
	safe := []byte(name)
	for i, b := range safe {
		switch {
		case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9', b == '.', b == '-', b == '_':
		default:
			safe[i] = '_'
		}
	}
	if len(safe) == 0 {
		safe = []byte("download")
	}
	return "attachment; filename=\"" + string(safe) + "\""
}

// Preview echoes posted html back as a standalone document so the SPA can show a
// live preview that may run scripts. The sandbox CSP omits allow-same-origin, so
// the document loads in an opaque origin: its scripts cannot read the admin
// session cookie, call the admin API with credentials, or reach the admin window.
// It also omits allow-top-navigation, so it cannot navigate the admin tab.
func (a *Admin) Preview(c *gin.Context) {
	extendRead(c, largeBodyReadTimeout)
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, previewMaxBody)
	body := c.PostForm("html")
	c.Header("Content-Security-Policy", previewCSP)
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Cache-Control", "no-store")
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(body))
}

// Export streams the registry content (namespaces, packages, versions and
// preview images) as a portable bundle. Operators, passkeys, tokens and drafts
// are not part of it.
func (a *Admin) Export(c *gin.Context) {
	c.Header("Content-Type", "application/gzip")
	// date stamp the filename so repeated exports do not overwrite each other.
	name := "baitbox-export-" + time.Now().Format("2006-01-02") + ".tar.gz"
	c.Header("Content-Disposition", attachmentDisposition(name))
	if err := a.reg.ExportBundle(c.Writer); err != nil {
		a.logAudit(c, "Registry.Export", false, map[string]any{"reason": "export failed"})
		c.Status(http.StatusInternalServerError)
		return
	}
	a.logAudit(c, "Registry.Export", true, nil)
}

// ExportPackage streams one package as a portable bundle in the same format as
// the whole registry export, scoped to the namespace and name in the path.
func (a *Admin) ExportPackage(c *gin.Context) {
	ns, name := c.Param("ns"), c.Param("name")
	// latest=true ships only the current version, for a smaller bundle; the default
	// ships every version so the bundle carries the whole package history.
	latestOnly := c.Query("latest") == "true"
	c.Header("Content-Type", "application/gzip")
	// date stamp the filename so repeated exports do not overwrite each other.
	suffix := ""
	if latestOnly {
		suffix = "-latest"
	}
	fname := ns + "-" + name + suffix + "-" + time.Now().Format("2006-01-02") + ".tar.gz"
	c.Header("Content-Disposition", attachmentDisposition(fname))
	details := map[string]any{"package": ns + "/" + name, "latestOnly": latestOnly}
	if err := a.reg.ExportPackageBundle(c.Writer, ns, name, latestOnly); err != nil {
		details["reason"] = "export failed"
		if errors.Is(err, service.ErrNotFound) {
			details["reason"] = "not found"
		}
		a.logAudit(c, "Package.Export", false, details)
		if errors.Is(err, service.ErrNotFound) {
			c.Status(http.StatusNotFound)
			return
		}
		c.Status(http.StatusInternalServerError)
		return
	}
	a.logAudit(c, "Package.Export", true, details)
}

// ImportPackage imports a single package bundle posted as the raw request body.
// It runs the same import path as the whole registry import, so a crafted bundle
// is capped and every version's archive integrity is reverified before it is stored.
func (a *Admin) ImportPackage(c *gin.Context) {
	extendRead(c, importReadTimeout)
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, importMaxBody)
	sum, err := a.reg.ImportBundle(c.Request.Body)
	a.finishImport(c, "Package.Import", sum, err)
}

// finishImport audits an import and writes its response. A bundle the service
// rejected as invalid carries a reason the service wrote for the operator, so it
// is shown; any other error is a server fault and its internals are not leaked.
func (a *Admin) finishImport(c *gin.Context, action string, sum *service.ImportSummary, err error) {
	if err != nil {
		if errors.Is(err, service.ErrInvalidBundle) {
			a.logAudit(c, action, false, map[string]any{"reason": err.Error()})
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if errors.Is(err, service.ErrConcurrentChange) {
			// the reason names the namespace or package that changed, which the
			// operator already sees in the admin UI.
			a.logAudit(c, action, false, map[string]any{"reason": err.Error()})
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		a.logAudit(c, action, false, map[string]any{"reason": "import failed"})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "import failed"})
		return
	}
	res := importResult(sum)
	a.logAudit(c, action, true, map[string]any{
		"namespaces": sum.Namespaces,
		"packages":   sum.Packages,
		"versions":   sum.Versions,
		"upgraded":   res["upgraded"],
		"skipped":    res["skipped"],
		"refused":    res["refused"],
		"warnings":   res["warnings"],
	})
	c.JSON(http.StatusOK, res)
}

// importResult shapes an import summary for the SPA. upgraded and skipped name
// the existing packages a newer bundle updated and the ones left untouched;
// refused names the packages the import would not file and warnings says why,
// so the UI can show what an import changed, skipped or refused.
func importResult(sum *service.ImportSummary) gin.H {
	return gin.H{
		"status":     "imported",
		"namespaces": sum.Namespaces,
		"packages":   sum.Packages,
		"versions":   sum.Versions,
		"upgraded":   utils.NonNil(sum.Upgraded),
		"skipped":    utils.NonNil(sum.Skipped),
		"refused":    utils.NonNil(sum.Refused),
		"warnings":   utils.NonNil(sum.Warnings),
	}
}

// importMaxBody caps the bundle a single import request may carry. It matches the
// magnitude of the service side bundle byte cap so the stream is bounded before
// any parsing, the same way the live preview caps its body.
const importMaxBody = 8 << 30

// importReadTimeout is how long a signed in import may take to send its body.
const importReadTimeout = time.Hour

// largeBodyReadTimeout is how long a signed in request with a large body, up to
// the admin API body cap, may take to send it.
const largeBodyReadTimeout = 10 * time.Minute

// extendRead gives a request a read deadline of d from now, longer than the
// listener's short read timeout, so a large body on a slow link can arrive. Call
// it only behind the session guard, so only a signed in operator gets it.
func extendRead(c *gin.Context, d time.Duration) {
	if err := http.NewResponseController(c.Writer).SetReadDeadline(time.Now().Add(d)); err != nil {
		log.Printf("could not extend the read deadline: %v", err)
	}
}

// Import imports a registry export bundle posted as the raw request body.
func (a *Admin) Import(c *gin.Context) {
	extendRead(c, importReadTimeout)
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, importMaxBody)
	sum, err := a.reg.ImportBundle(c.Request.Body)
	a.finishImport(c, "Registry.Import", sum, err)
}

// RawFile serves one raster image from a package archive, used for the package
// thumbnail. The file is served only when its bytes sniff as the type its
// extension names; html, svg, scripts and every other file are 404, so this
// authenticated same origin route never returns a document that could run in
// the admin origin. The headers are set first so every response, a 404
// included, carries the sandbox CSP.
func (a *Admin) RawFile(c *gin.Context) {
	c.Header("Content-Security-Policy", rawFileCSP)
	c.Header("X-Content-Type-Options", "nosniff")
	nsName, name, version := c.Param("ns"), c.Param("name"), c.Param("version")
	_, _, v, err := a.reg.Resolve(nsName, name, version)
	if err != nil {
		c.String(http.StatusNotFound, "not found")
		return
	}
	rel := c.Param("path")
	if rawImageTypes[strings.ToLower(filepath.Ext(rel))] == "" {
		c.String(http.StatusNotFound, "not found")
		return
	}
	data, err := a.reg.ReadPackageFile(v, rel)
	if err != nil {
		c.String(http.StatusNotFound, "not found")
		return
	}
	ct := rawImageType(rel, data)
	if ct == "" {
		c.String(http.StatusNotFound, "not found")
		return
	}
	c.Data(http.StatusOK, ct, data)
}
