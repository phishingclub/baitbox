package controller

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/model"
	"github.com/phishingclub/baitbox/service"
	"github.com/phishingclub/baitbox/utils"
)

// Registry handles the registry protocol: catalog browsing and download. A
// private registry needs a valid token on every request. A public one lets
// anonymous callers read public namespaces; private namespaces always need a
// token with read on them.
type Registry struct {
	reg    *service.RegistryService
	tokens *service.TokenService
}

// NewRegistry returns the Registry controller.
func NewRegistry(reg *service.RegistryService, tokens *service.TokenService) *Registry {
	return &Registry{reg: reg, tokens: tokens}
}

// tokenKey holds the token RequireToken resolved, so handlers do not look it up
// again.
const tokenKey = "registryToken"

// RequireToken refuses a request without a valid token. The reply is a plain
// generic error that does not name the product.
func (a *Registry) RequireToken(c *gin.Context) {
	h := c.GetHeader("Authorization")
	if h == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	t, err := a.tokens.Authenticate(h, c.ClientIP())
	if errors.Is(err, service.ErrInvalidToken) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}
	c.Set(tokenKey, t)
	c.Next()
}

// MinPhishingClubVersion is the minimum Phishing Club version that may use this
// registry. The consumer reads it from Info at connect time and refuses to
// connect when it is older. It is 1.44.0, the first Phishing Club version that
// ships the Bait Box registry client. Raise it in a later registry release that
// needs a newer consumer.
const MinPhishingClubVersion = "1.44.0"

// Info reports registry metadata a consumer needs before using it, currently the
// minimum Phishing Club version required. On a public registry it needs no
// token, so a consumer without one still learns the required version. The only
// field is a constant that is the same for every install of this release.
func (a *Registry) Info(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"minPhishingClubVersion": MinPhishingClubVersion})
}

// previewURLs returns the public preview image URLs for a package, in order.
func (a *Registry) previewURLs(nsName, name, pkgID string) []string {
	ps, err := a.reg.PreviewsByPackageID(pkgID)
	if err != nil {
		return []string{}
	}
	urls := make([]string, 0, len(ps))
	for i := range ps {
		urls = append(urls, "/api/v1/previews/"+nsName+"/"+name+"/"+ps[i].BlobSHA256)
	}
	return urls
}

// Preview streams a package preview image to a caller who can see the package.
func (a *Registry) Preview(c *gin.Context) {
	t := a.authToken(c)
	ns, pkg, _, err := a.reg.Resolve(c.Param("ns"), c.Param("name"), "latest")
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	if !a.canSee(t, ns.Name, ns.Visibility) {
		c.Status(http.StatusNotFound)
		return
	}
	rc, mediaType, err := a.reg.OpenPreview(ns.Name, pkg.Name, c.Param("sha"))
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	defer rc.Close()
	if mediaType == "" {
		mediaType = "application/octet-stream"
	}
	c.Header("Content-Type", mediaType)
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Content-Security-Policy", "sandbox")
	// the private, no-store default stays even for a public namespace, so turning
	// the namespace private takes effect at once instead of after a cache expiry.
	_, _ = io.Copy(c.Writer, rc)
}

// authToken resolves the bearer token, or nil when absent or invalid.
func (a *Registry) authToken(c *gin.Context) *database.Token {
	if v, ok := c.Get(tokenKey); ok {
		if t, ok := v.(*database.Token); ok {
			return t
		}
	}
	h := c.GetHeader("Authorization")
	if h == "" {
		return nil
	}
	t, err := a.tokens.Authenticate(h, c.ClientIP())
	if err != nil {
		return nil
	}
	return t
}

// canSee gates read access. Visibility is a namespace property: a package is
// reachable without a token only when its namespace is public on a public
// registry. Otherwise a token with read on the namespace is required.
func (a *Registry) canSee(t *database.Token, nsName, nsVisibility string) bool {
	if a.reg.EffectiveVisibility(nsVisibility) == database.VisibilityPublic {
		return true
	}
	return t != nil && a.tokens.CanRead(t, nsName)
}

// Index lists the packages visible to the caller.
func (a *Registry) Index(c *gin.Context) {
	t := a.authToken(c)
	namespaces, err := a.reg.Namespaces(nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "list namespaces"})
		return
	}
	nsName := map[string]string{}
	nsVis := map[string]string{}
	for i := range namespaces {
		nsName[namespaces[i].ID] = namespaces[i].Name
		nsVis[namespaces[i].ID] = a.reg.EffectiveVisibility(namespaces[i].Visibility)
	}
	packages, err := a.reg.Packages(nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "list packages"})
		return
	}
	out := []gin.H{}
	// the set of tag names on packages this caller can see, so the color map below
	// never reveals a tag that exists only on a hidden private package.
	visibleTags := map[string]bool{}
	for i := range packages {
		p := &packages[i]
		name := nsName[p.NamespaceID]
		if !a.canSee(t, name, nsVis[p.NamespaceID]) {
			continue
		}
		tags := utils.SplitTrim(p.Tags, ",")
		// color rows are keyed by the cleaned tag name, so match on that form.
		for _, tg := range model.CleanTags(tags) {
			visibleTags[tg] = true
		}
		out = append(out, gin.H{
			"namespace":     name,
			"name":          p.Name,
			"title":         p.Title,
			"type":          p.Type,
			"description":   p.Description,
			"visibility":    nsVis[p.NamespaceID],
			"downloadCount": p.DownloadCount,
			"version":       a.reg.CurrentVersion(p.ID),
			"previewImages": a.previewURLs(name, p.Name, p.ID),
			"tags":          tags,
		})
	}
	// the color for each visible tag, so the consumer renders the same chip colors
	// the operator chose here. scoped to visible tags only.
	tagColors := map[string]string{}
	if allTags, err := a.reg.ListTags(); err == nil {
		for i := range allTags {
			if visibleTags[allTags[i].Name] && allTags[i].Color != "" {
				tagColors[allTags[i].Name] = allTags[i].Color
			}
		}
	}
	c.JSON(http.StatusOK, gin.H{"packages": out, "tagColors": tagColors})
}

// GetPackage returns a package and its versions.
func (a *Registry) GetPackage(c *gin.Context) {
	t := a.authToken(c)
	ns, pkg, _, err := a.reg.Resolve(c.Param("ns"), c.Param("name"), "latest")
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if !a.canSee(t, ns.Name, ns.Visibility) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	versions, _ := a.reg.Versions(pkg.ID)
	vout := []gin.H{}
	for i := range versions {
		vout = append(vout, gin.H{
			"version": versions[i].Version, "yanked": versions[i].Yanked, "size": versions[i].Size,
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"namespace":     ns.Name,
		"name":          pkg.Name,
		"title":         pkg.Title,
		"type":          pkg.Type,
		"versions":      vout,
		"previewImages": a.previewURLs(ns.Name, pkg.Name, pkg.ID),
	})
}

// GetVersion returns a version manifest and its integrity hashes.
func (a *Registry) GetVersion(c *gin.Context) {
	t := a.authToken(c)
	ns, pkg, v, err := a.reg.Resolve(c.Param("ns"), c.Param("name"), c.Param("version"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if !a.canSee(t, ns.Name, ns.Visibility) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"namespace":   ns.Name,
		"name":        pkg.Name,
		"version":     v.Version,
		"manifest":    json.RawMessage(v.Manifest),
		"contentHash": v.ContentHash,
		"archiveSha":  v.ArchiveBlobSHA256,
		"size":        v.Size,
	})
}

// Download streams a version archive.
func (a *Registry) Download(c *gin.Context) {
	t := a.authToken(c)
	ns, pkg, v, err := a.reg.Resolve(c.Param("ns"), c.Param("name"), c.Param("version"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if !a.canSee(t, ns.Name, ns.Visibility) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	rc, err := a.reg.OpenArchive(v)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "open archive"})
		return
	}
	defer rc.Close()
	c.Header("Content-Type", "application/gzip")
	c.Header("Content-Disposition", attachmentDisposition(pkg.Name+"-"+v.Version+".tar.gz"))
	c.Header("X-Baitbox-Content-Hash", v.ContentHash)
	c.Header("X-Baitbox-Archive-Sha256", v.ArchiveBlobSHA256)
	c.Status(http.StatusOK)
	_, _ = io.Copy(c.Writer, rc)
}

// maxServedFile caps one file the Files route sends. Package previews only need
// html and images, far below the per file archive limit.
const maxServedFile = 8 << 20

// Files serves a single file from a version archive, used to preview an email
// or page with its images. A file whose bytes sniff as the raster image its
// extension names keeps that type; every other file is sent as an attachment of
// type application/octet-stream. The file is streamed from the archive, so a
// request holds only the decompressor state in memory.
func (a *Registry) Files(c *gin.Context) {
	t := a.authToken(c)
	ns, _, v, err := a.reg.Resolve(c.Param("ns"), c.Param("name"), c.Param("version"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if !a.canSee(t, ns.Name, ns.Visibility) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	rel := c.Param("path")
	f, size, err := a.reg.OpenPackageFile(v, rel, maxServedFile)
	if errors.Is(err, service.ErrFileTooLarge) {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "file is too large to serve"})
		return
	}
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	defer f.Close()
	// the sniff reads the same 512 bytes http.DetectContentType looks at.
	head := make([]byte, 512)
	n, err := io.ReadFull(f, head)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not read the file"})
		return
	}
	head = head[:n]
	ct := rawImageType(rel, head)
	if ct == "" {
		ct = "application/octet-stream"
		c.Header("Content-Disposition", attachmentDisposition(path.Base(rel)))
	}
	// never let a served package file execute in the registry origin.
	c.Header("Content-Security-Policy", "sandbox")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Content-Type", ct)
	c.Header("Content-Length", strconv.FormatInt(size, 10))
	c.Status(http.StatusOK)
	if _, err := c.Writer.Write(head); err != nil {
		return
	}
	_, _ = io.Copy(c.Writer, f)
}
