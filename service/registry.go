package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"slices"
	"sort"
	"strings"
	"time"

	"golang.org/x/mod/semver"

	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/manifest"
	"github.com/phishingclub/baitbox/model"
	"github.com/phishingclub/baitbox/repository"
)

// Publish and download errors.
var (
	ErrVersionExists     = errors.New("version already exists")
	ErrNamespaceMismatch = errors.New("archive namespace does not match target")
	ErrNotFound          = errors.New("not found")
	// ErrTypeMismatch is returned when a manifest declares a type other than the
	// type of the existing package it is published or imported into.
	ErrTypeMismatch = errors.New("package type does not match the existing package")
	// ErrConcurrentChange is returned when a package or namespace changed while a
	// move, rename or publish was in progress. Retrying the action is safe.
	ErrConcurrentChange = errors.New("the package changed while this action ran, try again")
	// ErrLastVersion refuses deleting the only version of a package.
	ErrLastVersion = &ValidationError{
		Err: errors.New("this is the only version of the package; delete the package instead"),
	}
)

// ValidationError is a refusal whose message was written for the operator, so a
// handler may send it to the client. Any other error is an internal fault whose
// text stays in the server log.
type ValidationError struct{ Err error }

func (e *ValidationError) Error() string { return e.Err.Error() }
func (e *ValidationError) Unwrap() error { return e.Err }

// invalid marks err as a ValidationError. A nil err stays nil.
func invalid(err error) error {
	if err == nil {
		return nil
	}
	return &ValidationError{Err: err}
}

// invalidf is fmt.Errorf marked as a ValidationError.
func invalidf(format string, args ...any) error {
	return invalid(fmt.Errorf(format, args...))
}

// IsValidation reports whether err carries a reason meant for the operator: a
// ValidationError or one of the publish refusals the admin UI shows as written.
func IsValidation(err error) bool {
	var ve *ValidationError
	return errors.As(err, &ve) ||
		errors.Is(err, ErrNamespaceMismatch) ||
		errors.Is(err, ErrTypeMismatch) ||
		errors.Is(err, ErrBundleTooLarge) ||
		errors.Is(err, ErrPreviewImage) ||
		errors.Is(err, ErrBlobTooLarge)
}

// RegistryService orchestrates publishing and downloading package archives over
// the blob store, the integrity pipeline and the repositories.
type RegistryService struct {
	repo        *repository.Registry
	blobs       *BlobStore
	maxDownload int64
	maxFile     int64
	limits      ArchiveLimits
	// bundleCap is the most a bundle and its references may unpack to, always
	// MaxBundleInstallBytes outside tests.
	bundleCap int64
	// public allows public namespaces. When false a namespace marked public is
	// treated as private everywhere visibility is decided.
	public bool
	// beforeRepackCommit, when set, runs after a move or rename built its plans
	// and before its transaction opens. Tests use it to commit a competing change.
	beforeRepackCommit func()
	// beforeWriteCommit, when set, runs after a publish or import made its checks
	// and before its transaction opens. Tests use it to commit a competing change.
	beforeWriteCommit func()
}

// RegistryDeps is what NewRegistryService needs. MaxDownload caps one uploaded
// archive and MaxFile one file inside it.
type RegistryDeps struct {
	Repo        *repository.Registry
	Blobs       *BlobStore
	MaxDownload int64
	MaxFile     int64
	// Public is the registry.public config flag.
	Public bool
}

// NewRegistryService returns a RegistryService.
func NewRegistryService(d RegistryDeps) *RegistryService {
	return &RegistryService{
		repo:        d.Repo,
		blobs:       d.Blobs,
		maxDownload: d.MaxDownload,
		maxFile:     d.MaxFile,
		limits:      ArchiveLimits{MaxFile: d.MaxFile}.withDefaults(),
		bundleCap:   MaxBundleInstallBytes,
		public:      d.Public,
	}
}

// ErrPublicDisabled refuses making a namespace public on a private registry.
var ErrPublicDisabled = errors.New(
	"the registry is private, so namespaces cannot be public; set registry.public in the config to allow it")

// PrivatizeStoredPublic stores every namespace marked public as private when
// the registry is not public, so turning registry.public on later shows nothing
// that was hidden. It returns how many changed.
func (s *RegistryService) PrivatizeStoredPublic() (int64, error) {
	if s.public {
		return 0, nil
	}
	return s.repo.MakePublicNamespacesPrivate()
}

// EffectiveVisibility is the visibility a namespace has on this registry: one
// marked public reads as private unless the registry is public.
func (s *RegistryService) EffectiveVisibility(v string) string {
	if s.public && v == database.VisibilityPublic {
		return database.VisibilityPublic
	}
	return database.VisibilityPrivate
}

// effectiveLookup wraps a namespace visibility lookup with EffectiveVisibility.
func (s *RegistryService) effectiveLookup(f func(string) string) func(string) string {
	return func(nsName string) string {
		return s.EffectiveVisibility(f(nsName))
	}
}

// SetArchiveLimits sets the unpacked total and file count caps every archive
// must fit at publish and import. A value of zero keeps the default.
func (s *RegistryService) SetArchiveLimits(maxUnpacked int64, maxFiles int) {
	s.limits = ArchiveLimits{
		MaxFile:     s.maxFile,
		MaxUnpacked: maxUnpacked,
		MaxFiles:    maxFiles,
	}.withDefaults()
}

// Publish validates and stores an uploaded archive as a new package version in
// namespaceName. The archive is streamed to the blob store under a size cap,
// inspected for integrity, checked to match the target namespace and recorded.
// A duplicate version is rejected.
func (s *RegistryService) Publish(
	namespaceName, expectName, expectVersion, mediaType string, body io.Reader,
) (*database.PackageVersion, error) {
	sha, size, err := s.blobs.Put(body, s.maxDownload)
	if err != nil {
		return nil, err
	}
	// Put pinned the blob so a concurrent cleanup cannot remove it before the
	// version row exists. Release the pin when done; if the publish did not
	// complete, also remove the blob unless something already references it (a
	// deduped upload), so a rejected upload does not leak disk.
	committed := false
	defer func() {
		s.blobs.Release(sha)
		if !committed {
			s.cleanupBlob(sha)
		}
	}()

	blobPath, err := s.blobs.Path(sha)
	if err != nil {
		return nil, err
	}
	m, unpacked, err := InspectArchiveSize(blobPath, s.limits)
	if err != nil {
		// a file system fault is internal; every other failure is a check on the
		// archive or its manifest.
		var pathErr *fs.PathError
		if errors.As(err, &pathErr) {
			return nil, err
		}
		return nil, invalid(err)
	}
	// the url coordinates must match the archive manifest so a publisher cannot
	// post an archive into a package or version it did not name.
	if m.Namespace() != namespaceName {
		return nil, ErrNamespaceMismatch
	}
	if expectName != "" && m.PackageName() != expectName {
		return nil, ErrNamespaceMismatch
	}
	if expectVersion != "" && m.Version != expectVersion {
		return nil, ErrNamespaceMismatch
	}

	// a namespace created by a publish is always private.
	ns, err := s.repo.EnsureNamespace(namespaceName, database.VisibilityPrivate)
	if err != nil {
		return nil, err
	}
	// validate the dependency rules before the package row exists so a rejected
	// manifest never leaves a package with no version behind.
	if err := s.validateDeps(m, ns); err != nil {
		return nil, err
	}
	existedBefore, _ := s.repo.GetPackage(ns.ID, m.PackageName())
	// a package keeps one type for its whole life. A version of another type would
	// be installed and previewed as the wrong kind of entity.
	if existedBefore != nil && existedBefore.Type != m.Type {
		return nil, ErrTypeMismatch
	}
	pkg, err := s.repo.EnsurePackage(ns.ID, m.PackageName(), m.Type)
	if err != nil {
		return nil, err
	}
	// if this publish created the package and then fails before committing a
	// version, remove the empty package so no row without a version is orphaned.
	if existedBefore == nil {
		defer func() {
			if committed {
				return
			}
			// only remove a package that still holds no version, so a package
			// that gained one is never cascade deleted by this cleanup.
			if vs, verr := s.repo.ListVersions(pkg.ID); verr == nil && len(vs) == 0 {
				_, _ = s.repo.DeletePackage(pkg.ID)
			}
		}()
	}
	if existing, _ := s.repo.GetVersion(pkg.ID, m.Version); existing != nil {
		return nil, ErrVersionExists
	}

	manifestJSON, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	v := &database.PackageVersion{
		PackageID:         pkg.ID,
		Version:           m.Version,
		Manifest:          string(manifestJSON),
		MinAppVersion:     m.MinAppVersion,
		ArchiveBlobSHA256: sha,
		ContentHash:       m.ContentHash,
		Size:              size,
		UnpackedSize:      unpacked,
	}
	// a new latest list version must keep serving every list name the packages
	// that depend on it use, with the same kind. A rename, a removal or a change
	// between allow and deny is refused. This reads every dependent archive, so
	// it runs before the transaction and the transaction only confirms that
	// nothing it read changed.
	var listReads *listBreakReads
	if m.Type == manifest.TypeAllowDeny {
		if listReads, err = s.checkListVersionBreaks(m, pkg.ID, v); err != nil {
			return nil, err
		}
	}
	if s.beforeWriteCommit != nil {
		s.beforeWriteCommit()
	}
	// commit the version only if the package still lives at the address the
	// archive names. A move or namespace rename that committed after the reads
	// above would otherwise leave this version filed under an address its
	// manifest disagrees with. The address read runs on the transaction's own
	// connection, so it cannot block on the transaction's lock.
	err = s.repo.Transaction(func(tx *repository.Registry) error {
		nsNow, nameNow, aerr := tx.PackageAddress(pkg.ID)
		if aerr != nil {
			return aerr
		}
		if nsNow != namespaceName || nameNow != m.PackageName() {
			return ErrConcurrentChange
		}
		// the dependency rules ran above on reads made before this transaction.
		// Repeat them on tx, so a namespace visibility change or a package delete
		// that committed in between cannot let a rule breaking version in.
		nsTx, nerr := tx.GetNamespace(namespaceName)
		if nerr != nil {
			return nerr
		}
		derr := s.checkDeps(
			m.Type, nsTx.Name, nsTx.Visibility, m.Dependencies,
			repoVisibility(tx), repoDepType(tx),
		)
		if derr != nil {
			return derr
		}
		// every allow deny list an asset uses must resolve to a pick variable or a
		// list of an allowdeny package this version depends on in its namespace.
		if err := s.checkArchiveAssetLists(namespaceName, m, sha, repoLatest(tx)); err != nil {
			return err
		}
		// Phishing Club refuses a bundle that unpacks to more than its install cap
		// together with the latest version of every reference, or whose shared pick
		// variables disagree with them. A bundle is checked itself; any other package
		// is checked through the bundles that reference it, since this version may
		// become the latest they install.
		if m.Type == manifest.TypeBundle {
			if err := s.checkBundleVersionSize(m.ID, unpacked, m.Dependencies, repoLatest(tx)); err != nil {
				return err
			}
			if err := checkBundleSharedPicks(m, repoLatest(tx)); err != nil {
				return err
			}
		} else {
			vs, lerr := tx.ListVersions(pkg.ID)
			if lerr != nil {
				return lerr
			}
			after := append(vs, *v)
			if err := s.checkDependentBundles(tx, m.ID, after); err != nil {
				return err
			}
			if err := checkDependentBundlePicks(tx, m.ID, after); err != nil {
				return err
			}
			// the list breaks were found before this transaction; confirm that
			// nothing they were found from changed since.
			if listReads != nil {
				if err := verifyListBreakReads(tx, m, listReads); err != nil {
					return err
				}
			}
		}
		if err := tx.CreateVersion(v); err != nil {
			return err
		}
		return tx.InsertBlobIfAbsent(sha, size, mediaType)
	})
	if err != nil {
		return nil, err
	}
	// seed the descriptive fields from the manifest only on the first publish.
	if existedBefore == nil {
		s.seedPackageMeta(pkg.ID, m)
	}
	committed = true
	return v, nil
}

// AuthoredPackage is the content and metadata the UI supplies to author and
// publish a package in one step. Files is the archive payload keyed by path;
// PreviewImages are package level meta images that are not shipped in the archive.
type AuthoredPackage struct {
	Namespace      string
	Name           string
	Type           string
	Version        string
	Title          string
	Description    string
	Preview        string
	Tags           []string
	Variables      []manifest.Variable
	Dependencies   []manifest.Dependency
	ShareVariables *bool
	Files          map[string][]byte
	PreviewImages  [][]byte
}

// AuthorPackage builds the archive from authored content, publishes it as a new
// version, stores any meta preview images, and clears the working draft. It
// returns the published version and the count of preview images that failed to
// store: a bad preview does not fail an otherwise successful publish, but the
// count is returned so the caller can record it rather than silently drop it.
func (s *RegistryService) AuthorPackage(in AuthoredPackage) (*database.PackageVersion, int, error) {
	if in.Type == manifest.TypeBundle {
		if err := validateBundleTemplates(in.Files); err != nil {
			return nil, 0, invalid(err)
		}
	}
	spec := PackageSpec{
		ID: in.Namespace + "/" + in.Name, Type: in.Type, Version: in.Version,
		Title: in.Title, Description: in.Description, Tags: in.Tags,
		Preview:   in.Preview,
		Variables: in.Variables, Dependencies: in.Dependencies, ShareVariables: in.ShareVariables,
	}
	archive, _, err := BuildArchive(spec, in.Files)
	if err != nil {
		return nil, 0, invalid(err)
	}
	v, err := s.Publish(in.Namespace, in.Name, in.Version, "application/gzip", bytes.NewReader(archive))
	if err != nil {
		return nil, 0, err
	}
	failedPreviews := 0
	for _, data := range in.PreviewImages {
		if _, perr := s.AddPreviewImage(in.Namespace, in.Name, data); perr != nil {
			failedPreviews++
		}
	}
	// the version is published, so the working draft is done. a failure to clear it
	// leaves a stale draft only, never a half published package, so it is not fatal.
	_ = s.DeleteDraft(in.Namespace, in.Name)
	return v, failedPreviews, nil
}

// validateDeps enforces the dependency rules that a single manifest cannot check
// on its own. For every package type a dependency must be at least as visible as
// the package that names it, so a public manifest never names a private package.
// A bundle also needs every referenced package to exist and not be a bundle or
// template itself (no nesting).
func (s *RegistryService) validateDeps(m *manifest.Manifest, ns *database.Namespace) error {
	return s.checkDeps(m.Type, ns.Name, ns.Visibility, m.Dependencies, s.liveVisibility, s.liveDepType)
}

// liveVisibility returns a namespace's current visibility, or private when it is
// unknown, so a missing namespace never reads as public.
func (s *RegistryService) liveVisibility(nsName string) string {
	return s.EffectiveVisibility(repoVisibility(s.repo)(nsName))
}

// liveDepType returns the type of the package a dependency resolves to in the
// registry, and whether it resolves at all.
func (s *RegistryService) liveDepType(nsName, name string) (string, bool) {
	return repoDepType(s.repo)(nsName, name)
}

// repoVisibility returns a namespace visibility lookup that reads through r, so
// a transaction can pass its own handle. A missing namespace reads as private.
func repoVisibility(r *repository.Registry) func(string) string {
	return func(nsName string) string {
		if ns, err := r.GetNamespace(nsName); err == nil && ns != nil {
			return ns.Visibility
		}
		return database.VisibilityPrivate
	}
}

// repoDepType returns a dependency lookup that reads through r: the type of the
// package a dependency names and whether it exists with at least one version,
// the same rule Resolve applies for latest.
func repoDepType(r *repository.Registry) func(string, string) (string, bool) {
	return func(nsName, name string) (string, bool) {
		ns, err := r.GetNamespace(nsName)
		if err != nil || ns == nil {
			return "", false
		}
		p, err := r.GetPackage(ns.ID, name)
		if err != nil || p == nil {
			return "", false
		}
		vs, err := r.ListVersions(p.ID)
		if err != nil || len(vs) == 0 {
			return "", false
		}
		return p.Type, true
	}
}

// checkDeps enforces the dependency rules for a package of pkgType living in
// pkgNSName with pkgVisibility. depType resolves a dependency to its package type
// (and whether it exists). A bundle references packages that are not bundles or
// templates. An allow / deny package has no dependencies. Any other package may
// only depend on allow / deny packages in its own namespace, whose lists its
// assets use.
func (s *RegistryService) checkDeps(
	pkgType, pkgNSName, pkgVisibility string,
	deps []manifest.Dependency,
	visibility func(nsName string) string,
	depType func(nsName, name string) (string, bool),
) error {
	if pkgType == manifest.TypeBundle {
		for _, d := range deps {
			dns, dname, ok := splitID(d.ID)
			if !ok {
				return invalidf("invalid dependency id %q", d.ID)
			}
			t, exists := depType(dns, dname)
			if !exists {
				return invalidf("referenced package %q does not exist", d.ID)
			}
			if t == manifest.TypeBundle || t == manifest.TypeTemplate {
				return invalidf("a bundle cannot reference another bundle or template (%q)", d.ID)
			}
		}
	} else if pkgType == manifest.TypeAllowDeny {
		if len(deps) > 0 {
			return invalidf("an allow / deny package cannot have dependencies")
		}
	} else {
		for _, d := range deps {
			dns, dname, ok := splitID(d.ID)
			if !ok {
				return invalidf("invalid dependency id %q", d.ID)
			}
			if dns != pkgNSName {
				return invalidf("the dependency %s is not in the namespace %s; a package can only depend on "+
					"allow / deny packages in its own namespace", d.ID, pkgNSName)
			}
			t, exists := depType(dns, dname)
			if !exists {
				return invalidf("the dependency %s does not exist", d.ID)
			}
			if t != manifest.TypeAllowDeny {
				return invalidf("the dependency %s is a %s package; a package can only depend on allow / deny packages",
					d.ID, t)
			}
		}
	}
	return checkDepVisibility(
		pkgType, pkgNSName, s.EffectiveVisibility(pkgVisibility), deps, s.effectiveLookup(visibility))
}

// checkDepVisibility enforces the visibility invariant for any package type: a
// public package may reference only packages in public namespaces; a private
// package may reference public packages or packages in its own namespace.
// Visibility is a namespace property, so the dependency's namespace visibility is
// what gates it.
func checkDepVisibility(
	pkgType, pkgNSName, pkgVisibility string,
	deps []manifest.Dependency,
	visibility func(nsName string) string,
) error {
	kind := pkgType
	if kind == "" {
		kind = "package"
	}
	for _, d := range deps {
		dns, _, ok := splitID(d.ID)
		if !ok {
			return invalidf("invalid dependency id %q", d.ID)
		}
		depPublic := visibility(dns) == database.VisibilityPublic
		if pkgVisibility == database.VisibilityPublic && !depPublic {
			return invalidf("a public %s cannot reference the private package %q", kind, d.ID)
		}
		if pkgVisibility != database.VisibilityPublic && !depPublic && dns != pkgNSName {
			return invalidf(
				"a private %s can only reference public packages or packages in its own namespace (%q)",
				kind, d.ID,
			)
		}
	}
	return nil
}

// splitID splits a "namespace/name" id.
func splitID(id string) (string, string, bool) {
	i := strings.IndexByte(id, '/')
	if i <= 0 || i == len(id)-1 {
		return "", "", false
	}
	return id[:i], id[i+1:], true
}

// revalidateDeps rechecks the dependency visibility invariant of every version
// of every package against visibility, a lookup that reflects a pending
// namespace visibility change. Every version is checked, not only latest, since
// an older version stays installable by its exact number. It reads through r so
// it can run inside the transaction that applies the change. It returns an error
// naming the first version the change would break, so the change is rejected
// before it is applied.
func revalidateDeps(r *repository.Registry, visibility func(nsName string) string) error {
	pkgs, err := r.ListPackages(nil)
	if err != nil {
		return err
	}
	nss, err := r.ListNamespaces(nil)
	if err != nil {
		return err
	}
	nsNameByID := map[string]string{}
	for i := range nss {
		nsNameByID[nss[i].ID] = nss[i].Name
	}
	for i := range pkgs {
		p := &pkgs[i]
		nsName := nsNameByID[p.NamespaceID]
		versions, verr := r.ListVersions(p.ID)
		if verr != nil {
			return verr
		}
		for j := range versions {
			err := checkVersionDeps(p.Type, nsName, visibility(nsName), &versions[j], visibility)
			if err != nil {
				return fmt.Errorf("%s/%s@%s would break: %w", nsName, p.Name, versions[j].Version, err)
			}
		}
	}
	return nil
}

// checkVersionDeps runs the visibility invariant on one stored version. A stored
// manifest that does not parse fails closed.
func checkVersionDeps(
	pkgType, nsName, nsVisibility string,
	v *database.PackageVersion,
	visibility func(nsName string) string,
) error {
	m, err := manifest.Parse([]byte(v.Manifest))
	if err != nil {
		return fmt.Errorf("stored manifest is unreadable: %w", err)
	}
	if len(m.Dependencies) == 0 {
		return nil
	}
	return checkDepVisibility(pkgType, nsName, nsVisibility, m.Dependencies, visibility)
}

// effectiveLatest returns the version that "latest" resolves to: the highest
// semver version that is not yanked. If every version is yanked it returns the
// highest semver version of all so the package still resolves. Latest is defined
// by semver precedence, not publish order, so publishing a lower version later
// never changes which version is served as latest. Returns nil for an empty
// list.
func effectiveLatest(versions []database.PackageVersion) *database.PackageVersion {
	var latest, latestAny *database.PackageVersion
	for i := range versions {
		v := &versions[i]
		if latestAny == nil || semverLess(latestAny.Version, v.Version) {
			latestAny = v
		}
		if v.Yanked {
			continue
		}
		if latest == nil || semverLess(latest.Version, v.Version) {
			latest = v
		}
	}
	if latest != nil {
		return latest
	}
	return latestAny
}

// semverLess reports whether version a precedes version b by semver ordering.
// Stored versions are validated semver without a leading v, which x/mod/semver
// needs, so both are prefixed before comparing.
func semverLess(a, b string) bool {
	return semver.Compare("v"+a, "v"+b) < 0
}

// Resolve returns the namespace, package and version (or latest when version is
// empty) for a package reference.
func (s *RegistryService) Resolve(
	namespaceName, name, version string,
) (*database.Namespace, *database.Package, *database.PackageVersion, error) {
	ns, err := s.repo.GetNamespace(namespaceName)
	if err != nil {
		return nil, nil, nil, ErrNotFound
	}
	pkg, err := s.repo.GetPackage(ns.ID, name)
	if err != nil {
		return nil, nil, nil, ErrNotFound
	}
	var v *database.PackageVersion
	if version == "" || version == "latest" {
		versions, lerr := s.repo.ListVersions(pkg.ID)
		if lerr != nil || len(versions) == 0 {
			return nil, nil, nil, ErrNotFound
		}
		// a yanked version stays installable by its exact version, so lockfiles
		// keep working, but it is never served as latest.
		v = effectiveLatest(versions)
	} else {
		v, err = s.repo.GetVersion(pkg.ID, version)
		if err != nil {
			return nil, nil, nil, ErrNotFound
		}
	}
	return ns, pkg, v, nil
}

// OpenArchiveNoCount opens a version's archive blob without recording a
// download. Used by the admin UI so an operator inspecting a package does not
// inflate the download stats.
func (s *RegistryService) OpenArchiveNoCount(v *database.PackageVersion) (io.ReadCloser, error) {
	return s.blobs.Open(v.ArchiveBlobSHA256)
}

// OpenArchive returns a reader for a version's archive blob and adds one to its
// download counts. A failed count does not stop the download.
func (s *RegistryService) OpenArchive(v *database.PackageVersion) (io.ReadCloser, error) {
	rc, err := s.blobs.Open(v.ArchiveBlobSHA256)
	if err != nil {
		return nil, err
	}
	if err := s.repo.RecordDownload(v.ID, v.PackageID, time.Now()); err != nil {
		log.Printf("download count: %v", err)
	}
	return rc, nil
}

// ErrNamespaceExists is returned when creating a namespace whose name is taken.
var ErrNamespaceExists = errors.New("a namespace with that name already exists")

// CreateNamespace creates a namespace with its description and color. A name
// that already exists is refused, so a create never changes the visibility or
// description of an existing namespace. A failed description or color write
// still leaves the namespace created.
func (s *RegistryService) CreateNamespace(
	name, description, visibility, color string,
) (*database.Namespace, error) {
	if visibility == database.VisibilityPublic && !s.public {
		return nil, ErrPublicDisabled
	}
	if existing, err := s.repo.GetNamespace(name); err == nil && existing != nil {
		return nil, ErrNamespaceExists
	}
	ns, err := s.repo.EnsureNamespace(name, visibility)
	if err != nil {
		return nil, err
	}
	if description != "" {
		_ = s.UpdateNamespace(ns.ID, description, visibility)
	}
	if color != "" {
		_ = s.repo.SetNamespaceColor(ns.ID, color)
	}
	return ns, nil
}

// NamespaceTotals returns the package count and the download total of every
// namespace, keyed by namespace id.
func (s *RegistryService) NamespaceTotals() (map[string]int, map[string]int64, error) {
	packages, err := s.repo.ListPackages(nil)
	if err != nil {
		return nil, nil, err
	}
	count := map[string]int{}
	downloads := map[string]int64{}
	for i := range packages {
		count[packages[i].NamespaceID]++
		downloads[packages[i].NamespaceID] += packages[i].DownloadCount
	}
	return count, downloads, nil
}

// GetNamespace returns a namespace by name, or gorm.ErrRecordNotFound if absent.
func (s *RegistryService) GetNamespace(name string) (*database.Namespace, error) {
	return s.repo.GetNamespace(name)
}

// GetNamespaceByID returns a namespace by its id.
func (s *RegistryService) GetNamespaceByID(id string) (*database.Namespace, error) {
	return s.repo.GetNamespaceByID(id)
}

// ErrNamespaceNotEmpty is returned when deleting a namespace that owns packages.
var ErrNamespaceNotEmpty = errors.New("namespace still has packages")

// ErrVisibilityRefused is returned when a namespace visibility change would
// break the dependency visibility invariant of a stored version.
var ErrVisibilityRefused = errors.New("visibility change refused")

// UpdateNamespace runs the visibility check and the write in one transaction,
// so a publish cannot add a version the change would break between the two.
func (s *RegistryService) UpdateNamespace(id, description, visibility string) error {
	if err := model.ValidateNamespaceDescription(description); err != nil {
		return err
	}
	if visibility == database.VisibilityPublic && !s.public {
		return ErrPublicDisabled
	}
	return s.repo.Transaction(func(tx *repository.Registry) error {
		ns, err := tx.GetNamespaceByID(id)
		if err != nil || ns == nil {
			return ErrNotFound
		}
		// a visibility change can break the dependency invariant (a public package
		// may only reference public namespaces). recheck every version of every
		// package against the pending visibility and reject the change if it would
		// break one, since nothing validates dependencies again after the fact.
		if s.EffectiveVisibility(visibility) != s.EffectiveVisibility(ns.Visibility) {
			live := repoVisibility(tx)
			pending := s.effectiveLookup(func(n string) string {
				if n == ns.Name {
					return visibility
				}
				return live(n)
			})
			if err := revalidateDeps(tx, pending); err != nil {
				return fmt.Errorf("%w: %v", ErrVisibilityRefused, err)
			}
		}
		return tx.UpdateNamespace(id, description, visibility)
	})
}

// SetNamespaceColor sets a namespace color label (an allowlisted token, or empty).
func (s *RegistryService) SetNamespaceColor(id, color string) error {
	return s.repo.SetNamespaceColor(id, color)
}

// DeleteNamespace removes a namespace only when it owns no packages, and drops
// its name from every token's namespace scope. Otherwise a token scoped to the
// deleted name would silently gain access to a namespace created later under the
// same name.
func (s *RegistryService) DeleteNamespace(id string) error {
	ns, err := s.repo.GetNamespaceByID(id)
	if err != nil || ns == nil {
		return ErrNotFound
	}
	n, err := s.repo.CountPackagesInNamespace(id)
	if err != nil {
		return err
	}
	if n > 0 {
		return ErrNamespaceNotEmpty
	}
	return s.repo.Transaction(func(tx *repository.Registry) error {
		// a publish may have filed a package here after the count above. This
		// count runs on the transaction's own connection, so it cannot block.
		if n, err := tx.CountPackagesInNamespace(id); err != nil {
			return err
		} else if n > 0 {
			return ErrNamespaceNotEmpty
		}
		// the token scopes are read on the transaction's connection too, so a token
		// created or edited just before cannot be overwritten with a stale scope.
		scopes, err := tx.TokenEntitlementsWithout(ns.Name)
		if err != nil {
			return err
		}
		if err := tx.DeleteNamespace(id); err != nil {
			return err
		}
		for tokenID, ent := range scopes {
			if err := tx.SetTokenEntitlements(tokenID, ent); err != nil {
				return err
			}
		}
		return nil
	})
}

// cleanupBlob removes a blob file and row when no row references it and no
// operation in flight holds a pin on it. The blob store runs the check and the
// removal under its lock so a concurrent Put of the same bytes is never lost.
func (s *RegistryService) cleanupBlob(sha string) {
	s.blobs.RemoveIfUnreferenced(sha, s.repo.BlobReferenced, func(sha string) {
		_ = s.repo.DeleteBlobRecord(sha)
	})
}

// releaseBlobs drops the pins Put took on each sha.
func (s *RegistryService) releaseBlobs(shas []string) {
	for _, sha := range shas {
		if sha != "" {
			s.blobs.Release(sha)
		}
	}
}

// cleanupBlobs removes each distinct sha that no row references any more. Used
// after a move or rename to drop the versions' superseded blobs, or to clear the
// blobs a rolled back move wrote.
func (s *RegistryService) cleanupBlobs(shas []string) {
	seen := map[string]bool{}
	for _, sha := range shas {
		if sha == "" || seen[sha] {
			continue
		}
		seen[sha] = true
		s.cleanupBlob(sha)
	}
}

// DependentsError refuses deleting a package that other packages depend on. It
// names them, so the operator knows what to change first.
type DependentsError struct {
	Package    string
	Dependents []string
}

func (e *DependentsError) Error() string {
	return fmt.Sprintf("%s is used by %s; delete those packages, or their versions that use it, first",
		e.Package, strings.Join(e.Dependents, ", "))
}

// DeletePackage removes a package and all its versions, cleaning up orphaned
// blobs. A package another package depends on is refused with a
// DependentsError, so no stored version is left naming an address that a new
// package, maybe a private one, could take later. The check and the delete run
// in one transaction, so a publish cannot add a dependent between them.
func (s *RegistryService) DeletePackage(nsName, name string) error {
	var shas []string
	err := s.repo.Transaction(func(tx *repository.Registry) error {
		ns, err := tx.GetNamespace(nsName)
		if err != nil || ns == nil {
			return ErrNotFound
		}
		pkg, err := tx.GetPackage(ns.ID, name)
		if err != nil {
			return ErrNotFound
		}
		deps, err := dependentsOf(tx, nsName+"/"+name)
		if err != nil {
			return err
		}
		if len(deps) > 0 {
			return &DependentsError{Package: nsName + "/" + name, Dependents: deps}
		}
		// the shas cover the version archives and the preview images.
		shas, err = tx.DeletePackage(pkg.ID)
		return err
	})
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, sha := range shas {
		if !seen[sha] {
			seen[sha] = true
			s.cleanupBlob(sha)
		}
	}
	s.pruneTags()
	return nil
}

// --- Package preview images (package meta, not archive content) ---

// MaxPreviewImages caps the gallery so a package page stays readable. The
// backend enforces it on add; the UI reads it to disable adding at the limit.
const MaxPreviewImages = 8

// allowedPreviewMediaType reports whether a preview image type is permitted.
// Raster only; svg and anything else is rejected because it can carry script.
// Used by both authoring and bundle import so the two agree.
func allowedPreviewMediaType(mt string) bool {
	switch mt {
	case "image/png", "image/jpeg", "image/gif", "image/webp":
		return true
	}
	return false
}

// AddPreviewImage stores an image as package level preview metadata: a standalone
// content addressed blob that is never part of a version archive or the content
// hash, so preview imagery can be curated without publishing a new version. The
// type is read from the bytes.
func (s *RegistryService) AddPreviewImage(nsName, name string, data []byte) (string, error) {
	mediaType, err := checkPreviewImage(data)
	if err != nil {
		return "", err
	}
	ns, err := s.repo.GetNamespace(nsName)
	if err != nil {
		return "", ErrNotFound
	}
	pkg, err := s.repo.GetPackage(ns.ID, name)
	if err != nil {
		return "", ErrNotFound
	}
	n, err := s.repo.CountPackagePreviews(pkg.ID)
	if err != nil {
		return "", err
	}
	if n >= MaxPreviewImages {
		return "", invalidf("a package can have at most %d preview images", MaxPreviewImages)
	}
	sha, size, err := s.blobs.Put(bytes.NewReader(data), MaxPreviewBytes)
	if err != nil {
		return "", err
	}
	err = s.repo.UpsertBlob(sha, size, mediaType)
	if err == nil {
		err = s.repo.AddPackagePreview(pkg.ID, sha, mediaType, int(n))
	}
	s.blobs.Release(sha)
	if err != nil {
		s.cleanupBlob(sha)
		return "", err
	}
	return sha, nil
}

// PreviewsByPackageID lists previews for an already resolved package id (listings).
func (s *RegistryService) PreviewsByPackageID(pkgID string) ([]database.PackagePreview, error) {
	return s.repo.ListPackagePreviews(pkgID)
}

// ReorderPreviews sets the gallery order of a package's preview images to the
// given sequence of blob shas. Shas not belonging to the package are ignored.
func (s *RegistryService) ReorderPreviews(nsName, name string, shas []string) error {
	ns, err := s.repo.GetNamespace(nsName)
	if err != nil {
		return ErrNotFound
	}
	pkg, err := s.repo.GetPackage(ns.ID, name)
	if err != nil {
		return ErrNotFound
	}
	return s.repo.SetPackagePreviewOrder(pkg.ID, shas)
}

// OpenPreview returns a reader and media type for a preview image, confirming the
// blob really is a preview of this package before serving it.
func (s *RegistryService) OpenPreview(nsName, name, sha string) (io.ReadCloser, string, error) {
	ns, err := s.repo.GetNamespace(nsName)
	if err != nil {
		return nil, "", ErrNotFound
	}
	pkg, err := s.repo.GetPackage(ns.ID, name)
	if err != nil {
		return nil, "", ErrNotFound
	}
	pv, err := s.repo.GetPackagePreview(pkg.ID, sha)
	if err != nil {
		return nil, "", ErrNotFound
	}
	rc, err := s.blobs.Open(sha)
	if err != nil {
		return nil, "", ErrNotFound
	}
	return rc, pv.MediaType, nil
}

// DeletePreview removes one preview image and cleans up its blob.
func (s *RegistryService) DeletePreview(nsName, name, sha string) error {
	ns, err := s.repo.GetNamespace(nsName)
	if err != nil {
		return ErrNotFound
	}
	pkg, err := s.repo.GetPackage(ns.ID, name)
	if err != nil {
		return ErrNotFound
	}
	if err := s.repo.DeletePackagePreview(pkg.ID, sha); err != nil {
		return err
	}
	s.cleanupBlob(sha)
	return nil
}

// VersionWarnings is what a yank, unyank or version delete breaks, which the
// change is never refused for: the bundles that now unpack to more than the
// install cap, and the packages whose asset lists no longer resolve.
type VersionWarnings struct {
	BundlesOverCap []string
	AssetLists     []string
}

// YankVersion sets or clears the yanked flag on a version. It is never refused
// for the bundle install cap or for the packages that use its lists, so a broken
// version can always be yanked. It returns what the change broke, so the caller
// can warn about it.
func (s *RegistryService) YankVersion(nsName, name, version string, yanked bool) (VersionWarnings, error) {
	_, pkg, v, err := s.Resolve(nsName, name, version)
	if err != nil {
		return VersionWarnings{}, err
	}
	before, _ := s.repo.ListVersions(pkg.ID)
	if err := s.repo.YankVersion(v.ID, yanked); err != nil {
		return VersionWarnings{}, err
	}
	return s.versionWarnings(pkg, nsName+"/"+name, before), nil
}

// versionWarnings collects the warnings for a change already applied to the
// versions of pkg, given the version list before it.
func (s *RegistryService) versionWarnings(
	pkg *database.Package, id string, before []database.PackageVersion,
) VersionWarnings {
	w := VersionWarnings{BundlesOverCap: s.bundleCapWarnings(pkg, id, before)}
	if pkg.Type == manifest.TypeAllowDeny && before != nil {
		after, err := s.repo.ListVersions(pkg.ID)
		if err != nil {
			w.AssetLists = []string{fmt.Sprintf("could not check the packages that use the lists of %s: %v", id, err)}
			return w
		}
		w.AssetLists = s.assetListWarnings(id, withVersions(id, before, repoLatest(s.repo)), after)
	}
	return w
}

// seedPackageMeta sets the package's descriptive fields from the manifest once, when
// the package is created. After that they are edited directly (UpdatePackageMeta) and
// a new version does not reset them, so the metadata is decoupled from any version.
func (s *RegistryService) seedPackageMeta(pkgID string, m *manifest.Manifest) {
	title, desc, tags := seedMeta(m)
	_ = s.repo.UpdatePackageMeta(pkgID, title, desc, tags)
}

// UpdatePackageMeta edits metadata without publishing a new version; the per
// version manifests are untouched.
func (s *RegistryService) UpdatePackageMeta(nsName, name, title, description, tags string) error {
	ns, err := s.repo.GetNamespace(nsName)
	if err != nil {
		return ErrNotFound
	}
	pkg, err := s.repo.GetPackage(ns.ID, name)
	if err != nil {
		return ErrNotFound
	}
	if err := s.repo.UpdatePackageMeta(pkg.ID, title, description, tags); err != nil {
		return err
	}
	s.pruneTags()
	return nil
}

// DeleteVersion removes one version and cleans up the archive blob if nothing
// else references it. Like YankVersion it is never refused for the bundle
// install cap or for the packages that use its lists, and returns what the
// change broke. The only version of a package is refused with ErrLastVersion.
func (s *RegistryService) DeleteVersion(nsName, name, version string) (VersionWarnings, error) {
	_, pkg, v, err := s.Resolve(nsName, name, version)
	if err != nil {
		return VersionWarnings{}, err
	}
	before, err := s.repo.ListVersions(pkg.ID)
	if err != nil {
		return VersionWarnings{}, err
	}
	sha, err := s.repo.DeleteVersion(v.ID)
	// a package with no version would still be listed but resolve to nothing.
	if errors.Is(err, repository.ErrLastVersion) {
		return VersionWarnings{}, ErrLastVersion
	}
	if err != nil {
		return VersionWarnings{}, err
	}
	w := s.versionWarnings(pkg, nsName+"/"+name, before)
	s.cleanupBlob(sha)
	return w, nil
}

// DependentsOf returns the ids (namespace/name) of packages with any stored
// version that declares a dependency on the given package. A delete is refused
// while there are any, and a move warns that it breaks them.
func (s *RegistryService) DependentsOf(nsName, name string) ([]string, error) {
	return dependentsOf(s.repo, nsName+"/"+name)
}

// dependentsOf reads through r, so a caller inside a transaction stays on its
// handle.
func dependentsOf(r *repository.Registry, targetID string) ([]string, error) {
	pkgs, err := r.ListPackages(nil)
	if err != nil {
		return nil, err
	}
	nss, err := r.ListNamespaces(nil)
	if err != nil {
		return nil, err
	}
	nameByNS := map[string]string{}
	for i := range nss {
		nameByNS[nss[i].ID] = nss[i].Name
	}
	var out []string
	for i := range pkgs {
		p := &pkgs[i]
		selfID := nameByNS[p.NamespaceID] + "/" + p.Name
		if selfID == targetID {
			continue
		}
		versions, err := r.ListVersions(p.ID)
		if err != nil {
			return nil, err
		}
		if versionsDependOn(versions, targetID) {
			out = append(out, selfID)
		}
	}
	return out, nil
}

// versionsDependOn reports whether any of the versions declares targetID as a
// dependency. A manifest that does not parse names nothing an install could use.
func versionsDependOn(versions []database.PackageVersion, targetID string) bool {
	for j := range versions {
		m, err := manifest.Parse([]byte(versions[j].Manifest))
		if err != nil {
			continue
		}
		for _, d := range m.Dependencies {
			if d.ID == targetID {
				return true
			}
		}
	}
	return false
}

// Namespaces lists namespaces. A nil q returns every row.
func (s *RegistryService) Namespaces(q *repository.QueryArgs) ([]database.Namespace, error) {
	return s.repo.ListNamespaces(q)
}

// CountNamespaces returns the total matching q's search filter, for paging.
func (s *RegistryService) CountNamespaces(q *repository.QueryArgs) (int64, error) {
	return s.repo.CountNamespaces(q)
}

// Packages lists packages. A nil q returns every row.
func (s *RegistryService) Packages(q *repository.QueryArgs) ([]database.Package, error) {
	return s.repo.ListPackages(q)
}

// CountPackages returns the total matching q's search filter, for paging.
func (s *RegistryService) CountPackages(q *repository.QueryArgs) (int64, error) {
	return s.repo.CountPackages(q)
}

// Versions lists a package's versions.
func (s *RegistryService) Versions(packageID string) ([]database.PackageVersion, error) {
	return s.repo.ListVersions(packageID)
}

// CurrentVersion returns the effective latest (highest non yanked semver) version
// string for a package, or "" when it has none.
func (s *RegistryService) CurrentVersion(packageID string) string {
	versions, err := s.Versions(packageID)
	if err != nil {
		return ""
	}
	if lv := effectiveLatest(versions); lv != nil {
		return lv.Version
	}
	return ""
}

// SaveDraft stores an unpublished authoring payload for a package address.
func (s *RegistryService) SaveDraft(d *database.Draft) error {
	return s.repo.UpsertDraft(d)
}

// ListDrafts returns the saved drafts, newest first.
func (s *RegistryService) ListDrafts() ([]database.Draft, error) {
	return s.repo.ListDrafts()
}

// GetDraft returns one draft by package address.
func (s *RegistryService) GetDraft(namespace, name string) (*database.Draft, error) {
	d, err := s.repo.GetDraft(namespace, name)
	if err != nil {
		return nil, ErrNotFound
	}
	return d, nil
}

// DeleteDraft removes the draft for a package address.
func (s *RegistryService) DeleteDraft(namespace, name string) error {
	return s.repo.DeleteDraft(namespace, name)
}

// ListTags returns the tag color registry.
func (s *RegistryService) ListTags() ([]database.Tag, error) {
	return s.repo.ListTags()
}

// TagInfo is one tag in use with its color, empty when none is set.
type TagInfo struct {
	Name  string
	Color string
}

// ListTagsInUse returns every tag some package carries, sorted by name, each
// with its color from the tag color registry when one is set. A tag with no
// color row is still listed, so the tag browser shows every tag in use. Both
// reads share one transaction so a tag and its color come from the same state.
func (s *RegistryService) ListTagsInUse() ([]TagInfo, error) {
	var out []TagInfo
	err := s.repo.Transaction(func(tx *repository.Registry) error {
		names, err := tx.ListUsedTagNames()
		if err != nil {
			return err
		}
		rows, err := tx.ListTags()
		if err != nil {
			return err
		}
		colors := make(map[string]string, len(rows))
		for i := range rows {
			colors[rows[i].Name] = rows[i].Color
		}
		out = make([]TagInfo, 0, len(names))
		for _, n := range names {
			out = append(out, TagInfo{Name: n, Color: colors[n]})
		}
		return nil
	})
	return out, err
}

// ErrTagNotInUse is returned when a color is set for a tag no package carries.
var ErrTagNotInUse = errors.New("no package uses that tag")

// SetTagColor sets the global color for a tag name. The tag must be carried by at
// least one package, so the color table only ever holds tags in use. The check
// and the write share one transaction, and tag rows no package uses any more are
// removed in the same step.
func (s *RegistryService) SetTagColor(name, color string) error {
	return s.repo.Transaction(func(tx *repository.Registry) error {
		used, err := tx.TagInUse(name)
		if err != nil {
			return err
		}
		if !used {
			return ErrTagNotInUse
		}
		if err := tx.UpsertTagColor(name, color); err != nil {
			return err
		}
		return tx.PruneUnusedTags()
	})
}

// pruneTags removes tag color rows no package carries any more. It runs after a
// package is deleted or its tags change; a failure only leaves a stale color
// row, so it is not reported to the caller.
func (s *RegistryService) pruneTags() {
	_ = s.repo.Transaction(func(tx *repository.Registry) error {
		return tx.PruneUnusedTags()
	})
}

// MovePackage moves a package to another namespace and optionally renames it. The
// package address is part of the id embedded in every version's archive manifest,
// so each version is repacked under the new id; the payload (content and assets) is
// unchanged, so the content hash stays the same. toName empty keeps the current
// name. The target namespace must exist and must not already have a package of the
// target name.
func (s *RegistryService) MovePackage(fromNs, name, toNs, toName string) error {
	fromNs = strings.TrimSpace(fromNs)
	toNs = strings.TrimSpace(toNs)
	toName = strings.TrimSpace(toName)
	if toNs == "" {
		return invalidf("a target namespace is required")
	}
	if toName == "" {
		toName = name
	}
	if fromNs == toNs && toName == name {
		return nil
	}
	srcNs, err := s.repo.GetNamespace(fromNs)
	if err != nil {
		return ErrNotFound
	}
	pkg, err := s.repo.GetPackage(srcNs.ID, name)
	if err != nil {
		return ErrNotFound
	}
	dstNs, err := s.repo.GetNamespace(toNs)
	if err != nil {
		return invalidf("target namespace %q does not exist", toNs)
	}
	if existing, _ := s.repo.GetPackage(dstNs.ID, toName); existing != nil && existing.ID != pkg.ID {
		return invalidf("a package named %q already exists in %q", toName, toNs)
	}
	versions, err := s.repo.ListVersions(pkg.ID)
	if err != nil {
		return err
	}
	// a package other than a bundle can only depend on allow / deny packages in
	// its own namespace, so moving one that has such dependencies would leave them
	// in the old namespace.
	if fromNs != toNs && pkg.Type != manifest.TypeBundle {
		for i := range versions {
			m, perr := manifest.Parse([]byte(versions[i].Manifest))
			if perr != nil {
				return fmt.Errorf("stored manifest of %s@%s is unreadable: %w", fromNs+"/"+name, versions[i].Version, perr)
			}
			if len(m.Dependencies) > 0 {
				return invalidf("version %s depends on the allow / deny package %s in %s, and a package can only "+
					"depend on lists in its own namespace; move or recreate the lists in %s first and publish a "+
					"version that uses them, or delete the versions that depend on %s",
					versions[i].Version, m.Dependencies[0].ID, fromNs, toNs, fromNs)
			}
		}
	}
	// moving into a namespace of different visibility can break the dependency
	// invariant (a public package may only reference public namespaces), so
	// recheck every version against the destination before moving.
	for i := range versions {
		if err := checkVersionDeps(
			pkg.Type, toNs, s.EffectiveVisibility(dstNs.Visibility), &versions[i], s.liveVisibility); err != nil {
			return fmt.Errorf("move would break version %s: %w", versions[i].Version, err)
		}
	}
	plannedIDs := versionIDSet(versions)
	newID := toNs + "/" + toName
	// build every repacked archive first (reads + blob writes), then apply the row
	// changes in one transaction. Only reads on tx run inside it, so it cannot
	// deadlock against its own write lock.
	plans := make([]repackPlan, 0, len(versions))
	for i := range versions {
		pl, berr := s.buildRepack(fromNs, name, newID, nil, &versions[i])
		if berr != nil {
			s.releaseBlobs(repackNewShas(plans))
			s.cleanupBlobs(repackNewShas(plans))
			return berr
		}
		plans = append(plans, pl)
	}
	if s.beforeRepackCommit != nil {
		s.beforeRepackCommit()
	}
	err = s.repo.Transaction(func(tx *repository.Registry) error {
		// a publish or another move may have committed since the plans were built.
		// These reads run on the transaction's own connection, so they cannot block.
		nsNow, nameNow, aerr := tx.PackageAddress(pkg.ID)
		if aerr != nil {
			return aerr
		}
		if nsNow != fromNs || nameNow != name {
			return ErrConcurrentChange
		}
		ids, ierr := tx.VersionIDs(pkg.ID)
		if ierr != nil {
			return ierr
		}
		if !slices.Equal(ids, plannedIDs) {
			return ErrConcurrentChange
		}
		// the destination visibility check above read outside this transaction, so
		// repeat it on tx against the destination as it is now.
		dstNow, derr := tx.GetNamespaceByID(dstNs.ID)
		if derr != nil {
			return ErrConcurrentChange
		}
		live := s.effectiveLookup(repoVisibility(tx))
		for i := range versions {
			err := checkVersionDeps(
				pkg.Type, dstNow.Name, s.EffectiveVisibility(dstNow.Visibility), &versions[i], live)
			if err != nil {
				return fmt.Errorf("move would break version %s: %w", versions[i].Version, err)
			}
		}
		for _, pl := range plans {
			if err := applyRepack(tx, pl); err != nil {
				return err
			}
		}
		if err := tx.SetPackageNamespace(pkg.ID, dstNs.ID); err != nil {
			return err
		}
		if toName != name {
			if err := tx.SetPackageName(pkg.ID, toName); err != nil {
				return err
			}
		}
		return nil
	})
	s.releaseBlobs(repackNewShas(plans))
	if err != nil {
		// the move rolled back, so the blobs it wrote are unreferenced: remove them.
		s.cleanupBlobs(repackNewShas(plans))
		return err
	}
	// the move committed, so each version's previous blob may be unreferenced now.
	s.cleanupBlobs(repackOldShas(plans))
	return nil
}

// repackPlan is a prepared archive rewrite for one version: the new blob is
// already written to the store, and applyRepack commits the row change inside a
// transaction. oldSha is the version's previous blob, cleaned up after commit.
type repackPlan struct {
	versionID    string
	manifestJSON string
	newSha       string
	size         int64
	unpacked     int64
	contentHash  string
	oldSha       string
}

// buildRepack rebuilds one version's archive under newID and writes the new blob
// to the store, returning the row write it implies. It does only reads and the
// archive build, so the caller can run every buildRepack BEFORE opening the
// transaction: a read must never run while the move or rename transaction holds
// the database write lock, or it deadlocks against its own writer.
//
// The package rows are not touched here; the caller updates the namespace or
// name. fromNsName and pkgName locate the current content, read from committed
// state. rewriteDep, when set, maps each dependency id to its new form (used by a
// namespace rename so a bundle keeps pointing at a sibling that moved with it);
// nil leaves dependencies untouched.
func (s *RegistryService) buildRepack(
	fromNsName, pkgName, newID string,
	rewriteDep func(string) string,
	v *database.PackageVersion,
) (repackPlan, error) {
	_, oldM, files, verr := s.VersionContent(fromNsName, pkgName, v.Version)
	if verr != nil {
		return repackPlan{}, verr
	}
	deps := oldM.Dependencies
	if rewriteDep != nil && len(deps) > 0 {
		nd := make([]manifest.Dependency, len(deps))
		for i, d := range deps {
			nd[i] = manifest.Dependency{ID: rewriteDep(d.ID), Range: d.Range}
		}
		deps = nd
	}
	spec := PackageSpec{
		ID: newID, Type: oldM.Type, Version: oldM.Version, Title: oldM.Title,
		Description: oldM.Description, Tags: oldM.Tags,
		MinAppVersion: oldM.MinAppVersion, Preview: oldM.Preview,
		Dependencies: deps, Variables: oldM.Variables, ShareVariables: oldM.ShareVariables,
	}
	archive, newM, berr := BuildArchive(spec, files)
	if berr != nil {
		return repackPlan{}, invalidf("version %s cannot be rebuilt: %w", v.Version, berr)
	}
	// marshal and measure before Put, so no error path after Put can leave its
	// pin held. The manifest changed, so the unpacked size changes with it.
	mj, merr := json.Marshal(newM)
	if merr != nil {
		return repackPlan{}, merr
	}
	unpacked, uerr := archiveUnpackedSize(bytes.NewReader(archive))
	if uerr != nil {
		return repackPlan{}, uerr
	}
	sha, size, perr := s.blobs.Put(bytes.NewReader(archive), s.maxDownload)
	if perr != nil {
		return repackPlan{}, perr
	}
	return repackPlan{
		versionID: v.ID, manifestJSON: string(mj), newSha: sha, size: size,
		unpacked: unpacked, contentHash: newM.ContentHash, oldSha: v.ArchiveBlobSHA256,
	}, nil
}

// applyRepack commits one prepared repack on tx: it writes only, so it is safe to
// run inside the transaction.
func applyRepack(tx *repository.Registry, p repackPlan) error {
	if err := tx.UpsertBlob(p.newSha, p.size, "application/gzip"); err != nil {
		return err
	}
	return tx.UpdateVersionArchive(repository.VersionArchive{
		VersionID:    p.versionID,
		ManifestJSON: p.manifestJSON,
		ArchiveSHA:   p.newSha,
		ContentHash:  p.contentHash,
		UnpackedSize: p.unpacked,
	})
}

// repackNewShas and repackOldShas pull the blob lists out of a set of plans for
// post transaction cleanup (new blobs on rollback, superseded blobs on commit).
func repackNewShas(plans []repackPlan) []string {
	out := make([]string, len(plans))
	for i, p := range plans {
		out[i] = p.newSha
	}
	return out
}

func repackOldShas(plans []repackPlan) []string {
	out := make([]string, len(plans))
	for i, p := range plans {
		out[i] = p.oldSha
	}
	return out
}

// versionIDSet returns the sorted ids of a version list.
func versionIDSet(versions []database.PackageVersion) []string {
	ids := make([]string, len(versions))
	for i := range versions {
		ids[i] = versions[i].ID
	}
	sort.Strings(ids)
	return ids
}

// RenameNamespace changes a namespace's name, which changes the address of every
// package it owns from oldName/<pkg> to newName/<pkg>. Each version is repacked so
// its manifest id and content hash match the new address, a bundle in the renamed
// namespace keeps pointing at its siblings, and tokens scoped to the old name
// follow the rename. Old addresses stop resolving (there is no redirect), so
// consumers that installed from the old address must reinstall from the new one
// and external bundles that referenced the old address must be republished.
func (s *RegistryService) RenameNamespace(oldName, newName string) error {
	oldName = strings.TrimSpace(oldName)
	newName = strings.TrimSpace(newName)
	if newName == "" {
		return invalidf("a new namespace name is required")
	}
	if oldName == newName {
		return nil
	}
	ns, err := s.repo.GetNamespace(oldName)
	if err != nil {
		return ErrNotFound
	}
	if existing, _ := s.repo.GetNamespace(newName); existing != nil {
		return ErrNamespaceExists
	}
	all, err := s.repo.ListPackages(nil)
	if err != nil {
		return err
	}
	// rewrite a dependency id that points at the old namespace to the new one, so a
	// bundle that references a sibling in this namespace stays valid after the rename.
	rewrite := func(id string) string {
		if i := strings.IndexByte(id, '/'); i >= 0 && id[:i] == oldName {
			return newName + "/" + id[i+1:]
		}
		return id
	}
	// build every package's repacked archives first (reads + blob writes), reading
	// content by the old address, then apply all row changes in one transaction.
	// Only reads on tx run inside it, so it cannot deadlock against its lock.
	var plans []repackPlan
	var plannedIDs []string
	abort := func(err error) error {
		s.releaseBlobs(repackNewShas(plans))
		s.cleanupBlobs(repackNewShas(plans))
		return err
	}
	for i := range all {
		p := &all[i]
		if p.NamespaceID != ns.ID {
			continue
		}
		versions, verr := s.repo.ListVersions(p.ID)
		if verr != nil {
			return abort(verr)
		}
		newID := newName + "/" + p.Name
		for j := range versions {
			plannedIDs = append(plannedIDs, versions[j].ID)
			pl, berr := s.buildRepack(oldName, p.Name, newID, rewrite, &versions[j])
			if berr != nil {
				return abort(berr)
			}
			plans = append(plans, pl)
		}
	}
	sort.Strings(plannedIDs)
	if s.beforeRepackCommit != nil {
		s.beforeRepackCommit()
	}
	err = s.repo.Transaction(func(tx *repository.Registry) error {
		// a publish, move or rename may have committed since the plans were built.
		// These reads run on the transaction's own connection, so they cannot block.
		nsNow, gerr := tx.GetNamespaceByID(ns.ID)
		if gerr != nil {
			return gerr
		}
		if nsNow.Name != oldName {
			return ErrConcurrentChange
		}
		ids, ierr := tx.VersionIDsInNamespace(ns.ID)
		if ierr != nil {
			return ierr
		}
		if !slices.Equal(ids, plannedIDs) {
			return ErrConcurrentChange
		}
		for _, pl := range plans {
			if err := applyRepack(tx, pl); err != nil {
				return err
			}
		}
		// the new name must still be free: a create or rename may have taken it
		// since the check above.
		if taken, terr := tx.NamespaceNameTaken(newName); terr != nil {
			return terr
		} else if taken {
			return ErrNamespaceExists
		}
		// flip the name only after every archive is repacked, since repack reads the
		// content by the old address.
		if err := tx.RenameNamespace(ns.ID, newName); err != nil {
			return err
		}
		// no namespace had the new name, so a token scope naming it grants nothing
		// today. Drop it, so the rename cannot hand that token this namespace.
		stale, err := tx.TokenEntitlementsWithout(newName)
		if err != nil {
			return err
		}
		for tokenID, ent := range stale {
			if err := tx.SetTokenEntitlements(tokenID, ent); err != nil {
				return err
			}
		}
		// a token scoped to this namespace keeps working under the new name.
		if _, err := tx.RewriteNamespaceInTokens(oldName, newName); err != nil {
			return err
		}
		return nil
	})
	s.releaseBlobs(repackNewShas(plans))
	if err != nil {
		// the rename rolled back, so drop any blob it wrote: nothing references them.
		s.cleanupBlobs(repackNewShas(plans))
		return err
	}
	// the rename committed, so the versions' previous blobs may be unreferenced now.
	s.cleanupBlobs(repackOldShas(plans))
	return nil
}

// NamespaceRenameImpact reports the consequences of renaming a namespace, so the
// operator can see them before confirming: how many packages change address, the
// external packages (in other namespaces) whose latest version depends on a
// package here and would break because the old address stops resolving, and how
// many tokens are scoped to this namespace and would follow the rename.
func (s *RegistryService) NamespaceRenameImpact(oldName string) (int, []string, int, error) {
	ns, err := s.repo.GetNamespace(oldName)
	if err != nil {
		return 0, nil, 0, ErrNotFound
	}
	all, err := s.repo.ListPackages(nil)
	if err != nil {
		return 0, nil, 0, err
	}
	nss, err := s.repo.ListNamespaces(nil)
	if err != nil {
		return 0, nil, 0, err
	}
	nameByNS := map[string]string{}
	for i := range nss {
		nameByNS[nss[i].ID] = nss[i].Name
	}
	pkgCount := 0
	var externalDependents []string
	for i := range all {
		p := &all[i]
		if p.NamespaceID == ns.ID {
			pkgCount++
			continue
		}
		versions, verr := s.repo.ListVersions(p.ID)
		if verr != nil || len(versions) == 0 {
			continue
		}
		lv := effectiveLatest(versions)
		if lv == nil {
			continue
		}
		m, perr := manifest.Parse([]byte(lv.Manifest))
		if perr != nil {
			continue
		}
		for _, d := range m.Dependencies {
			if j := strings.IndexByte(d.ID, '/'); j >= 0 && d.ID[:j] == oldName {
				externalDependents = append(externalDependents, nameByNS[p.NamespaceID]+"/"+p.Name)
				break
			}
		}
	}
	tokensAffected, _ := s.repo.CountTokensScopedTo(oldName)
	return pkgCount, externalDependents, tokensAffected, nil
}
