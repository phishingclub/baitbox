package service

import (
	"path/filepath"
	"testing"

	"gorm.io/gorm"

	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/manifest"
	"github.com/phishingclub/baitbox/repository"
)

// newTestDB opens a temp on-disk SQLite database with every entity migrated. No
// network, no docker, no shared fixtures.
func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := database.Open(filepath.Join(t.TempDir(), "reg.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	return db
}

// registryOverDB builds a RegistryService over an existing database and a fresh
// temp blob store. The caps match the config defaults so the tests exercise the
// same limits production runs with. A test that needs direct database access
// (tokens, sessions) builds the db first and shares it with the service. The
// registry is public, so the visibility rules between namespaces apply.
func registryOverDB(t *testing.T, db *gorm.DB) *RegistryService {
	t.Helper()
	return registryOverDBPublic(t, db, true)
}

// registryOverDBPublic is registryOverDB with the registry.public flag given.
func registryOverDBPublic(t *testing.T, db *gorm.DB, public bool) *RegistryService {
	t.Helper()
	blobs, err := NewBlobStore(t.TempDir())
	if err != nil {
		t.Fatalf("blob store: %v", err)
	}
	repo := repository.NewRegistry(db)
	return NewRegistryService(RegistryDeps{
		Repo: repo, Blobs: blobs, MaxDownload: 64 << 20, MaxFile: 128 << 20, Public: public,
	})
}

// newTestRegistry builds a RegistryService over a fresh temp database and blob
// store, for tests that do not need the db handle directly.
func newTestRegistry(t *testing.T) *RegistryService {
	t.Helper()
	return registryOverDB(t, newTestDB(t))
}

// mustEnsureNS pre-creates a namespace with an explicit visibility, since a
// namespace created implicitly by publish inherits the default (private).
func mustEnsureNS(t *testing.T, svc *RegistryService, name, visibility string) *database.Namespace {
	t.Helper()
	ns, err := svc.repo.EnsureNamespace(name, visibility)
	if err != nil {
		t.Fatalf("ensure namespace %s: %v", name, err)
	}
	return ns
}

// publishPage authors and publishes a minimal page package version.
func publishPage(t *testing.T, svc *RegistryService, ns, name, version string) *database.PackageVersion {
	t.Helper()
	v, _, err := svc.AuthorPackage(AuthoredPackage{
		Namespace: ns, Name: name, Type: manifest.TypePage, Version: version,
		Title: name,
		Files: map[string][]byte{"content/index.html": []byte("<h1>" + name + " " + version + "</h1>")},
	})
	if err != nil {
		t.Fatalf("publish %s/%s@%s: %v", ns, name, version, err)
	}
	return v
}

// publishBundle authors and publishes a bundle referencing the given deps.
func publishBundle(svc *RegistryService, ns, name, version string, deps []manifest.Dependency) (*database.PackageVersion, error) {
	v, _, err := svc.AuthorPackage(AuthoredPackage{
		Namespace: ns, Name: name, Type: manifest.TypeBundle, Version: version,
		Dependencies: deps,
		Files:        map[string][]byte{"content/bundle.txt": []byte("kit")},
	})
	return v, err
}

// isPinned reports whether a blob currently holds a pin.
func (b *BlobStore) isPinned(sha string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.pins[sha] > 0
}

// inspectManifest runs InspectArchiveSize and returns only the manifest.
func inspectManifest(archivePath string, lim ArchiveLimits) (*manifest.Manifest, error) {
	m, _, err := InspectArchiveSize(archivePath, lim)
	return m, err
}

// resetOperatorName resets an operator password without an audit record and
// returns the operator username and new password.
func (s *OperatorService) resetOperatorName(username string) (string, string, error) {
	_, u, p, _, err := s.resetOperator(username)
	return u, p, err
}

// setOperatorFields writes columns straight into an operator row.
func setOperatorFields(t *testing.T, db *gorm.DB, id string, fields map[string]any) {
	t.Helper()
	if err := db.Model(&database.Operator{}).Where("id = ?", id).Updates(fields).Error; err != nil {
		t.Fatalf("update operator: %v", err)
	}
}

// mustPackageID returns the id of a published package.
func mustPackageID(t *testing.T, svc *RegistryService, nsName, name string) string {
	t.Helper()
	ns, err := svc.repo.GetNamespace(nsName)
	if err != nil {
		t.Fatalf("namespace %s: %v", nsName, err)
	}
	pkg, err := svc.repo.GetPackage(ns.ID, name)
	if err != nil {
		t.Fatalf("package %s/%s: %v", nsName, name, err)
	}
	return pkg.ID
}
