package repository

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/model"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Order allowlists gate the single user supplied order column per table: an
// order request outside the list is rejected before it reaches SQL. Search
// allowlists are the repository's own fixed text columns the LIKE runs over,
// never user supplied. "version" is intentionally not orderable in SQL because
// NOCASE collation sorts semver wrong (10.0.0 before 9.0.0); versions are small
// per package and ordered by created_at, with latest resolved by semver in Go.
var (
	namespaceOrderColumns = []clause.Column{
		{Table: database.NAMESPACE_TABLE, Name: "created_at"},
		{Table: database.NAMESPACE_TABLE, Name: "updated_at"},
		{Table: database.NAMESPACE_TABLE, Name: "name"},
	}
	namespaceSearchColumns = []clause.Column{
		{Table: database.NAMESPACE_TABLE, Name: "name"},
		{Table: database.NAMESPACE_TABLE, Name: "description"},
	}
	packageOrderColumns = []clause.Column{
		{Table: database.PACKAGE_TABLE, Name: "created_at"},
		{Table: database.PACKAGE_TABLE, Name: "updated_at"},
		{Table: database.PACKAGE_TABLE, Name: "name"},
		{Table: database.PACKAGE_TABLE, Name: "type"},
		{Table: database.PACKAGE_TABLE, Name: "download_count"},
	}
	packageSearchColumns = []clause.Column{
		{Table: database.PACKAGE_TABLE, Name: "name"},
		{Table: database.PACKAGE_TABLE, Name: "description"},
	}
)

// Registry is the data access layer for namespaces, packages, versions, blobs
// and download counts.
type Registry struct {
	db *gorm.DB
}

// NewRegistry returns a Registry repository.
func NewRegistry(db *gorm.DB) *Registry {
	return &Registry{db: db}
}

// Transaction runs fn against a repository bound to a single database
// transaction. Every repo call fn makes on the passed Registry commits together
// or, on any returned error, rolls back as one, so a multi step mutation cannot
// leave the database half changed.
func (r *Registry) Transaction(fn func(*Registry) error) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		return fn(&Registry{db: tx})
	})
}

// --- Namespace ---

// EnsureNamespace returns the namespace with name, creating it when absent.
func (r *Registry) EnsureNamespace(name, visibility string) (*database.Namespace, error) {
	var ns database.Namespace
	err := r.db.Where("name = ?", name).First(&ns).Error
	if err == nil {
		return &ns, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	ns = database.Namespace{Name: name, Visibility: visibility}
	if err := r.db.Create(&ns).Error; err != nil {
		return nil, err
	}
	return &ns, nil
}

// GetNamespace returns a namespace by name.
func (r *Registry) GetNamespace(name string) (*database.Namespace, error) {
	var ns database.Namespace
	if err := r.db.Where("name = ?", name).First(&ns).Error; err != nil {
		return nil, err
	}
	return &ns, nil
}

// NamespaceNameTaken reports whether a namespace has the name.
func (r *Registry) NamespaceNameTaken(name string) (bool, error) {
	var n int64
	err := r.db.Model(&database.Namespace{}).Where("name = ?", name).Count(&n).Error
	return n > 0, err
}

// GetNamespaceByID returns a namespace by id.
func (r *Registry) GetNamespaceByID(id string) (*database.Namespace, error) {
	var ns database.Namespace
	if err := r.db.Where("id = ?", id).First(&ns).Error; err != nil {
		return nil, err
	}
	return &ns, nil
}

// UpdateNamespace sets a namespace's description and visibility.
func (r *Registry) UpdateNamespace(id, description, visibility string) error {
	return r.db.Model(&database.Namespace{}).Where("id = ?", id).
		Updates(map[string]any{"description": description, "visibility": visibility}).Error
}

// MakePublicNamespacesPrivate sets every namespace stored as public to private
// and returns how many changed.
func (r *Registry) MakePublicNamespacesPrivate() (int64, error) {
	res := r.db.Model(&database.Namespace{}).Where("visibility = ?", database.VisibilityPublic).
		Update("visibility", database.VisibilityPrivate)
	return res.RowsAffected, res.Error
}

// RenameNamespace sets a namespace's name. Package addresses are derived from
// the namespace name, so this changes the address of every package it owns. The
// caller has checked the new name is a valid slug and not already taken.
func (r *Registry) RenameNamespace(id, newName string) error {
	return r.db.Model(&database.Namespace{}).Where("id = ?", id).
		Update("name", newName).Error
}

// RewriteNamespaceInTokens replaces an old namespace name with a new one in every
// token's entitlements, so a token scoped to a namespace keeps
// working after that namespace is renamed. A "*" entry (all namespaces) is left
// alone. Returns how many tokens changed.
func (r *Registry) RewriteNamespaceInTokens(oldName, newName string) (int, error) {
	var tokens []database.Token
	if err := r.db.Find(&tokens).Error; err != nil {
		return 0, err
	}
	changed := 0
	for i := range tokens {
		t := &tokens[i]
		newEnt, e1 := rewriteNameInJSONList(t.Entitlements, oldName, newName)
		if !e1 {
			continue
		}
		if err := r.db.Model(&database.Token{}).Where("id = ?", t.ID).
			Update("entitlements", newEnt).Error; err != nil {
			return changed, err
		}
		changed++
	}
	return changed, nil
}

// TokenEntitlementsWithout returns, for every token whose entitlements name the
// namespace exactly, the entitlements json with that name removed, keyed by token
// id. A "*" entry is left alone. It only reads, so the caller can apply the
// result with SetTokenEntitlements inside a transaction.
func (r *Registry) TokenEntitlementsWithout(name string) (map[string]string, error) {
	var tokens []database.Token
	if err := r.db.Find(&tokens).Error; err != nil {
		return nil, err
	}
	out := map[string]string{}
	for i := range tokens {
		if updated, changed := removeNameFromJSONList(tokens[i].Entitlements, name); changed {
			out[tokens[i].ID] = updated
		}
	}
	return out, nil
}

// SetTokenEntitlements replaces a token's entitlements json.
func (r *Registry) SetTokenEntitlements(id, entitlements string) error {
	return r.db.Model(&database.Token{}).Where("id = ?", id).
		Update("entitlements", entitlements).Error
}

// removeNameFromJSONList drops every exact name from a json string array,
// returning the new json and whether anything changed.
func removeNameFromJSONList(jsonList, name string) (string, bool) {
	if strings.TrimSpace(jsonList) == "" {
		return jsonList, false
	}
	var items []string
	if err := json.Unmarshal([]byte(jsonList), &items); err != nil {
		return jsonList, false
	}
	kept := make([]string, 0, len(items))
	for _, it := range items {
		if it != name {
			kept = append(kept, it)
		}
	}
	if len(kept) == len(items) {
		return jsonList, false
	}
	out, err := json.Marshal(kept)
	if err != nil {
		return jsonList, false
	}
	return string(out), true
}

// CountTokensScopedTo returns how many tokens name a namespace explicitly in
// their entitlements. A "*" (all namespaces) token does not count,
// since renaming one namespace does not change what it grants.
func (r *Registry) CountTokensScopedTo(name string) (int, error) {
	var tokens []database.Token
	if err := r.db.Find(&tokens).Error; err != nil {
		return 0, err
	}
	n := 0
	for i := range tokens {
		if jsonListHas(tokens[i].Entitlements, name) {
			n++
		}
	}
	return n, nil
}

// jsonListHas reports whether a json string array contains an exact value.
func jsonListHas(jsonList, want string) bool {
	if strings.TrimSpace(jsonList) == "" {
		return false
	}
	var items []string
	if err := json.Unmarshal([]byte(jsonList), &items); err != nil {
		return false
	}
	for _, it := range items {
		if it == want {
			return true
		}
	}
	return false
}

// rewriteNameInJSONList replaces oldName with newName in a json string array,
// returning the rewritten json and whether anything changed. A value that is not
// a json array is returned unchanged.
func rewriteNameInJSONList(jsonList, oldName, newName string) (string, bool) {
	if strings.TrimSpace(jsonList) == "" {
		return jsonList, false
	}
	var items []string
	if err := json.Unmarshal([]byte(jsonList), &items); err != nil {
		return jsonList, false
	}
	changed := false
	for i, it := range items {
		if it == oldName {
			items[i] = newName
			changed = true
		}
	}
	if !changed {
		return jsonList, false
	}
	out, err := json.Marshal(items)
	if err != nil {
		return jsonList, false
	}
	return string(out), true
}

// SetNamespaceColor sets a namespace's color label. The caller passes a value
// already checked against the color allowlist, or empty for no color.
func (r *Registry) SetNamespaceColor(id, color string) error {
	return r.db.Model(&database.Namespace{}).Where("id = ?", id).
		Update("color", color).Error
}

// CountPackagesInNamespace returns how many packages a namespace owns.
func (r *Registry) CountPackagesInNamespace(nsID string) (int64, error) {
	var n int64
	err := r.db.Model(&database.Package{}).Where("namespace_id = ?", nsID).Count(&n).Error
	return n, err
}

// CreateNamespace inserts a namespace row. Unlike EnsureNamespace it only
// writes, so it is safe inside a transaction whose reads ran before it.
func (r *Registry) CreateNamespace(ns *database.Namespace) error {
	return r.db.Create(ns).Error
}

// DeleteNamespace removes an empty namespace.
func (r *Registry) DeleteNamespace(id string) error {
	return r.db.Where("id = ?", id).Delete(&database.Namespace{}).Error
}

// ListNamespaces lists namespaces.
func (r *Registry) ListNamespaces(q *QueryArgs) ([]database.Namespace, error) {
	db := applySearch(r.db.Model(&database.Namespace{}), q, namespaceSearchColumns)
	db, err := applyOrder(db, q, namespaceOrderColumns)
	if err != nil {
		return nil, err
	}
	var out []database.Namespace
	return out, applyPage(db, q).Find(&out).Error
}

// CountNamespaces returns how many namespaces match q's search filter, ignoring
// its paging, so a list endpoint can report the total page count.
func (r *Registry) CountNamespaces(q *QueryArgs) (int64, error) {
	var n int64
	return n, applySearch(r.db.Model(&database.Namespace{}), q, namespaceSearchColumns).Count(&n).Error
}

// --- Package ---

// EnsurePackage returns the package in a namespace, creating it when absent.
func (r *Registry) EnsurePackage(namespaceID, name, pkgType string) (*database.Package, error) {
	var p database.Package
	err := r.db.Where("namespace_id = ? AND name = ?", namespaceID, name).First(&p).Error
	if err == nil {
		return &p, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}
	p = database.Package{NamespaceID: namespaceID, Name: name, Type: pkgType}
	if err := r.db.Create(&p).Error; err != nil {
		return nil, err
	}
	return &p, nil
}

// CreatePackage inserts a package row. It only writes, so it is safe inside a
// transaction whose reads ran before it.
func (r *Registry) CreatePackage(p *database.Package) error {
	return r.db.Create(p).Error
}

// PackageAddress returns the namespace name and package name a package row
// currently has, so a writer can confirm the address it read earlier still
// holds before it commits.
func (r *Registry) PackageAddress(packageID string) (string, string, error) {
	var row struct {
		NsName  string
		PkgName string
	}
	err := r.db.Table("packages AS p").
		Select("n.name AS ns_name, p.name AS pkg_name").
		Joins("JOIN namespaces AS n ON n.id = p.namespace_id").
		Where("p.id = ?", packageID).Scan(&row).Error
	if err != nil {
		return "", "", err
	}
	if row.NsName == "" {
		return "", "", gorm.ErrRecordNotFound
	}
	return row.NsName, row.PkgName, nil
}

// GetPackage returns a package by namespace and name.
func (r *Registry) GetPackage(namespaceID, name string) (*database.Package, error) {
	var p database.Package
	if err := r.db.Where("namespace_id = ? AND name = ?", namespaceID, name).First(&p).Error; err != nil {
		return nil, err
	}
	return &p, nil
}

// applyPackageFilters binds every filter as a value: namespace resolves to its
// id via a subquery, and a tag goes through whereHasTag.
func (r *Registry) applyPackageFilters(db *gorm.DB, q *QueryArgs) *gorm.DB {
	if q == nil {
		return db
	}
	if q.FilterType != "" {
		db = db.Where("type = ?", q.FilterType)
	}
	if q.FilterNamespace != "" {
		db = db.Where("namespace_id IN (?)",
			r.db.Model(&database.Namespace{}).Select("id").Where("name = ?", q.FilterNamespace))
	}
	if q.FilterTag != "" {
		db = whereHasTag(db, q.FilterTag)
	}
	return db
}

// whereHasTag limits db to packages that carry exactly the tag. The tag is
// cleaned the way stored tags are, and matched on comma boundaries with the LIKE
// wildcards escaped, so "o365" never matches "o3650" and "a,b" or "o%" match no
// single tag.
func whereHasTag(db *gorm.DB, tag string) *gorm.DB {
	cleaned := model.CleanTags([]string{tag})
	if len(cleaned) != 1 || strings.Contains(cleaned[0], ",") {
		return db.Where("1 = 0")
	}
	return db.Where(`(',' || tags || ',') LIKE ? ESCAPE '\'`, "%,"+escapeLike(cleaned[0])+",%")
}

// ListPackages returns every row for a nil q (the service's internal reads).
func (r *Registry) ListPackages(q *QueryArgs) ([]database.Package, error) {
	db := r.applyPackageFilters(applySearch(r.db.Model(&database.Package{}), q, packageSearchColumns), q)
	db, err := applyOrder(db, q, packageOrderColumns)
	if err != nil {
		return nil, err
	}
	var out []database.Package
	return out, applyPage(db, q).Find(&out).Error
}

// CountPackages returns how many packages match q's search and filters, ignoring
// its paging, so a list endpoint can report the total page count.
func (r *Registry) CountPackages(q *QueryArgs) (int64, error) {
	var n int64
	db := r.applyPackageFilters(applySearch(r.db.Model(&database.Package{}), q, packageSearchColumns), q)
	return n, db.Count(&n).Error
}

// UpdatePackageMeta changes metadata without publishing a new version. Tags are
// stored comma separated.
func (r *Registry) UpdatePackageMeta(packageID, title, description, tags string) error {
	return r.db.Model(&database.Package{}).Where("id = ?", packageID).Updates(map[string]any{
		"title":       title,
		"description": description,
		"tags":        tags,
	}).Error
}

// --- Package previews (package meta images, not archive content) ---

// AddPackagePreview does nothing when the blob is already a preview of the
// package (the pair is unique).
func (r *Registry) AddPackagePreview(packageID, sha, mediaType string, position int) error {
	err := r.db.Where("package_id = ? AND blob_sha256 = ?", packageID, sha).First(&database.PackagePreview{}).Error
	if err == nil {
		return nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	p := database.PackagePreview{PackageID: packageID, BlobSHA256: sha, MediaType: mediaType, Position: position}
	return r.db.Create(&p).Error
}

// InsertPackagePreview inserts a preview row, ignoring one that already exists
// for the same package and blob. It only writes, so it is safe inside a
// transaction.
func (r *Registry) InsertPackagePreview(packageID, sha, mediaType string, position int) error {
	p := database.PackagePreview{PackageID: packageID, BlobSHA256: sha, MediaType: mediaType, Position: position}
	return r.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&p).Error
}

// ListPackagePreviews returns a package's preview images in gallery order.
func (r *Registry) ListPackagePreviews(packageID string) ([]database.PackagePreview, error) {
	var out []database.PackagePreview
	return out, r.db.Where("package_id = ?", packageID).Order("position ASC, created_at ASC").Find(&out).Error
}

// SetPackagePreviewOrder applies a new gallery order. shas lists the package's
// previews in the wanted order; each row is given its index as Position. Only
// rows for this package are touched, so a sha from another package is ignored.
func (r *Registry) SetPackagePreviewOrder(packageID string, shas []string) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		for i, sha := range shas {
			if err := tx.Model(&database.PackagePreview{}).
				Where("package_id = ? AND blob_sha256 = ?", packageID, sha).
				Update("position", i).Error; err != nil {
				return err
			}
		}
		return nil
	})
}

// GetPackagePreview returns one preview by package and blob sha, used to confirm
// a requested preview actually belongs to the package before serving it.
func (r *Registry) GetPackagePreview(packageID, sha string) (*database.PackagePreview, error) {
	var p database.PackagePreview
	if err := r.db.Where("package_id = ? AND blob_sha256 = ?", packageID, sha).First(&p).Error; err != nil {
		return nil, err
	}
	return &p, nil
}

// CountPackagePreviews returns how many previews a package has (to cap the gallery).
func (r *Registry) CountPackagePreviews(packageID string) (int64, error) {
	var n int64
	err := r.db.Model(&database.PackagePreview{}).Where("package_id = ?", packageID).Count(&n).Error
	return n, err
}

// DeletePackagePreview removes one preview row; the caller cleans the blob.
func (r *Registry) DeletePackagePreview(packageID, sha string) error {
	return r.db.Where("package_id = ? AND blob_sha256 = ?", packageID, sha).Delete(&database.PackagePreview{}).Error
}

// --- Version ---

// CreateVersion inserts a package version.
func (r *Registry) CreateVersion(v *database.PackageVersion) error {
	return r.db.Create(v).Error
}

// PackageExists reports whether a package with name lives in the namespace.
// It counts rows, so a missing package is false with no error.
func (r *Registry) PackageExists(namespaceID, name string) (bool, error) {
	var n int64
	err := r.db.Model(&database.Package{}).Where("namespace_id = ? AND name = ?", namespaceID, name).Count(&n).Error
	return n > 0, err
}

// VersionExists reports whether the package already has the version. It
// counts rows, so a missing version is false with no error.
func (r *Registry) VersionExists(packageID, version string) (bool, error) {
	var n int64
	err := r.db.Model(&database.PackageVersion{}).
		Where("package_id = ? AND version = ?", packageID, version).
		Count(&n).Error
	return n > 0, err
}

// IsUniqueViolation reports whether err is a unique index failure from an
// insert, so a caller can tell a row another writer created first apart from
// any other database error.
func IsUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// GetVersion returns a specific version of a package.
func (r *Registry) GetVersion(packageID, version string) (*database.PackageVersion, error) {
	var v database.PackageVersion
	if err := r.db.Where("package_id = ? AND version = ?", packageID, version).First(&v).Error; err != nil {
		return nil, err
	}
	return &v, nil
}

// ListVersions returns all versions of a package, newest first.
func (r *Registry) ListVersions(packageID string) ([]database.PackageVersion, error) {
	var out []database.PackageVersion
	return out, r.db.Model(&database.PackageVersion{}).
		Where("package_id = ?", packageID).
		Order("created_at DESC").Find(&out).Error
}

// VersionIDs returns the ids of every version of a package, sorted, so a
// writer can confirm the set it planned against is unchanged.
func (r *Registry) VersionIDs(packageID string) ([]string, error) {
	var ids []string
	err := r.db.Model(&database.PackageVersion{}).Where("package_id = ?", packageID).
		Order("id ASC").Pluck("id", &ids).Error
	return ids, err
}

// VersionIDsInNamespace returns the ids of every version of every package in a
// namespace, sorted.
func (r *Registry) VersionIDsInNamespace(namespaceID string) ([]string, error) {
	var ids []string
	err := r.db.Model(&database.PackageVersion{}).
		Where("package_id IN (?)", r.db.Model(&database.Package{}).Select("id").Where("namespace_id = ?", namespaceID)).
		Order("id ASC").Pluck("id", &ids).Error
	return ids, err
}

// YankVersion sets or clears the yanked flag on a version.
func (r *Registry) YankVersion(versionID string, yanked bool) error {
	return r.db.Model(&database.PackageVersion{}).Where("id = ?", versionID).Update("yanked", yanked).Error
}

// ErrLastVersion is returned by DeleteVersion when the version is the only one
// its package has.
var ErrLastVersion = errors.New("last version of the package")

// DeleteVersion removes a single version row and returns its archive blob sha.
// It never removes the last version of a package: the count and the delete are
// one statement, so two deletes racing cannot leave the package empty.
func (r *Registry) DeleteVersion(versionID string) (string, error) {
	var v database.PackageVersion
	if err := r.db.Where("id = ?", versionID).First(&v).Error; err != nil {
		return "", err
	}
	res := r.db.Where("id = ?", versionID).
		Where("(SELECT COUNT(*) FROM package_versions WHERE package_id = ?) > 1", v.PackageID).
		Delete(&database.PackageVersion{})
	if res.Error != nil {
		return "", res.Error
	}
	if res.RowsAffected == 0 {
		return "", ErrLastVersion
	}
	return v.ArchiveBlobSHA256, nil
}

// DeletePackage removes a package with all its versions and preview images in
// one transaction, returning the archive and preview blob shas that were
// referenced so the caller can clean up orphans.
func (r *Registry) DeletePackage(pkgID string) ([]string, error) {
	// the reads run before the transaction, so it holds the single database
	// connection only for the deletes.
	var vers []database.PackageVersion
	if err := r.db.Where("package_id = ?", pkgID).Find(&vers).Error; err != nil {
		return nil, err
	}
	var previews []database.PackagePreview
	if err := r.db.Where("package_id = ?", pkgID).Find(&previews).Error; err != nil {
		return nil, err
	}
	shas := make([]string, 0, len(vers)+len(previews))
	for i := range vers {
		shas = append(shas, vers[i].ArchiveBlobSHA256)
	}
	for i := range previews {
		shas = append(shas, previews[i].BlobSHA256)
	}
	err := r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("package_id = ?", pkgID).Delete(&database.PackagePreview{}).Error; err != nil {
			return err
		}
		if err := tx.Where("package_id = ?", pkgID).Delete(&database.PackageVersion{}).Error; err != nil {
			return err
		}
		return tx.Where("id = ?", pkgID).Delete(&database.Package{}).Error
	})
	if err != nil {
		return nil, err
	}
	return shas, nil
}

// DeleteBlobRecord removes a blob row (the file is removed by the blob store).
func (r *Registry) DeleteBlobRecord(sha string) error {
	return r.db.Where("sha256 = ?", sha).Delete(&database.Blob{}).Error
}

// --- Blob ---

// UpsertBlob records a blob, leaving an existing row alone, so a shared archive
// or asset is tracked once.
func (r *Registry) UpsertBlob(sha string, size int64, mediaType string) error {
	var b database.Blob
	err := r.db.Where("sha256 = ?", sha).First(&b).Error
	if err == nil {
		// blobs are content addressed, so an existing row is the same bytes: dedupe.
		// whether a blob is still needed is answered live by BlobReferenced.
		return nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	b = database.Blob{SHA256: sha, Size: size, MediaType: mediaType}
	return r.db.Create(&b).Error
}

// InsertBlobIfAbsent records a blob row, leaving an existing row alone. It only
// writes, so it is safe inside a transaction.
func (r *Registry) InsertBlobIfAbsent(sha string, size int64, mediaType string) error {
	b := database.Blob{SHA256: sha, Size: size, MediaType: mediaType}
	return r.db.Clauses(clause.OnConflict{DoNothing: true}).Create(&b).Error
}

// BlobReferenced reports whether any package version uses the given archive
// blob, so an orphaned blob can be cleaned up safely without removing one a
// published version still points at.
func (r *Registry) BlobReferenced(sha string) (bool, error) {
	var count int64
	err := r.db.Model(&database.PackageVersion{}).
		Where("archive_blob_sha256 = ?", sha).
		Count(&count).Error
	if err != nil {
		return false, err
	}
	if count > 0 {
		return true, nil
	}
	// a preview image is a standalone blob referenced only by package_previews, so
	// it must also count as referenced or orphan cleanup would delete it.
	err = r.db.Model(&database.PackagePreview{}).Where("blob_sha256 = ?", sha).Count(&count).Error
	return count > 0, err
}

// --- Download counts ---

// RecordDownload adds one to the package count, the version count and the
// daily count of the version for the UTC day of at, in one transaction so they
// never drift apart. It only writes.
func (r *Registry) RecordDownload(versionID, packageID string, at time.Time) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&database.Package{}).Where("id = ?", packageID).
			UpdateColumn("download_count", gorm.Expr("download_count + 1")).Error; err != nil {
			return err
		}
		if err := tx.Model(&database.PackageVersion{}).Where("id = ?", versionID).
			UpdateColumn("download_count", gorm.Expr("download_count + 1")).Error; err != nil {
			return err
		}
		row := database.DownloadDaily{
			VersionID: versionID,
			Day:       at.UTC().Format("2006-01-02"),
			PackageID: packageID,
			Count:     1,
		}
		addOne := gorm.Expr("download_daily.count + 1")
		return tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "version_id"}, {Name: "day"}},
			DoUpdates: clause.Assignments(map[string]any{"count": addOne}),
		}).Create(&row).Error
	})
}

// escapeLike escapes the LIKE wildcards and the escape character itself.
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "%", `\%`)
	return strings.ReplaceAll(s, "_", `\_`)
}

// UpsertDraft saves a draft for a package address, overwriting any existing one
// so there is a single working draft per namespace and name.
func (r *Registry) UpsertDraft(d *database.Draft) error {
	var existing database.Draft
	err := r.db.Where("namespace = ? AND name = ?", d.Namespace, d.Name).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return r.db.Create(d).Error
	}
	if err != nil {
		return err
	}
	return r.db.Model(&database.Draft{}).Where("id = ?", existing.ID).
		Updates(map[string]any{
			"type": d.Type, "version": d.Version, "title": d.Title, "body": d.Body,
		}).Error
}

// ListDrafts returns the saved drafts, newest first. Body is left loaded; the
// list view ignores it.
func (r *Registry) ListDrafts() ([]database.Draft, error) {
	var out []database.Draft
	if err := r.db.Order("updated_at desc").Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

// GetDraft returns the draft for a package address, or an error if none.
func (r *Registry) GetDraft(namespace, name string) (*database.Draft, error) {
	var d database.Draft
	if err := r.db.Where("namespace = ? AND name = ?", namespace, name).First(&d).Error; err != nil {
		return nil, err
	}
	return &d, nil
}

// DeleteDraft removes the draft for a package address. A missing draft is not an
// error, so publishing a package that never had a draft still succeeds.
func (r *Registry) DeleteDraft(namespace, name string) error {
	return r.db.Where("namespace = ? AND name = ?", namespace, name).Delete(&database.Draft{}).Error
}

// ListTags returns all tag color entries, ordered by name.
func (r *Registry) ListTags() ([]database.Tag, error) {
	var out []database.Tag
	if err := r.db.Order("name asc").Find(&out).Error; err != nil {
		return nil, err
	}
	return out, nil
}

// UpsertTagColor sets a tag's color, creating the tag row if it does not exist.
func (r *Registry) UpsertTagColor(name, color string) error {
	var existing database.Tag
	err := r.db.Where("name = ?", name).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return r.db.Create(&database.Tag{Name: name, Color: color}).Error
	}
	if err != nil {
		return err
	}
	return r.db.Model(&database.Tag{}).Where("id = ?", existing.ID).Update("color", color).Error
}

// TagInUse reports whether any package carries the tag name, matched the same
// way as the package list tag filter.
func (r *Registry) TagInUse(name string) (bool, error) {
	var n int64
	err := whereHasTag(r.db.Model(&database.Package{}), name).Count(&n).Error
	return n > 0, err
}

// ListUsedTagNames returns every tag name at least one package carries, sorted
// and without duplicates. Names are in the cleaned form tag color rows are
// stored in. The package table is small, so the set is built in memory.
func (r *Registry) ListUsedTagNames() ([]string, error) {
	var cols []string
	if err := r.db.Model(&database.Package{}).Where("tags <> ''").Pluck("tags", &cols).Error; err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	out := []string{}
	for _, c := range cols {
		for _, t := range model.CleanTags(strings.Split(c, ",")) {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

// PruneUnusedTags deletes the tag color rows whose name no package carries. The
// tag and package tables are small, so the used set is built in memory.
func (r *Registry) PruneUnusedTags() error {
	var tags []database.Tag
	if err := r.db.Find(&tags).Error; err != nil {
		return err
	}
	if len(tags) == 0 {
		return nil
	}
	names, err := r.ListUsedTagNames()
	if err != nil {
		return err
	}
	used := map[string]bool{}
	for _, n := range names {
		used[n] = true
	}
	var stale []string
	for i := range tags {
		if !used[tags[i].Name] {
			stale = append(stale, tags[i].ID)
		}
	}
	if len(stale) == 0 {
		return nil
	}
	return r.db.Where("id IN ?", stale).Delete(&database.Tag{}).Error
}

// SetPackageNamespace moves a package to another namespace by id. The caller
// ensures the target namespace exists and has no package of the same name.
func (r *Registry) SetPackageNamespace(packageID, namespaceID string) error {
	return r.db.Model(&database.Package{}).Where("id = ?", packageID).
		Update("namespace_id", namespaceID).Error
}

// SetPackageName renames a package by id. The caller ensures the new name is a
// valid slug and that the target namespace has no package of that name.
func (r *Registry) SetPackageName(packageID, name string) error {
	return r.db.Model(&database.Package{}).Where("id = ?", packageID).
		Update("name", name).Error
}

// VersionArchive is a version's rebuilt archive: its manifest, archive blob,
// content hash and unpacked size.
type VersionArchive struct {
	VersionID    string
	ManifestJSON string
	ArchiveSHA   string
	ContentHash  string
	UnpackedSize int64
}

// UpdateVersionArchive replaces a version's archive, used when a package is
// moved and each version is repacked under the new id.
func (r *Registry) UpdateVersionArchive(a VersionArchive) error {
	return r.db.Model(&database.PackageVersion{}).Where("id = ?", a.VersionID).
		Updates(map[string]any{
			"manifest":            a.ManifestJSON,
			"archive_blob_sha256": a.ArchiveSHA,
			"content_hash":        a.ContentHash,
			"unpacked_size":       a.UnpackedSize,
		}).Error
}
