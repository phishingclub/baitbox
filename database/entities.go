// Package database holds the GORM entity definitions and table name constants.
// Entities are the schema. Domain logic and validation live in the model
// package; data access lives in the repository package. This mirrors the
// phishingclub layering (controller, service, repository, model, database).
package database

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"gorm.io/gorm"
)

// Table name constants. Repositories and the SQL column allowlist reference
// these so a table name is never a literal scattered across the code.
const (
	NAMESPACE_TABLE       = "namespaces"
	PACKAGE_TABLE         = "packages"
	PACKAGE_VERSION_TABLE = "package_versions"
	PACKAGE_PREVIEW_TABLE = "package_previews"
	BLOB_TABLE            = "blobs"
	TOKEN_TABLE           = "tokens"
	OPERATOR_TABLE        = "operators"
	SESSION_TABLE         = "sessions"
	DOWNLOAD_DAILY_TABLE  = "download_daily"
	OPERATOR_CRED_TABLE   = "operator_credentials"
	DRAFT_TABLE           = "drafts"
	TAG_TABLE             = "tags"
)

// Visibility values.
const (
	VisibilityPublic  = "public"
	VisibilityPrivate = "private"
)

// newID returns a random 32 character hex id used as a string primary key. A
// CSPRNG failure is unrecoverable, so it panics rather than return a weak id.
func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand read failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// Base carries the string primary key and timestamps shared by most entities.
type Base struct {
	ID        string    `gorm:"primaryKey;size:32" json:"id"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// BeforeCreate assigns a random id when one was not set by the caller.
func (b *Base) BeforeCreate(_ *gorm.DB) error {
	if b.ID == "" {
		b.ID = newID()
	}
	return nil
}

// Namespace is a scope or vendor that owns packages, e.g. "phishingclub".
type Namespace struct {
	Base
	Name        string `gorm:"uniqueIndex;size:128" json:"name"`
	Description string `json:"description"`
	Visibility  string `gorm:"size:16;default:private" json:"visibility"`
	Color       string `gorm:"size:16" json:"color"`
}

func (Namespace) TableName() string { return NAMESPACE_TABLE }

// Package is a named, versioned unit of content within a namespace.
type Package struct {
	Base
	NamespaceID   string `gorm:"index;size:32;uniqueIndex:idx_pkg_ns_name" json:"namespaceId"`
	Name          string `gorm:"size:128;uniqueIndex:idx_pkg_ns_name" json:"name"`
	Title         string `gorm:"size:255" json:"title"`
	Type          string `gorm:"size:32;index" json:"type"`
	Description   string `json:"description"`
	Tags          string `json:"tags"`
	DownloadCount int64  `json:"downloadCount"`
}

func (Package) TableName() string { return PACKAGE_TABLE }

// PackageVersion is a single semver release of a package, pointing at the
// content addressed archive blob and carrying the manifest.
type PackageVersion struct {
	Base
	PackageID         string `gorm:"index;size:32;uniqueIndex:idx_ver_pkg_version" json:"packageId"`
	Version           string `gorm:"size:64;uniqueIndex:idx_ver_pkg_version" json:"version"`
	Manifest          string `gorm:"type:text" json:"manifest"`
	MinAppVersion     string `gorm:"size:64" json:"minAppVersion"`
	ArchiveBlobSHA256 string `gorm:"size:64;index" json:"archiveBlobSha256"`
	ContentHash       string `gorm:"size:64" json:"contentHash"`
	Size              int64  `json:"size"`
	// UnpackedSize is the sum of every file in the archive once unpacked, the
	// measure the bundle install cap uses.
	UnpackedSize  int64 `gorm:"default:0" json:"unpackedSize"`
	Yanked        bool  `gorm:"default:false" json:"yanked"`
	DownloadCount int64 `json:"downloadCount"`
}

func (PackageVersion) TableName() string { return PACKAGE_VERSION_TABLE }

// PackagePreview is a preview image shown when browsing a package. It is package
// level metadata backed by a standalone content addressed blob: it is NOT part of
// any version archive, the manifest, or the content hash, so an operator can curate
// preview imagery without publishing a new version. Position orders the gallery.
type PackagePreview struct {
	Base
	PackageID  string `gorm:"index;size:32;uniqueIndex:idx_preview_pkg_blob" json:"packageId"`
	BlobSHA256 string `gorm:"size:64;uniqueIndex:idx_preview_pkg_blob" json:"blobSha256"`
	MediaType  string `gorm:"size:128" json:"mediaType"`
	Position   int    `gorm:"default:0" json:"position"`
}

func (PackagePreview) TableName() string { return PACKAGE_PREVIEW_TABLE }

// Blob is a content addressed file on disk, referenced by sha256. Shared assets
// across packages dedupe to one blob.
type Blob struct {
	SHA256    string    `gorm:"primaryKey;size:64" json:"sha256"`
	Size      int64     `json:"size"`
	MediaType string    `gorm:"size:128" json:"mediaType"`
	CreatedAt time.Time `json:"createdAt"`
}

func (Blob) TableName() string { return BLOB_TABLE }

// Token is a bearer credential for read access to entitled namespaces. Only the
// sha256 of the token is stored; it is looked up by that hash.
type Token struct {
	Base
	TokenHash    string `gorm:"uniqueIndex;size:64" json:"-"`
	Prefix       string `gorm:"size:12;index" json:"prefix"`
	Name         string `gorm:"size:128" json:"name"`
	Entitlements string `gorm:"type:text" json:"entitlements"`
	// AllowedCIDRs is a json array of CIDRs or bare IPs the token may be used from.
	// An empty list means the token is not restricted by source IP.
	AllowedCIDRs string     `gorm:"type:text" json:"allowedCidrs"`
	ExpiresAt    *time.Time `json:"expiresAt"`
	LastUsedAt   *time.Time `json:"lastUsedAt"`
	Revoked      bool       `gorm:"default:false" json:"revoked"`
	// OperatorID is the operator who created the token, so the token is revoked
	// when that operator is deleted.
	OperatorID string `gorm:"index;size:32" json:"operatorId"`
	CreatedBy  string `gorm:"size:128" json:"createdBy"`
}

func (Token) TableName() string { return TOKEN_TABLE }

// Operator is a server admin account for the html admin UI.
type Operator struct {
	Base
	Username     string `gorm:"uniqueIndex;size:128" json:"username"`
	PasswordHash string `gorm:"type:text" json:"-"`
	// TOTP two factor: MFASecret is the base32 shared secret (never serialized),
	// set only while enabled. MFAEnabled gates the second login step.
	MFASecret  string `gorm:"type:text" json:"-"`
	MFAEnabled bool   `gorm:"default:false" json:"mfaEnabled"`
	// the TOTP time step counter last accepted for this operator, so a code cannot be
	// replayed within its validity window (single use second factor).
	MFALastCounter int64 `gorm:"default:0" json:"-"`
	// MustChangePassword is set when the password was issued rather than chosen
	// (first run seed, reset, or created by another operator). In prod the operator
	// can do nothing else until they set their own password.
	MustChangePassword bool `gorm:"default:false" json:"mustChangePassword"`
	// AuthEpoch goes up in every change that drops the operator's sessions. A
	// session keeps the epoch its login checked and stops working once they differ.
	AuthEpoch int64 `gorm:"not null;default:0" json:"-"`
}

func (Operator) TableName() string { return OPERATOR_TABLE }

// Session is an operator login session bound to a client IP.
type Session struct {
	ID            string    `gorm:"primaryKey;size:64" json:"id"`
	OperatorID    string    `gorm:"index;size:32" json:"operatorId"`
	IP            string    `gorm:"size:64" json:"ip"`
	IdleExpiresAt time.Time `json:"idleExpiresAt"`
	MaxExpiresAt  time.Time `json:"maxExpiresAt"`
	LastActiveAt  time.Time `json:"lastActiveAt"`
	CreatedAt     time.Time `json:"createdAt"`
	// AuthEpoch is the operator's AuthEpoch read by the login that made this
	// session.
	AuthEpoch int64 `gorm:"not null;default:0" json:"-"`
}

func (Session) TableName() string { return SESSION_TABLE }

// DownloadDaily counts downloads per version per UTC day. Each download adds
// one to the row of its version and day. The dashboard total is their sum.
type DownloadDaily struct {
	VersionID string `gorm:"primaryKey;size:32" json:"versionId"`
	Day       string `gorm:"primaryKey;size:10" json:"day"`
	PackageID string `gorm:"index;size:32" json:"packageId"`
	Count     int64  `gorm:"not null;default:0" json:"count"`
}

func (DownloadDaily) TableName() string { return DOWNLOAD_DAILY_TABLE }

// OperatorCredential is a registered WebAuthn passkey for an operator: a second
// login factor alongside TOTP. Fields map to webauthn.Credential; the raw
// CredentialID is unique across the instance.
type OperatorCredential struct {
	Base
	OperatorID      string `gorm:"index;size:32" json:"operatorId"`
	Name            string `gorm:"size:128" json:"name"`
	CredentialID    []byte `gorm:"uniqueIndex" json:"-"`
	PublicKey       []byte `json:"-"`
	AttestationType string `gorm:"size:32" json:"-"`
	AAGUID          []byte `json:"-"`
	SignCount       uint32 `json:"-"`
	CloneWarning    bool   `json:"-"`
	// BackupEligible and BackupState are the authenticator backup flags. A synced
	// passkey (iCloud, Google) is backup eligible, and the login check refuses an
	// assertion whose eligible flag differs from the stored one.
	BackupEligible bool       `json:"-"`
	BackupState    bool       `json:"-"`
	Transports     string     `gorm:"type:text" json:"-"`
	LastUsedAt     *time.Time `json:"lastUsedAt"`
}

func (OperatorCredential) TableName() string { return OPERATOR_CRED_TABLE }

// Draft is a saved, unpublished authoring payload for a package address. One
// draft exists per namespace and name, so saving again overwrites it and
// publishing clears it. Body is the full author request as JSON, the same shape
// the publish endpoint accepts, so publishing a draft replays its body.
type Draft struct {
	Base
	Namespace string `gorm:"size:128;uniqueIndex:idx_draft_ns_name" json:"namespace"`
	Name      string `gorm:"size:128;uniqueIndex:idx_draft_ns_name" json:"name"`
	Type      string `gorm:"size:32" json:"type"`
	Version   string `gorm:"size:64" json:"version"`
	Title     string `gorm:"size:255" json:"title"`
	Body      string `json:"-"`
}

func (Draft) TableName() string { return DRAFT_TABLE }

// Tag is a package tag with an optional color. The color is a global property of
// the tag name, so the same tag reads the same color across every package. Color
// is one of the allowlisted tokens (or empty for none).
type Tag struct {
	Base
	Name  string `gorm:"uniqueIndex;size:32" json:"name"`
	Color string `gorm:"size:16" json:"color"`
}

func (Tag) TableName() string { return TAG_TABLE }

// AllEntities is the ordered list passed to AutoMigrate.
func AllEntities() []any {
	return []any{
		&Namespace{},
		&Package{},
		&PackageVersion{},
		&PackagePreview{},
		&Blob{},
		&Token{},
		&Operator{},
		&Session{},
		&DownloadDaily{},
		&OperatorCredential{},
		&Draft{},
		&Tag{},
	}
}
