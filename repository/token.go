package repository

import (
	"errors"
	"time"

	"github.com/phishingclub/baitbox/database"
	"gorm.io/gorm"
)

// TokenRepository is the data access layer for bearer tokens. Only the sha256 of
// a token is stored; it is looked up by that hash.
type TokenRepository struct {
	db *gorm.DB
}

// NewTokenRepository returns a TokenRepository.
func NewTokenRepository(db *gorm.DB) *TokenRepository {
	return &TokenRepository{db: db}
}

// CreateScoped inserts a token row only when every namespace in namespaces
// exists ("*" is not a namespace and is skipped). The check and the insert run
// in one transaction, so a namespace deleted at the same time cannot leave the
// token scoped to a name that no longer exists. It returns the names that do not
// exist, and then writes nothing.
func (r *TokenRepository) CreateScoped(t *database.Token, namespaces []string) ([]string, error) {
	var missing []string
	err := r.db.Transaction(func(tx *gorm.DB) error {
		var err error
		missing, err = missingNamespaces(tx, namespaces)
		if err != nil || len(missing) > 0 {
			return err
		}
		return tx.Create(t).Error
	})
	if err != nil {
		return nil, err
	}
	return missing, nil
}

// MissingNamespaces returns the names in namespaces that no namespace has, in
// the order given. "*" is skipped.
func (r *TokenRepository) MissingNamespaces(namespaces []string) ([]string, error) {
	return missingNamespaces(r.db, namespaces)
}

func missingNamespaces(db *gorm.DB, namespaces []string) ([]string, error) {
	want := make([]string, 0, len(namespaces))
	for _, n := range namespaces {
		if n != "*" {
			want = append(want, n)
		}
	}
	if len(want) == 0 {
		return nil, nil
	}
	var found []string
	if err := db.Model(&database.Namespace{}).Where("name IN ?", want).Pluck("name", &found).Error; err != nil {
		return nil, err
	}
	have := make(map[string]bool, len(found))
	for _, n := range found {
		have[n] = true
	}
	var missing []string
	for _, n := range want {
		if !have[n] {
			missing = append(missing, n)
			have[n] = true
		}
	}
	return missing, nil
}

// FindByHash returns the token with the given hash, or nil when none matches.
// A missing row is not an error so the caller can map it to an auth failure.
func (r *TokenRepository) FindByHash(hash string) (*database.Token, error) {
	var t database.Token
	err := r.db.Where("token_hash = ?", hash).First(&t).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// UpdateLastUsed stamps a token's last used time.
func (r *TokenRepository) UpdateLastUsed(id string, at time.Time) error {
	return r.db.Model(&database.Token{}).Where("id = ?", id).Update("last_used_at", at).Error
}

// SetAllowedCIDRs replaces a token's source IP allowlist with a json array and
// returns how many rows matched. Select forces the write even when the value is
// cleared, and the struct field maps to the right column (the CIDR acronym does
// not snake_case to a guessable name).
func (r *TokenRepository) SetAllowedCIDRs(id, cidrJSON string) (int64, error) {
	res := r.db.Model(&database.Token{}).Where("id = ?", id).
		Select("AllowedCIDRs").
		Updates(database.Token{AllowedCIDRs: cidrJSON})
	return res.RowsAffected, res.Error
}

// Exists reports whether a token with the id exists.
func (r *TokenRepository) Exists(id string) (bool, error) {
	var n int64
	err := r.db.Model(&database.Token{}).Where("id = ?", id).Count(&n).Error
	return n > 0, err
}

// Revoke marks a token revoked and returns how many rows matched.
func (r *TokenRepository) Revoke(id string) (int64, error) {
	res := r.db.Model(&database.Token{}).Where("id = ?", id).Update("revoked", true)
	return res.RowsAffected, res.Error
}

// Delete removes a token permanently and returns how many rows were deleted.
func (r *TokenRepository) Delete(id string) (int64, error) {
	res := r.db.Where("id = ?", id).Delete(&database.Token{})
	return res.RowsAffected, res.Error
}

// List returns all tokens newest first.
func (r *TokenRepository) List() ([]database.Token, error) {
	var tokens []database.Token
	err := r.db.Order("created_at DESC").Find(&tokens).Error
	return tokens, err
}
