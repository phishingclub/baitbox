package repository

import (
	"github.com/phishingclub/baitbox/database"
	"gorm.io/gorm"
)

// StatsRepository counts registry rows for the admin dashboard.
type StatsRepository struct {
	db *gorm.DB
}

// NewStatsRepository returns a StatsRepository.
func NewStatsRepository(db *gorm.DB) *StatsRepository {
	return &StatsRepository{db: db}
}

// CountNamespaces returns the number of namespaces.
func (r *StatsRepository) CountNamespaces() (int64, error) {
	var n int64
	return n, r.db.Model(&database.Namespace{}).Count(&n).Error
}

// CountPackages returns the number of packages.
func (r *StatsRepository) CountPackages() (int64, error) {
	var n int64
	return n, r.db.Model(&database.Package{}).Count(&n).Error
}

// CountVersions returns the number of package versions.
func (r *StatsRepository) CountVersions() (int64, error) {
	var n int64
	return n, r.db.Model(&database.PackageVersion{}).Count(&n).Error
}

// SumDownloads returns the number of recorded downloads from the daily counts.
func (r *StatsRepository) SumDownloads() (int64, error) {
	var n int64
	return n, r.db.Model(&database.DownloadDaily{}).Select("COALESCE(SUM(count), 0)").Scan(&n).Error
}

// CountActiveTokens returns the number of tokens that are not revoked, so the
// dashboard onboarding knows a read token exists.
func (r *StatsRepository) CountActiveTokens() (int64, error) {
	var n int64
	return n, r.db.Model(&database.Token{}).Where("revoked = ?", false).Count(&n).Error
}
