package repository

import (
	"context"
	"time"

	"github.com/phishingclub/baitbox/database"
	"gorm.io/gorm"
)

// CleanupRepository deletes expired sessions for the cleanup job. Each call
// deletes at most one batch, picked by rowid, so one statement never holds the
// SQLite write lock for long.
type CleanupRepository struct {
	db *gorm.DB
}

// NewCleanupRepository returns a CleanupRepository.
func NewCleanupRepository(db *gorm.DB) *CleanupRepository {
	return &CleanupRepository{db: db}
}

// maxZoneOffset is wider than any real UTC offset (they run from -12h to +14h).
const maxZoneOffset = 15 * time.Hour

// DeleteExpiredSessions deletes one batch of sessions past their idle or hard
// expiry at now. When ctx is done the call stops waiting for the connection
// and the running statement is interrupted.
//
// Times are stored as text with the offset of the zone they were written in, so
// a plain text compare is wrong when offsets differ (DST, a changed TZ).
// julianday turns both sides into the same instant scale. The text compare
// before it is only a coarse filter that lets SQLite use an index: the wall
// clock text of a stored time is within the largest offset of its UTC time, so
// the coarse filter never drops a match.
func (r *CleanupRepository) DeleteExpiredSessions(ctx context.Context, now time.Time, limit int) (int64, error) {
	now = now.UTC()
	coarse := now.Add(maxZoneOffset).Format("2006-01-02 15:04:05")
	db := r.db.WithContext(ctx)
	batch := db.Model(&database.Session{}).
		Select("rowid").
		Where(`(idle_expires_at <= ? AND julianday(idle_expires_at) < julianday(?))
			OR (max_expires_at <= ? AND julianday(max_expires_at) < julianday(?))`,
			coarse, now, coarse, now).
		Limit(limit)
	res := db.Where("rowid IN (?)", batch).Delete(&database.Session{})
	return res.RowsAffected, res.Error
}
