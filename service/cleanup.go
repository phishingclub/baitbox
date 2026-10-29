package service

import (
	"context"
	"log"
	"time"

	"github.com/phishingclub/baitbox/repository"
)

// Cleanup job timing and batch size. A batch of a few thousand rows is deleted
// in a few milliseconds, and the pause between batches lets requests waiting
// for the single SQLite connection get their turn.
const (
	cleanupBatchSize  = 2000
	cleanupBatchPause = 50 * time.Millisecond
	cleanupTick       = time.Hour
)

// CleanupService deletes expired sessions and drops expired memory entries, so
// the database and memory stop growing forever. SQLite reuses the freed pages
// for new rows; the file does not shrink.
type CleanupService struct {
	repo   *repository.CleanupRepository
	sweeps []func()
	batch  int
	pause  time.Duration
	now    func() time.Time
}

// NewCleanupService takes sweeps, cleanups of expired memory entries run with
// every pass.
func NewCleanupService(repo *repository.CleanupRepository, sweeps ...func()) *CleanupService {
	return &CleanupService{repo: repo, sweeps: sweeps, batch: cleanupBatchSize, pause: cleanupBatchPause, now: time.Now}
}

// deleteInBatches calls del until a batch comes back short, pausing between
// batches. It stops early when ctx is done.
func (s *CleanupService) deleteInBatches(ctx context.Context, del func(limit int) (int64, error)) (int64, error) {
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, err := del(s.batch)
		total += n
		if err != nil || n < int64(s.batch) {
			return total, err
		}
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		case <-time.After(s.pause):
		}
	}
}

// RunOnce drops expired memory entries and deletes expired sessions, and
// returns how many sessions it deleted.
func (s *CleanupService) RunOnce(ctx context.Context) (int64, error) {
	for _, sweep := range s.sweeps {
		sweep()
	}
	now := s.now()
	return s.deleteInBatches(ctx, func(limit int) (int64, error) {
		return s.repo.DeleteExpiredSessions(ctx, now, limit)
	})
}

// Start runs a cleanup now and then every hour until ctx is done. The returned
// channel is closed when the job has stopped, so the caller can wait for it
// before closing the database.
func (s *CleanupService) Start(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(cleanupTick)
		defer ticker.Stop()
		for {
			n, err := s.RunOnce(ctx)
			if err != nil && ctx.Err() == nil {
				log.Printf("cleanup: expired sessions: %v", err)
			}
			if n > 0 {
				log.Printf("cleanup: deleted %d expired sessions", n)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return done
}
