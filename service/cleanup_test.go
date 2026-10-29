package service

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/repository"
	"gorm.io/gorm"
)

// TestCleanupDeletesOnlyExpiredSessions: a pass runs the sweeps and deletes
// expired sessions in several batches, and keeps live ones.
func TestCleanupDeletesOnlyExpiredSessions(t *testing.T) {
	db := newTestDB(t)
	now := time.Now()
	opID := seedOperator(t, db, "admin")
	for i := 0; i < 25; i++ {
		mustCreate(t, db, &database.Session{ID: fmt.Sprintf("idle%d", i), OperatorID: opID, IdleExpiresAt: now.Add(-time.Minute), MaxExpiresAt: now.Add(time.Hour)})
	}
	mustCreate(t, db, &database.Session{ID: "hard", OperatorID: opID, IdleExpiresAt: now.Add(time.Hour), MaxExpiresAt: now.Add(-time.Minute)})
	mustCreate(t, db, &database.Session{ID: "live", OperatorID: opID, IdleExpiresAt: now.Add(time.Hour), MaxExpiresAt: now.Add(2 * time.Hour)})

	swept := 0
	svc := NewCleanupService(repository.NewCleanupRepository(db), func() { swept++ })
	svc.batch = 10
	svc.pause = 0
	n, err := svc.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if n != 26 || swept != 1 {
		t.Fatalf("deleted %d swept %d, want 26 and one sweep", n, swept)
	}
	var ids []string
	db.Model(&database.Session{}).Pluck("id", &ids)
	if len(ids) != 1 || ids[0] != "live" {
		t.Fatalf("sessions left = %v, want only live", ids)
	}
}

// TestCleanupBatches: deleting runs one bounded batch at a time until a batch
// comes back short, and stops when the context is done.
func TestCleanupBatches(t *testing.T) {
	svc := &CleanupService{batch: 10}
	left := int64(35)
	calls := 0
	del := func(limit int) (int64, error) {
		calls++
		n := min(left, int64(limit))
		left -= n
		return n, nil
	}
	total, err := svc.deleteInBatches(context.Background(), del)
	if err != nil || total != 35 || calls != 4 {
		t.Fatalf("total %d calls %d err %v, want 35 in 4 calls", total, calls, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	left, calls = 35, 0
	if _, err := svc.deleteInBatches(ctx, del); err == nil || calls != 0 {
		t.Fatalf("a done context must stop before deleting, calls %d err %v", calls, err)
	}
}

// TestCleanupStartStops: the job runs a pass at start and its channel closes
// once the context is done.
func TestCleanupStartStops(t *testing.T) {
	db := newTestDB(t)
	swept := make(chan struct{}, 1)
	svc := NewCleanupService(repository.NewCleanupRepository(db), func() {
		select {
		case swept <- struct{}{}:
		default:
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := svc.Start(ctx)
	select {
	case <-swept:
	case <-time.After(5 * time.Second):
		t.Fatal("no pass at start")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("job did not stop")
	}
}

func mustCreate(t *testing.T, db *gorm.DB, row any) {
	t.Helper()
	if err := db.Create(row).Error; err != nil {
		t.Fatalf("create %T: %v", row, err)
	}
}
