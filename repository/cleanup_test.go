package repository

import (
	"context"
	"sort"
	"testing"
	"time"

	"github.com/phishingclub/baitbox/database"
)

func cleanupSession(id string, idle, max time.Time) *database.Session {
	return &database.Session{
		ID: id, OperatorID: "o", IP: "ip",
		IdleExpiresAt: idle, MaxExpiresAt: max, LastActiveAt: idle, CreatedAt: idle,
	}
}

func sessionIDs(t *testing.T, r *CleanupRepository) []string {
	t.Helper()
	var ids []string
	if err := r.db.Model(&database.Session{}).Order("id").Pluck("id", &ids).Error; err != nil {
		t.Fatal(err)
	}
	return ids
}

// TestCleanupMixedOffsets: stored times carry the offset of the zone they were
// written in. Across a DST change the text order differs from the time order, so
// the cutoff must compare instants. 02:20+01:00 is 01:20 UTC and 03:05+02:00 is
// 01:05 UTC, so at 01:10 UTC only the second session has expired. The same holds
// for the hard expiry.
func TestCleanupMixedOffsets(t *testing.T) {
	_, db := newQueryTestRepo(t)
	cr := NewCleanupRepository(db)
	now := time.Date(2026, 3, 29, 1, 10, 0, 0, time.UTC)
	winter := time.FixedZone("CET", 3600)
	summer := time.FixedZone("CEST", 7200)
	later := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	keepAt := time.Date(2026, 3, 29, 2, 20, 0, 0, winter)
	dropAt := time.Date(2026, 3, 29, 3, 5, 0, 0, summer)

	for _, s := range []*database.Session{
		cleanupSession("keep idle", keepAt, later),
		cleanupSession("drop idle", dropAt, later),
		cleanupSession("keep max", later, keepAt),
		cleanupSession("drop max", later, dropAt),
	} {
		if err := db.Create(s).Error; err != nil {
			t.Fatal(err)
		}
	}
	// the stored text keeps each zone's offset, which is what makes the text
	// order differ from the time order.
	var stored string
	err := db.Model(&database.Session{}).Where("id = ?", "drop idle").
		Pluck("idle_expires_at", &stored).Error
	if err != nil || stored[len(stored)-6:] != "+02:00" {
		t.Fatalf("stored %q err=%v, want a +02:00 offset", stored, err)
	}

	if n, err := cr.DeleteExpiredSessions(context.Background(), now, 100); err != nil || n != 2 {
		t.Fatalf("sessions deleted = %d err=%v, want 2", n, err)
	}
	ids := sessionIDs(t, cr)
	sort.Strings(ids)
	if len(ids) != 2 || ids[0] != "keep idle" || ids[1] != "keep max" {
		t.Fatalf("sessions left %v, want [keep idle keep max]", ids)
	}
}

// TestCleanupBatchLimit: one call deletes at most limit sessions.
func TestCleanupBatchLimit(t *testing.T) {
	_, db := newQueryTestRepo(t)
	cr := NewCleanupRepository(db)
	past := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, id := range []string{"a", "b", "c"} {
		if err := db.Create(cleanupSession(id, past, past)).Error; err != nil {
			t.Fatal(err)
		}
	}
	if n, err := cr.DeleteExpiredSessions(context.Background(), time.Now(), 2); err != nil || n != 2 {
		t.Fatalf("first batch = %d err=%v, want 2", n, err)
	}
	if n, err := cr.DeleteExpiredSessions(context.Background(), time.Now(), 2); err != nil || n != 1 {
		t.Fatalf("second batch = %d err=%v, want 1", n, err)
	}
	if ids := sessionIDs(t, cr); len(ids) != 0 {
		t.Fatalf("sessions left %v", ids)
	}
}
