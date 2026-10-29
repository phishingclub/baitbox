package service

import (
	"testing"
	"time"

	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/repository"
)

// TestDownloadCounts: each download adds one to the package, version and daily
// counts, repeats included, and the dashboard total reads the daily counts.
func TestDownloadCounts(t *testing.T) {
	db := newTestDB(t)
	svc := registryOverDB(t, db)
	v := publishPage(t, svc, "acme", "login", "1.0.0")
	for i := 0; i < 3; i++ {
		rc, err := svc.OpenArchive(v)
		if err != nil {
			t.Fatalf("open archive: %v", err)
		}
		rc.Close()
	}
	var rows []database.DownloadDaily
	if err := db.Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	today := time.Now().UTC().Format("2006-01-02")
	if len(rows) != 1 || rows[0].Count != 3 || rows[0].Day != today || rows[0].VersionID != v.ID || rows[0].PackageID != v.PackageID {
		t.Fatalf("daily rows = %+v, want one row of 3 for %s today", rows, v.ID)
	}

	stats := NewStatsService(repository.NewStatsRepository(db))
	if c, err := stats.Counts(); err != nil || c.Downloads != 3 {
		t.Fatalf("downloads = %d (%v), want 3", c.Downloads, err)
	}
	var pkg database.Package
	var ver database.PackageVersion
	if err := db.First(&pkg, "id = ?", v.PackageID).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.First(&ver, "id = ?", v.ID).Error; err != nil {
		t.Fatal(err)
	}
	if pkg.DownloadCount != 3 || ver.DownloadCount != 3 {
		t.Fatalf("package count %d version count %d, want 3 and 3", pkg.DownloadCount, ver.DownloadCount)
	}
}
