package database

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"gorm.io/gorm"
)

func closeTestDB(t *testing.T, db *gorm.DB) {
	t.Helper()
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	if err := sqlDB.Close(); err != nil {
		t.Fatal(err)
	}
}

func readVersion(t *testing.T, db *gorm.DB) int {
	t.Helper()
	v, err := userVersion(db)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestSchemaStampMatchesVersion: the written out pragma stamps SchemaVersion.
func TestSchemaStampMatchesVersion(t *testing.T) {
	if want := fmt.Sprintf("PRAGMA user_version = %d", SchemaVersion); stampSchemaVersion != want {
		t.Fatalf("stamp %q, want %q", stampSchemaVersion, want)
	}
}

// TestSchemaFreshDatabaseIsCurrent: a new database is stamped with the schema
// version, and opening it again keeps it there.
func TestSchemaFreshDatabaseIsCurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fresh.sqlite3")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got := readVersion(t, db); got != SchemaVersion {
		t.Fatalf("version = %d, want %d", got, SchemaVersion)
	}
	closeTestDB(t, db)
	db, err = Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer closeTestDB(t, db)
	if got := readVersion(t, db); got != SchemaVersion {
		t.Fatalf("version after reopen = %d, want %d", got, SchemaVersion)
	}
}

// TestSchemaNewerDatabaseRefused: a database stamped by a newer binary is
// refused, and its stamp is left as it was.
func TestSchemaNewerDatabaseRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "newer.sqlite3")
	db, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Exec("PRAGMA user_version = 2").Error; err != nil {
		t.Fatal(err)
	}
	closeTestDB(t, db)

	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "newer Bait Box") {
		t.Fatalf("open of a newer database = %v, want a refusal", err)
	}
	db, err = openRaw(path)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestDB(t, db)
	if got := readVersion(t, db); got != 2 {
		t.Fatalf("version after refusal = %d, want 2", got)
	}
}

// TestSchemaUsernameIndexIgnoresCase: two operators whose names differ only in
// case cannot both exist.
func TestSchemaUsernameIndexIgnoresCase(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "index.sqlite3"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer closeTestDB(t, db)
	if err := db.Create(&Operator{Username: "Alice"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&Operator{Username: "alice"}).Error; err == nil {
		t.Fatal("a username differing only in case was accepted")
	}
}
