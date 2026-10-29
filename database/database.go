package database

import (
	"fmt"
	"os"
	"path/filepath"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Open opens the SQLite database at path, applies the connection pragmas,
// refuses a database from a newer Bait Box and builds the schema (see
// schema.go). WAL plus a single writer connection matches the sibling
// projects: SQLite is a single writer store.
func Open(path string) (*gorm.DB, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("create db dir: %w", err)
		}
	}
	db, err := openRaw(path)
	if err != nil {
		return nil, err
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("sql db handle: %w", err)
	}
	if err := setupSchema(db); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	return db, nil
}

// openRaw opens the SQLite database at path with the connection pragmas and a
// single connection, without touching the schema.
func openRaw(path string) (*gorm.DB, error) {
	dsn := path + "?_busy_timeout=5000&_journal_mode=WAL&_foreign_keys=on"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("sql db handle: %w", err)
	}
	sqlDB.SetMaxOpenConns(1)
	return db, nil
}
