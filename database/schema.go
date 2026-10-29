package database

import (
	"fmt"

	"gorm.io/gorm"
)

// SchemaVersion is the schema AutoMigrate builds from the entities. It is
// stamped in PRAGMA user_version, so a binary refuses a database stamped by a
// newer one.
const SchemaVersion = 1

// stampSchemaVersion writes SchemaVersion. A pragma takes no bound parameter, so
// the number is written out; a test keeps it equal to SchemaVersion.
const stampSchemaVersion = "PRAGMA user_version = 1"

// userVersion reads the schema version stamp from PRAGMA user_version.
func userVersion(db *gorm.DB) (int, error) {
	var v int
	if err := db.Raw("PRAGMA user_version").Scan(&v).Error; err != nil {
		return 0, fmt.Errorf("read schema version: %w", err)
	}
	return v, nil
}

// setupSchema refuses a database from a newer Bait Box, builds the schema and
// stamps its version.
func setupSchema(db *gorm.DB) error {
	v, err := userVersion(db)
	if err != nil {
		return err
	}
	if v > SchemaVersion {
		return fmt.Errorf("the database schema is version %d but this Bait Box knows only "+
			"version %d; run the newer Bait Box that wrote it", v, SchemaVersion)
	}
	if err := db.AutoMigrate(AllEntities()...); err != nil {
		return fmt.Errorf("automigrate: %w", err)
	}
	// usernames ignore case, so the lookups are backed by a unique index that
	// does too.
	err = db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_operators_username_nocase
		ON operators (username COLLATE NOCASE)`).Error
	if err != nil {
		return fmt.Errorf("operator username index: %w", err)
	}
	if err := db.Exec(stampSchemaVersion).Error; err != nil {
		return fmt.Errorf("write schema version: %w", err)
	}
	return nil
}
