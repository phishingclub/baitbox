package repository

import (
	"errors"

	"github.com/phishingclub/baitbox/database"
	"gorm.io/gorm"
)

// SessionRepository is the data access layer for operator sessions. Validating a
// session also loads its owning operator, so that read lives here too.
type SessionRepository struct {
	db *gorm.DB
}

// NewSessionRepository returns a SessionRepository.
func NewSessionRepository(db *gorm.DB) *SessionRepository {
	return &SessionRepository{db: db}
}

// Create inserts a session row.
func (r *SessionRepository) Create(sess *database.Session) error {
	return r.db.Create(sess).Error
}

// FindByID returns the session with the id, or nil when none.
func (r *SessionRepository) FindByID(id string) (*database.Session, error) {
	var sess database.Session
	err := r.db.Where("id = ?", id).First(&sess).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &sess, nil
}

// FindOperator returns the operator that owns a session, or nil when none.
func (r *SessionRepository) FindOperator(operatorID string) (*database.Operator, error) {
	var op database.Operator
	err := r.db.Where("id = ?", operatorID).First(&op).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &op, nil
}

// Touch merges the given columns into a session row.
func (r *SessionRepository) Touch(id string, fields map[string]any) error {
	return r.db.Model(&database.Session{}).Where("id = ?", id).Updates(fields).Error
}

// Delete removes a session by id.
func (r *SessionRepository) Delete(id string) error {
	return r.db.Where("id = ?", id).Delete(&database.Session{}).Error
}
