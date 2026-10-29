package repository

import (
	"errors"

	"github.com/phishingclub/baitbox/database"
	"gorm.io/gorm"
)

// WebAuthnRepository is the data access layer for operator passkeys and the
// operator lookup the login ceremony needs.
type WebAuthnRepository struct {
	db *gorm.DB
}

// NewWebAuthnRepository returns a WebAuthnRepository.
func NewWebAuthnRepository(db *gorm.DB) *WebAuthnRepository {
	return &WebAuthnRepository{db: db}
}

// ListByOperator returns an operator's passkeys, oldest first.
func (r *WebAuthnRepository) ListByOperator(operatorID string) ([]database.OperatorCredential, error) {
	var rows []database.OperatorCredential
	err := r.db.Where("operator_id = ?", operatorID).Order("created_at ASC").Find(&rows).Error
	return rows, err
}

// CountByOperator returns how many passkeys an operator has.
func (r *WebAuthnRepository) CountByOperator(operatorID string) (int64, error) {
	var n int64
	err := r.db.Model(&database.OperatorCredential{}).Where("operator_id = ?", operatorID).Count(&n).Error
	return n, err
}

// DeleteDropSessions removes one of an operator's passkeys and, when one was
// removed, drops the operator's other sessions in the same transaction. It
// returns how many passkeys were deleted (zero when the id is unknown or belongs
// to another operator, and then no session is touched). keepSession is the stored
// id of the session that stays, or empty to drop them all.
func (r *WebAuthnRepository) DeleteDropSessions(rowID, operatorID, keepSession string) (int64, error) {
	var n int64
	err := r.db.Transaction(func(tx *gorm.DB) error {
		res := tx.Where("id = ? AND operator_id = ?", rowID, operatorID).Delete(&database.OperatorCredential{})
		if res.Error != nil {
			return res.Error
		}
		n = res.RowsAffected
		if n == 0 {
			return nil
		}
		_, err := dropSessions(tx, operatorID, keepSession)
		return err
	})
	return n, err
}

// CreateDropSessions stores a new passkey credential and drops the operator's
// other sessions in one transaction. keepSession is the stored id of the session
// that stays, or empty to drop them all.
func (r *WebAuthnRepository) CreateDropSessions(row *database.OperatorCredential, keepSession string) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(row).Error; err != nil {
			return err
		}
		_, err := dropSessions(tx, row.OperatorID, keepSession)
		return err
	})
}

// FindOperator returns the operator with the id, or nil when none.
func (r *WebAuthnRepository) FindOperator(operatorID string) (*database.Operator, error) {
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

// UpdateCredential merges the given columns into a credential row.
func (r *WebAuthnRepository) UpdateCredential(rowID string, fields map[string]any) error {
	return r.db.Model(&database.OperatorCredential{}).Where("id = ?", rowID).Updates(fields).Error
}
