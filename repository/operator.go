package repository

import (
	"errors"

	"github.com/phishingclub/baitbox/database"
	"gorm.io/gorm"
)

// OperatorRepository is the data access layer for operator accounts. It also
// owns the operator scoped cascades (revoking an operator's tokens and dropping
// its sessions), so removing or resetting an operator leaves nothing usable
// behind.
type OperatorRepository struct {
	db *gorm.DB
}

// NewOperatorRepository returns an OperatorRepository.
func NewOperatorRepository(db *gorm.DB) *OperatorRepository {
	return &OperatorRepository{db: db}
}

// Count returns how many operator accounts exist.
func (r *OperatorRepository) Count() (int64, error) {
	var n int64
	err := r.db.Model(&database.Operator{}).Count(&n).Error
	return n, err
}

// CountByUsername returns how many operators have the username, ignoring case.
func (r *OperatorRepository) CountByUsername(username string) (int64, error) {
	var n int64
	err := r.db.Model(&database.Operator{}).Where("username = ? COLLATE NOCASE", username).Count(&n).Error
	return n, err
}

// Create inserts an operator row.
func (r *OperatorRepository) Create(op *database.Operator) error {
	return r.db.Create(op).Error
}

// FindByUsername returns the operator with the username, ignoring case, or nil
// when none.
func (r *OperatorRepository) FindByUsername(username string) (*database.Operator, error) {
	var op database.Operator
	err := r.db.Where("username = ? COLLATE NOCASE", username).First(&op).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &op, nil
}

// FindByID returns the operator with the id, or nil when none.
func (r *OperatorRepository) FindByID(id string) (*database.Operator, error) {
	var op database.Operator
	err := r.db.Where("id = ?", id).First(&op).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &op, nil
}

// FindOldest returns the first operator created, or nil when none.
func (r *OperatorRepository) FindOldest() (*database.Operator, error) {
	var op database.Operator
	err := r.db.Order("created_at ASC").First(&op).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &op, nil
}

// List returns all operators ordered by username.
func (r *OperatorRepository) List() ([]database.Operator, error) {
	var out []database.Operator
	return out, r.db.Order("username ASC").Find(&out).Error
}

// ClaimMFACounter advances an operator's TOTP counter only when the stored
// counter is below counter, so one captured code cannot be consumed twice at
// once. It returns how many rows changed (zero means a concurrent login already
// claimed this step).
func (r *OperatorRepository) ClaimMFACounter(id string, counter int64) (int64, error) {
	res := r.db.Model(&database.Operator{}).
		Where("id = ? AND mfa_last_counter < ?", id, counter).
		Update("mfa_last_counter", counter)
	return res.RowsAffected, res.Error
}

// DeleteOperatorCascade removes an operator together with everything that lets
// it act: its tokens are revoked, and its passkeys and sessions are deleted, all
// in one transaction so a failure part way leaves no half removed account. The
// operator row is deleted only while more than one exists, counted inside the
// one DELETE so two concurrent deletes cannot both empty the table. found is
// false when no operator has the id; deleted is false when nothing was removed
// (an unknown id, or the last operator), and then nothing else changed. Every
// statement runs on the tx handle, as SQLite has a single connection.
func (r *OperatorRepository) DeleteOperatorCascade(id string) (deleted, found bool, err error) {
	err = r.db.Transaction(func(tx *gorm.DB) error {
		res := tx.Where("id = ? AND (SELECT COUNT(*) FROM `operators`) > 1", id).Delete(&database.Operator{})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			var n int64
			if err := tx.Model(&database.Operator{}).Where("id = ?", id).Count(&n).Error; err != nil {
				return err
			}
			found = n > 0
			return nil
		}
		deleted, found = true, true
		if err := tx.Model(&database.Token{}).Where("operator_id = ?", id).Update("revoked", true).Error; err != nil {
			return err
		}
		if err := tx.Where("operator_id = ?", id).Delete(&database.OperatorCredential{}).Error; err != nil {
			return err
		}
		return tx.Where("operator_id = ?", id).Delete(&database.Session{}).Error
	})
	if err != nil {
		return false, false, err
	}
	return deleted, found, nil
}

// ResetSecondFactors turns off TOTP for an operator (clearing the secret), deletes
// every passkey it registered and drops its sessions, in one transaction. The
// TOTP counter is kept, so a code from the old secret can never be replayed. It
// returns how many passkeys were deleted.
func (r *OperatorRepository) ResetSecondFactors(id string) (int64, error) {
	var passkeys int64
	err := r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&database.Operator{}).Where("id = ?", id).
			Updates(map[string]any{"mfa_enabled": false, "mfa_secret": ""}).Error; err != nil {
			return err
		}
		res := tx.Where("operator_id = ?", id).Delete(&database.OperatorCredential{})
		if res.Error != nil {
			return res.Error
		}
		passkeys = res.RowsAffected
		_, err := dropSessions(tx, id, "")
		return err
	})
	if err != nil {
		return 0, err
	}
	return passkeys, nil
}

// UpdateFieldsDropSessions merges the given columns into an operator row and
// drops the operator's sessions in one transaction, so a failed drop leaves the
// row as it was. keepSession, when not empty, is the stored id of a session that
// stays. It returns the operator's new auth epoch.
func (r *OperatorRepository) UpdateFieldsDropSessions(
	id string, fields map[string]any, keepSession string,
) (int64, error) {
	var epoch int64
	err := r.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&database.Operator{}).Where("id = ?", id).Updates(fields).Error; err != nil {
			return err
		}
		var err error
		epoch, err = dropSessions(tx, id, keepSession)
		return err
	})
	return epoch, err
}

// dropSessions raises the operator's auth epoch and deletes its sessions except
// keepSession (a stored session id, or empty to drop them all), which moves to
// the new epoch. A login that checked the old credentials then holds the old
// epoch, so its session is refused even when created after this commits. It
// must run on a transaction handle and returns the new epoch.
func dropSessions(tx *gorm.DB, operatorID, keepSession string) (int64, error) {
	if err := tx.Model(&database.Operator{}).Where("id = ?", operatorID).
		UpdateColumn("auth_epoch", gorm.Expr("auth_epoch + 1")).Error; err != nil {
		return 0, err
	}
	var op database.Operator
	if err := tx.Select("auth_epoch").Where("id = ?", operatorID).First(&op).Error; err != nil {
		return 0, err
	}
	q := tx.Where("operator_id = ?", operatorID)
	if keepSession != "" {
		q = q.Where("id <> ?", keepSession)
	}
	if err := q.Delete(&database.Session{}).Error; err != nil {
		return 0, err
	}
	if keepSession != "" {
		if err := tx.Model(&database.Session{}).Where("id = ? AND operator_id = ?", keepSession, operatorID).
			UpdateColumn("auth_epoch", op.AuthEpoch).Error; err != nil {
			return 0, err
		}
	}
	return op.AuthEpoch, nil
}

// CountCredentialsByOperator returns how many passkeys an operator has.
func (r *OperatorRepository) CountCredentialsByOperator(operatorID string) (int64, error) {
	var n int64
	err := r.db.Model(&database.OperatorCredential{}).Where("operator_id = ?", operatorID).Count(&n).Error
	return n, err
}
