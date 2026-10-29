package model

import "errors"

// MaxNamespaceDescriptionRunes caps a namespace description. SQLite ignores the
// column size tags, so the cap is enforced here on every write path (admin
// create, admin edit and bundle import).
const MaxNamespaceDescriptionRunes = 4000

// ErrInvalidNamespaceName is returned when a namespace name is not a usable
// lowercase slug. A package address is namespace/name, so the name must be able
// to stand as the namespace part of an address.
var ErrInvalidNamespaceName = errors.New(
	"name must be lowercase letters, numbers and dashes (a package address is namespace/name)",
)

// ErrNamespaceDescriptionTooLong is returned when a namespace description is
// over MaxNamespaceDescriptionRunes.
var ErrNamespaceDescriptionTooLong = errors.New("description must be 4000 characters or fewer")

// Namespace is the validatable form of a namespace write. Description is
// expected already trimmed by the caller.
type Namespace struct {
	Name        string
	Description string
}

// Validate checks the namespace name is a usable slug and the description fits
// its cap.
func (n Namespace) Validate() error {
	if !ValidNamespaceName(n.Name) {
		return ErrInvalidNamespaceName
	}
	return ValidateNamespaceDescription(n.Description)
}

// ValidateNamespaceDescription checks the namespace description cap, for an
// edit that does not change the name.
func ValidateNamespaceDescription(description string) error {
	if len([]rune(description)) > MaxNamespaceDescriptionRunes {
		return ErrNamespaceDescriptionTooLong
	}
	return nil
}
