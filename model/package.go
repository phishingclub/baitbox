package model

import (
	"errors"
	"strings"
)

// Rune length caps on the free text package fields. SQLite ignores the column
// size tags, so these are enforced here on every write path (publish and meta
// edit) instead of being checked again by hand in each controller.
const (
	MaxTitleRunes       = 255
	MaxDescriptionRunes = 4000
)

// maxTags caps how many tags a package keeps, and maxTagLen caps each tag's
// length in bytes, so a typo cannot bloat a package and tags stay filterable.
const (
	maxTags   = 20
	maxTagLen = 32
)

// Validation errors for a package write.
var (
	ErrPackageFieldsRequired = errors.New("namespace, name, type and version are required")
	ErrTitleTooLong          = errors.New("title must be 255 characters or fewer")
	ErrDescriptionTooLong    = errors.New("description must be 4000 characters or fewer")
)

// Package is the validatable form of a package write. Title and Description are
// expected already trimmed by the caller.
type Package struct {
	Namespace   string
	Name        string
	Type        string
	Version     string
	Title       string
	Description string
}

// Validate checks the fields required to publish a package and the free text
// caps. The required check runs first so an empty request reports the missing
// fields before the length checks.
func (p Package) Validate() error {
	if p.Namespace == "" || p.Name == "" || p.Version == "" || p.Type == "" {
		return ErrPackageFieldsRequired
	}
	return ValidatePackageMeta(p.Title, p.Description)
}

// ValidatePackageMeta checks the editable free text caps shared by the publish
// and meta edit paths. Title and Description are expected already trimmed.
func ValidatePackageMeta(title, description string) error {
	if len([]rune(title)) > MaxTitleRunes {
		return ErrTitleTooLong
	}
	if len([]rune(description)) > MaxDescriptionRunes {
		return ErrDescriptionTooLong
	}
	return nil
}

// CleanTags normalizes operator supplied tags: trim, lowercase, drop empties,
// cap each length, dedupe, and keep at most maxTags, so tags stay tidy and
// filterable.
func CleanTags(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, t := range in {
		t = strings.ToLower(strings.TrimSpace(t))
		if t == "" || seen[t] {
			continue
		}
		if len(t) > maxTagLen {
			t = t[:maxTagLen]
		}
		seen[t] = true
		out = append(out, t)
		if len(out) >= maxTags {
			break
		}
	}
	return out
}
