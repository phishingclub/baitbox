package model

import (
	"regexp"
	"strings"
)

// colorTokens is the fixed set of named color tokens an operator may pick for a
// namespace or a tag.
var colorTokens = map[string]bool{
	"slate": true, "red": true, "orange": true, "amber": true, "green": true,
	"teal": true, "sky": true, "blue": true, "violet": true, "pink": true,
}

// hexColorRe matches a custom color: a six digit hex like #1a2b3c. It is strict so
// the stored value is safe to use as an inline color.
var hexColorRe = regexp.MustCompile(`^#[0-9a-f]{6}$`)

// NormalizeColor returns a named token or a #rrggbb hex when valid, otherwise
// empty (no color). Every path that stores a color (admin edit and bundle
// import) runs it, so only allowlisted values are ever stored.
func NormalizeColor(c string) string {
	c = strings.ToLower(strings.TrimSpace(c))
	if colorTokens[c] || hexColorRe.MatchString(c) {
		return c
	}
	return ""
}
