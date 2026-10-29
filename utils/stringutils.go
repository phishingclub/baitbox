package utils

import (
	"fmt"
	"strings"
)

// SplitTrim splits s on sep, trims spaces from each part and drops empty parts.
// It never returns nil.
func SplitTrim(s, sep string) []string {
	out := []string{}
	for _, p := range strings.Split(s, sep) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// TruncateRunes cuts s to at most n runes.
func TruncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

// FormatMiB renders a byte count in MiB with one decimal.
func FormatMiB(n int64) string {
	return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
}
