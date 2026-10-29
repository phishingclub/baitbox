package model

import (
	"errors"
	"net"
	"strings"
)

// Validation errors for a token write.
var (
	ErrInvalidEntitlement = errors.New("each namespace must be \"*\" or a valid namespace name")
	ErrInvalidAllowedCIDR = errors.New("each allowed IP must be a CIDR (10.0.0.0/8) or an IP address")
)

// Token is the validatable form of a token write. Entitlements lists the
// namespaces the token may read (a single "*" grants all); AllowedCIDRs limits
// the source IPs it may be used from (empty means unrestricted).
type Token struct {
	Entitlements []string
	AllowedCIDRs []string
}

// Validate checks the entitlements and the source IP allowlist. A bad
// entitlement would mint a token scoped to a namespace that can never exist; a
// bad CIDR would restrict a token to an address range it never matches.
func (t Token) Validate() error {
	if err := ValidateEntitlements(t.Entitlements); err != nil {
		return err
	}
	return ValidateAllowedCIDRs(t.AllowedCIDRs)
}

// ValidateEntitlements checks each entry is the wildcard or a valid namespace
// slug.
func ValidateEntitlements(entitlements []string) error {
	for _, ns := range entitlements {
		if ns != "*" && !ValidNamespaceName(ns) {
			return ErrInvalidEntitlement
		}
	}
	return nil
}

// ValidateAllowedCIDRs checks each entry is a parseable CIDR or bare IP.
func ValidateAllowedCIDRs(allowedCIDRs []string) error {
	for _, c := range allowedCIDRs {
		if !ValidCIDR(c) {
			return ErrInvalidAllowedCIDR
		}
	}
	return nil
}

// ValidCIDR reports whether s is a parseable CIDR or a bare IP.
func ValidCIDR(s string) bool {
	s = strings.TrimSpace(s)
	if _, _, err := net.ParseCIDR(s); err == nil {
		return true
	}
	return net.ParseIP(s) != nil
}
