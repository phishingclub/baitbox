package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// TokenPrefixLen is how many leading characters of a token are stored in the
// clear so a token can be looked up without a full table scan.
const TokenPrefixLen = 8

// NewBearerToken returns a fresh bearer token string and its sha256 hash. The
// clear token is shown to the operator once; only the hash is stored.
func NewBearerToken() (token string, hash string) {
	token = Token()
	return token, HashToken(token)
}

// HashToken returns the hex sha256 of a bearer token. A high entropy token does
// not need a slow hash, so a single indexed sha256 lookup is used, matching the
// API key handling in the sibling projects.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// TokenPrefix returns the stored prefix of a token.
func TokenPrefix(token string) string {
	if len(token) < TokenPrefixLen {
		return token
	}
	return token[:TokenPrefixLen]
}

// ParseBearer extracts the token from an Authorization header value, accepting
// an optional "Bearer " prefix. Returns empty when no token is present.
func ParseBearer(header string) string {
	h := strings.TrimSpace(header)
	if h == "" {
		return ""
	}
	if len(h) >= 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return h
}
