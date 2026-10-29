// Package crypto holds the random, password and token primitives used across
// Bait Box. These are borrowed in spirit from the sibling projects: a
// CSPRNG for ids and tokens, Argon2id for operator passwords, and a sha256 hash
// for bearer tokens.
package crypto

import (
	"crypto/rand"
	"encoding/base64"
)

// unambiguous omits characters that are easy to misread.
const unambiguous = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// Bytes returns n cryptographically random bytes. A failure of the system CSPRNG
// is unrecoverable, so it panics rather than hand back weak or zero randomness.
func Bytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand read failed: " + err.Error())
	}
	return b
}

// String returns a random string of length n from the unambiguous alphabet.
func String(n int) string {
	b := Bytes(n)
	out := make([]byte, n)
	for i := range b {
		out[i] = unambiguous[int(b[i])%len(unambiguous)]
	}
	return string(out)
}

// Token returns a 32 byte url safe session or secret token.
func Token() string {
	return base64.RawURLEncoding.EncodeToString(Bytes(32))
}
