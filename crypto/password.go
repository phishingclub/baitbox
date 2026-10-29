package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters, matching the sibling projects: 64 MiB, 2 passes, 1 lane,
// 64 byte output.
const (
	argonMemory  = 64 * 1024
	argonTime    = 2
	argonThreads = 1
	argonKeyLen  = 64
	argonSaltLen = 16
)

// ErrInvalidHash is returned when a stored hash cannot be parsed.
var ErrInvalidHash = errors.New("invalid password hash")

// ErrBusy is returned when too many password hashes already run at once. Nothing
// was checked; the caller should ask the client to try again shortly.
var ErrBusy = errors.New("too many password checks running, try again")

// maxHashSlots caps the slots on large machines, since each run holds 64 MiB.
const maxHashSlots = 16

// hashSlots bounds how many Argon2id runs happen at once, so a flood of logins
// cannot use up memory. A run that finds every slot taken fails with ErrBusy
// instead of waiting in an unbounded queue.
var hashSlots = make(chan struct{}, hashSlotCount())

// hashSlotCount is twice the CPU count, at least 2 and at most maxHashSlots.
func hashSlotCount() int {
	n := 2 * runtime.NumCPU()
	if n < 2 {
		n = 2
	}
	if n > maxHashSlots {
		n = maxHashSlots
	}
	return n
}

// acquireHashSlot takes a slot without waiting and reports whether it got one.
func acquireHashSlot() bool {
	select {
	case hashSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func releaseHashSlot() { <-hashSlots }

// HoldHashSlots takes every free hash slot, so each hash fails with ErrBusy
// until the returned release is called. Tests use it to act out a busy server.
func HoldHashSlots() (release func()) {
	n := 0
	for acquireHashSlot() {
		n++
	}
	return func() {
		for ; n > 0; n-- {
			releaseHashSlot()
		}
	}
}

// HashPassword returns an encoded Argon2id hash of password, or ErrBusy when
// every hash slot is taken.
func HashPassword(password string) (string, error) {
	if !acquireHashSlot() {
		return "", ErrBusy
	}
	defer releaseHashSlot()
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf(
		"argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// TakeHashSlot takes a hash slot without waiting, for a caller that must learn
// the server is busy before it counts the attempt anywhere. It reports false
// when every slot is taken. Pass the slot to VerifyPasswordInSlot and call
// release once done.
func TakeHashSlot() (release func(), ok bool) {
	if !acquireHashSlot() {
		return nil, false
	}
	var once sync.Once
	return func() { once.Do(releaseHashSlot) }, true
}

// VerifyPassword reports whether password matches the encoded hash, in constant
// time over the derived key. It returns ErrBusy when every hash slot is taken.
func VerifyPassword(password, encoded string) (bool, error) {
	return verifyPassword(password, encoded, true)
}

// VerifyPasswordInSlot is VerifyPassword for a caller that already holds a slot
// from TakeHashSlot.
func VerifyPasswordInSlot(password, encoded string) (bool, error) {
	return verifyPassword(password, encoded, false)
}

// verifyPassword takes a hash slot first when takeSlot is set.
func verifyPassword(password, encoded string, takeSlot bool) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 || parts[0] != "argon2id" {
		return false, ErrInvalidHash
	}
	var version, mem, t, p int
	if _, err := fmt.Sscanf(parts[1], "v=%d", &version); err != nil {
		return false, ErrInvalidHash
	}
	if _, err := fmt.Sscanf(parts[2], "m=%d,t=%d,p=%d", &mem, &t, &p); err != nil {
		return false, ErrInvalidHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false, ErrInvalidHash
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, ErrInvalidHash
	}
	if takeSlot {
		if !acquireHashSlot() {
			return false, ErrBusy
		}
		defer releaseHashSlot()
	}
	got := argon2.IDKey([]byte(password), salt, uint32(t), uint32(mem), uint8(p), uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
