package crypto

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// totpPeriod is the time step in seconds and totpDigits the code length, the
// defaults every authenticator app expects (RFC 6238, TOTP-SHA1).
const (
	totpPeriod = 30
	totpDigits = 6
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a fresh base32 TOTP secret (160 bits).
func NewTOTPSecret() string {
	return b32.EncodeToString(Bytes(20))
}

// totpAt computes the TOTP code for a secret at a given counter (unix/period).
func totpAt(secret string, counter uint64) (string, bool) {
	key, err := b32.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil || len(key) == 0 {
		return "", false
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	return fmt.Sprintf("%0*d", totpDigits, bin%pow10(totpDigits)), true
}

func pow10(n int) uint32 {
	p := uint32(1)
	for i := 0; i < n; i++ {
		p *= 10
	}
	return p
}

// VerifyTOTPAt verifies a code against the +/-1 step window and, on a match,
// returns the time step counter it matched. The counter lets callers enforce
// single use (reject a counter that was already consumed) to stop replay of a
// captured code within the window.
func VerifyTOTPAt(secret, code string) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != totpDigits {
		return 0, false
	}
	counter := uint64(time.Now().Unix() / totpPeriod)
	for _, c := range []uint64{counter - 1, counter, counter + 1} {
		want, ok := totpAt(secret, c)
		if ok && subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return int64(c), true
		}
	}
	return 0, false
}

// TOTPURI builds an otpauth:// URI an authenticator app can import, by QR or by
// pasting. issuer and account label the entry in the app.
func TOTPURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprintf("%d", totpDigits))
	q.Set("period", fmt.Sprintf("%d", totpPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}
