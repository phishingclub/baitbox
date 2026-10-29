// Package embedded holds files compiled into the binary. The signing keys are
// the Ed25519 public keys used to verify a downloaded release during a self
// update. Two keys are embedded so one can be rotated while the other still
// verifies. The matching private keys live only in CI, never in the repo.
package embedded

import _ "embed"

//go:embed signingkeys/public1.bin
var SigningKey1 []byte

//go:embed signingkeys/public2.bin
var SigningKey2 []byte
