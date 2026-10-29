//go:build !dev

package acme

import "github.com/caddyserver/certmagic"

// setupIssuer points certmagic at the real Let's Encrypt production CA.
func setupIssuer(email string) error {
	certmagic.DefaultACME = certmagic.ACMEIssuer{
		CA:     certmagic.LetsEncryptProductionCA,
		Email:  email,
		Agreed: true,
	}
	return nil
}

// resetDevStorage is a no op in production so real certificates persist.
func resetDevStorage(_ string) {}
