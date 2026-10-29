//go:build dev

package acme

import (
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"os"

	"github.com/caddyserver/certmagic"
)

const devACMEURL = "https://pebble:14000/dir"

//go:embed pebble.minica.pem
var pebbleRootPEM []byte

// setupIssuer points certmagic at the local pebble ACME server and trusts the
// embedded pebble root so issuance succeeds in the dev stack.
func setupIssuer(email string) error {
	block, _ := pem.Decode(pebbleRootPEM)
	if block == nil {
		return errors.New("failed to parse pebble root certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	// dev only: serve a self signed cert for an unmatched SNI so the vite proxy
	// (which may not send SNI) can reach the backend over TLS.
	EnableDevFallback()
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	certmagic.DefaultACME = certmagic.ACMEIssuer{
		CA:           devACMEURL,
		TestCA:       devACMEURL,
		Email:        email,
		Agreed:       true,
		TrustedRoots: pool,
		// pebble validates challenges on these alternate ports, not 80/443.
		AltHTTPPort:    8000,
		AltTLSALPNPort: 8001,
	}
	return nil
}

// resetDevStorage removes any stored ACME account and certificates so a fresh
// account is created against the current pebble instance.
func resetDevStorage(path string) {
	_ = os.RemoveAll(path)
}
