// Package acme serves HTTPS with certificates obtained on demand via certmagic.
// It is copied from the sibling projects: certificates are issued lazily per
// host and gated by an allowlist, so startup never blocks. The issuer is chosen
// at build time, pebble under the dev tag and Let's Encrypt otherwise. A self
// signed mode is provided for running behind a TLS terminating front such as
// Cloudflare in Full mode.
package acme

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
)

// quietHandshakeErrors drops failed TLS handshake lines from the server error
// log and passes everything else through. Those lines come from scanners
// probing the address with a name the server does not serve, or speaking plain
// HTTP to the TLS port. Nothing reaches a handler, so the line only fills the
// log.
type quietHandshakeErrors struct{}

func (quietHandshakeErrors) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("http: TLS handshake error")) {
		return len(p), nil
	}
	return os.Stderr.Write(p)
}

// server timeouts. ReadHeaderTimeout and IdleTimeout bound slow or idle
// clients. ReadTimeout covers the whole request including the body. A handler
// that takes a large upload (an admin import, package author, draft or preview)
// extends the read deadline of its own request once the caller is signed in.
// WriteTimeout is left unset because a bundle export or a large package
// download streams for as long as the transfer takes.
const (
	readHeaderTimeout = 10 * time.Second
	readTimeout       = time.Minute
	idleTimeout       = 120 * time.Second
	maxHeaderBytes    = 1 << 20
)

// ShutdownTimeout is how long a shutdown waits for requests in flight (an
// upload, an import, a download) to finish before their connections are closed.
// It stays below the systemd stop timeout so the process exits on its own.
const ShutdownTimeout = 30 * time.Second

func newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ErrorLog:          log.New(quietHandshakeErrors{}, "", log.LstdFlags),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}
}

var localNames = map[string]bool{"localhost": true, "127.0.0.1": true}

// devFallback, when set by the dev issuer, makes the TLS layer serve the
// localhost self signed certificate for an unmatched or missing SNI instead of
// failing the handshake. This lets the vite dev proxy (which does not always
// send SNI) reach the backend over TLS. It is never set in production.
var devFallback bool

// EnableDevFallback is called by the dev issuer to turn on the fallback.
func EnableDevFallback() { devFallback = true }

// isLocal reports whether a handshake should be served the localhost
// certificate: a local name or no name at all, and only from a loopback
// connection. A remote client that sends a local name is treated like any
// other unknown name.
func isLocal(hello *tls.ClientHelloInfo) bool {
	if hello.ServerName != "" && !localNames[strings.ToLower(hello.ServerName)] {
		return false
	}
	if hello.Conn == nil {
		return false
	}
	host, _, err := net.SplitHostPort(hello.Conn.RemoteAddr().String())
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Listener pairs a listen address with the handler served on it.
type Listener struct {
	Addr    string
	Handler http.Handler
	// Stop, when set, closes this listener once the channel is closed. The
	// other listeners keep serving.
	Stop <-chan struct{}
}

// ListenAndServe serves every listener over HTTPS for the given hosts, sharing
// one TLS config so a certificate is obtained once per host on demand at the
// first handshake, whichever listener receives it. It returns when any listener
// fails, or once ctx is done and every server has shut down.
func ListenAndServe(
	ctx context.Context,
	hosts []string,
	listeners []Listener,
	storagePath, acmeEmail string,
	selfSigned bool,
) error {
	if selfSigned {
		return listenSelfSigned(ctx, hosts, listeners)
	}
	if err := setupIssuer(acmeEmail); err != nil {
		return err
	}
	// in dev the pebble account is lost when pebble restarts, so clear any stale
	// stored account and certificates on startup; in prod this is a no op.
	resetDevStorage(storagePath)

	allowed := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		allowed[strings.ToLower(h)] = true
	}

	cfg := certmagic.NewDefault()
	cfg.Storage = &certmagic.FileStorage{Path: storagePath}
	cfg.OnDemand = &certmagic.OnDemandConfig{
		DecisionFunc: func(name string) error {
			if allowed[strings.ToLower(name)] {
				return nil
			}
			return fmt.Errorf("certificate not allowed for host %q", name)
		},
	}

	var finalConfig *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return finalConfig, nil
		},
	})
	finalConfig = certmagic.New(cache, *cfg)
	// stop the certificate renewal work when serving ends.
	defer cache.Stop()

	tlsConfig := finalConfig.TLSConfig()
	tlsConfig.NextProtos = append([]string{"h2", "http/1.1"}, tlsConfig.NextProtos...)

	localCert, err := selfSignedCert([]string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}, 10)
	if err != nil {
		return err
	}
	acmeGetCertificate := tlsConfig.GetCertificate
	tlsConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if isLocal(hello) {
			return localCert, nil
		}
		cert, err := acmeGetCertificate(hello)
		if err != nil && devFallback {
			// dev: serve a self signed cert for an unmatched or missing SNI so
			// the vite proxy can reach the backend. Prod never sets devFallback.
			return localCert, nil
		}
		return cert, err
	}

	return serveAll(ctx, listeners, tlsConfig)
}

// listenSelfSigned serves every listener over HTTPS using one long lived self
// signed certificate covering every configured host plus localhost, for running
// behind a TLS terminating front where ACME cannot complete.
func listenSelfSigned(ctx context.Context, hosts []string, listeners []Listener) error {
	allowed := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		allowed[strings.ToLower(h)] = true
	}
	// the origin certificate carries no names, so a scan of the server address
	// cannot read the hostnames from the handshake. The front never validates it.
	originCert, err := selfSignedCert(nil, nil, 100)
	if err != nil {
		return err
	}
	localCert, err := selfSignedCert([]string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}, 100)
	if err != nil {
		return err
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if isLocal(hello) {
				return localCert, nil
			}
			if !allowed[strings.ToLower(hello.ServerName)] {
				return nil, fmt.Errorf("no certificate for server name %q", hello.ServerName)
			}
			return originCert, nil
		},
	}
	return serveAll(ctx, listeners, tlsConfig)
}

// serveAll binds every listener before serving any, so a bad address fails
// startup instead of leaving one surface up, then serves them all. When ctx is
// done it shuts every server down and returns nil. When a listener fails it
// shuts the others down and returns that error.
func serveAll(ctx context.Context, listeners []Listener, tlsConfig *tls.Config) error {
	lns := make([]net.Listener, 0, len(listeners))
	for _, l := range listeners {
		ln, err := tls.Listen("tcp", l.Addr, tlsConfig)
		if err != nil {
			for _, open := range lns {
				_ = open.Close()
			}
			return fmt.Errorf("listen %s: %w", l.Addr, err)
		}
		lns = append(lns, ln)
	}
	errs := make(chan error, len(lns))
	servers := make([]*http.Server, 0, len(lns))
	for i, ln := range lns {
		srv := newHTTPServer(listeners[i].Handler)
		servers = append(servers, srv)
		stop := listeners[i].Stop
		if stop != nil {
			go func() {
				select {
				case <-stop:
				case <-ctx.Done():
					return
				}
				sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = srv.Shutdown(sctx)
			}()
		}
		go func(ln net.Listener) {
			err := srv.Serve(ln)
			if stop != nil && errors.Is(err, http.ErrServerClosed) {
				return
			}
			errs <- err
		}(ln)
	}
	select {
	case err := <-errs:
		shutdownAll(servers, ShutdownTimeout)
		return err
	case <-ctx.Done():
		shutdownAll(servers, ShutdownTimeout)
		return nil
	}
}

// shutdownAll stops every server at once: no new connections are accepted and
// requests in flight get until the timeout to finish. A server still busy at
// the timeout has its connections closed.
func shutdownAll(servers []*http.Server, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	done := make(chan struct{}, len(servers))
	for _, srv := range servers {
		go func(srv *http.Server) {
			defer func() { done <- struct{}{} }()
			if err := srv.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("shutdown: requests still running after %s were cut off", timeout)
				_ = srv.Close()
			}
		}(srv)
	}
	for range servers {
		<-done
	}
}
