package acme

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"testing"
	"time"
)

func freeAddr(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func TestServeAllStopClosesOnlyThatListener(t *testing.T) {
	cert, err := selfSignedCert([]string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)}, 1)
	if err != nil {
		t.Fatal(err)
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	keep, stopAddr := freeAddr(t), freeAddr(t)
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- serveAll(context.Background(), []Listener{{Addr: keep, Handler: ok}, {Addr: stopAddr, Handler: ok, Stop: stop}}, &tls.Config{Certificates: []tls.Certificate{*cert}})
	}()

	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	get := func(addr string) error {
		resp, err := client.Get("https://" + addr + "/")
		if err == nil {
			resp.Body.Close()
		}
		return err
	}
	deadline := time.Now().Add(3 * time.Second)
	for get(keep) != nil || get(stopAddr) != nil {
		if time.Now().After(deadline) {
			t.Fatal("listeners did not start")
		}
		time.Sleep(50 * time.Millisecond)
	}

	close(stop)
	deadline = time.Now().Add(3 * time.Second)
	for get(stopAddr) == nil {
		if time.Now().After(deadline) {
			t.Fatal("stopped listener still serving")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err := get(keep); err != nil {
		t.Fatalf("other listener stopped too: %v", err)
	}
	select {
	case err := <-done:
		t.Fatalf("serveAll returned after a stop: %v", err)
	default:
	}
}

// addrConn is a net.Conn that only reports a remote address.
type addrConn struct {
	net.Conn
	remote net.Addr
}

func (c addrConn) RemoteAddr() net.Addr { return c.remote }

func TestIsLocalRequiresLoopback(t *testing.T) {
	loop := addrConn{remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}}
	loop6 := addrConn{remote: &net.TCPAddr{IP: net.IPv6loopback, Port: 1}}
	remote := addrConn{remote: &net.TCPAddr{IP: net.IPv4(203, 0, 113, 7), Port: 1}}
	cases := []struct {
		name string
		sni  string
		conn net.Conn
		want bool
	}{
		{"loopback localhost", "localhost", loop, true},
		{"loopback v6 localhost", "LocalHost", loop6, true},
		{"loopback no sni", "", loop, true},
		{"loopback other name", "example.com", loop, false},
		{"remote localhost", "localhost", remote, false},
		{"remote 127 name", "127.0.0.1", remote, false},
		{"remote no sni", "", remote, false},
		{"no conn", "localhost", nil, false},
	}
	for _, tc := range cases {
		hello := &tls.ClientHelloInfo{ServerName: tc.sni}
		if tc.conn != nil {
			hello.Conn = tc.conn
		}
		if got := isLocal(hello); got != tc.want {
			t.Errorf("%s: isLocal = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestServeAllShutdownLetsRequestsFinish: when ctx is done serveAll stops
// taking new connections, lets a request in flight finish and returns nil.
func TestServeAllShutdownLetsRequestsFinish(t *testing.T) {
	cert, err := selfSignedCert([]string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)}, 1)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	slow := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			close(started)
			time.Sleep(500 * time.Millisecond)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	addr := freeAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- serveAll(ctx, []Listener{{Addr: addr, Handler: slow}}, &tls.Config{Certificates: []tls.Certificate{*cert}})
	}()
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	deadline := time.Now().Add(3 * time.Second)
	for {
		resp, err := client.Get("https://" + addr + "/")
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("listener did not start")
		}
		time.Sleep(50 * time.Millisecond)
	}

	result := make(chan int, 1)
	go func() {
		resp, err := client.Get("https://" + addr + "/slow")
		if err != nil {
			result <- 0
			return
		}
		resp.Body.Close()
		result <- resp.StatusCode
	}()
	<-started
	cancel()
	if code := <-result; code != http.StatusNoContent {
		t.Fatalf("request in flight got %d, want 204", code)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serveAll after shutdown = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveAll did not return after shutdown")
	}
}
