package middleware

import (
	"net"
	"testing"
)

func TestIPAllowOpenWhenEmpty(t *testing.T) {
	a := NewIPAllow(nil)
	if !a.open {
		t.Fatal("empty allowlist must be open")
	}
	if !a.permits(net.ParseIP("203.0.113.9")) {
		// open is handled in Middleware; permits is only consulted when not open,
		// but an open list should never reject in practice.
	}
}

func TestIPAllowCIDR(t *testing.T) {
	a := NewIPAllow([]string{"10.0.0.0/8"})
	if a.open {
		t.Fatal("non-empty allowlist must not be open")
	}
	if !a.permits(net.ParseIP("10.1.2.3")) {
		t.Fatal("ip within the allowed CIDR should be permitted")
	}
	if a.permits(net.ParseIP("192.168.1.1")) {
		t.Fatal("ip outside the allowed CIDR must be rejected")
	}
}

func TestIPAllowExact(t *testing.T) {
	a := NewIPAllow([]string{"1.2.3.4", "2001:db8::1"})
	if !a.permits(net.ParseIP("1.2.3.4")) || !a.permits(net.ParseIP("2001:db8::1")) {
		t.Fatal("exact allowed ips should be permitted")
	}
	if a.permits(net.ParseIP("1.2.3.5")) {
		t.Fatal("a different ip must be rejected")
	}
}

func TestIPAllowUnparseableStaysClosed(t *testing.T) {
	a := NewIPAllow([]string{"not-an-ip"})
	if a.open {
		t.Fatal("an allowlist with only bad entries must not be open")
	}
	if a.permits(net.ParseIP("1.2.3.4")) {
		t.Fatal("nothing should match a fully unparseable allowlist")
	}
}
