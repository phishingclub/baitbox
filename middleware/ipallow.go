package middleware

import (
	"net"
	"net/http"

	"github.com/gin-gonic/gin"
)

// IPAllow restricts access to a set of allowed client IPs or CIDR ranges. An
// empty allowlist allows everyone, matching the phishingclub default. It is
// applied to the operator admin UI only, not the registry listener, so remote
// clients can still browse and install while the human console is locked down.
type IPAllow struct {
	open  bool
	nets  []*net.IPNet
	addrs []net.IP
}

// NewIPAllow parses the allowlist entries (plain IPs or CIDRs). Unparseable
// entries are ignored. An empty list yields an open allowlist.
func NewIPAllow(entries []string) *IPAllow {
	if len(entries) == 0 {
		return &IPAllow{open: true}
	}
	a := &IPAllow{}
	for _, e := range entries {
		if _, cidr, err := net.ParseCIDR(e); err == nil {
			a.nets = append(a.nets, cidr)
			continue
		}
		if ip := net.ParseIP(e); ip != nil {
			a.addrs = append(a.addrs, ip)
		}
	}
	// a non empty but fully unparseable list stays closed (nothing matches).
	return a
}

func (a *IPAllow) permits(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range a.nets {
		if n.Contains(ip) {
			return true
		}
	}
	for _, addr := range a.addrs {
		if addr.Equal(ip) {
			return true
		}
	}
	return false
}

// Middleware rejects a request whose client IP is not in the allowlist with 403.
func (a *IPAllow) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if a.open {
			c.Next()
			return
		}
		if a.permits(net.ParseIP(c.ClientIP())) {
			c.Next()
			return
		}
		c.AbortWithStatus(http.StatusForbidden)
	}
}
