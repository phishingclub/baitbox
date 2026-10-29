package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestRateLimiterGroupsIPv6By64(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rl := NewRateLimiter(0.001, 2, time.Minute)
	r := gin.New()
	r.Use(rl.Middleware())
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })
	hit := func(ip string) int {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "[" + ip + "]:1234"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w.Code
	}
	// rotating the low 64 bits stays in one bucket.
	codes := []int{hit("2001:db8:1:1::1"), hit("2001:db8:1:1::2"), hit("2001:db8:1:1:ffff::3")}
	if codes[0] != 200 || codes[1] != 200 || codes[2] != http.StatusTooManyRequests {
		t.Fatalf("same /64 codes %v", codes)
	}
	// another /64 has its own bucket.
	if code := hit("2001:db8:1:2::1"); code != 200 {
		t.Fatalf("other /64: %d", code)
	}
}
