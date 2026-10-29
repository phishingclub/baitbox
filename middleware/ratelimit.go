// Package middleware holds the Gin middleware chain: client IP aware rate
// limiting, security headers and the operator session guard. These mirror the
// phishingclub security chassis.
package middleware

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/phishingclub/baitbox/service"
	"golang.org/x/time/rate"
)

// keyLimiter tracks a token bucket and its last access for idle eviction.
type keyLimiter struct {
	limiter    *rate.Limiter
	lastAccess atomic.Int64
}

// RateLimiter is a per key token bucket limiter with background eviction of
// idle keys, keyed by client address grouped with service.ClientKey.
type RateLimiter struct {
	buckets sync.Map
	limit   rate.Limit
	burst   int
	idle    time.Duration
}

// NewRateLimiter builds a limiter allowing limit requests per second with the
// given burst, evicting keys idle longer than idle.
func NewRateLimiter(perSecond float64, burst int, idle time.Duration) *RateLimiter {
	rl := &RateLimiter{limit: rate.Limit(perSecond), burst: burst, idle: idle}
	go rl.cleanup()
	return rl
}

func (rl *RateLimiter) get(key string) *rate.Limiter {
	now := time.Now().UnixNano()
	if v, ok := rl.buckets.Load(key); ok {
		kl := v.(*keyLimiter)
		kl.lastAccess.Store(now)
		return kl.limiter
	}
	kl := &keyLimiter{limiter: rate.NewLimiter(rl.limit, rl.burst)}
	kl.lastAccess.Store(now)
	actual, _ := rl.buckets.LoadOrStore(key, kl)
	return actual.(*keyLimiter).limiter
}

func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(rl.idle)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-rl.idle).UnixNano()
		rl.buckets.Range(func(k, v any) bool {
			if v.(*keyLimiter).lastAccess.Load() < cutoff {
				rl.buckets.Delete(k)
			}
			return true
		})
	}
}

// Middleware returns a Gin handler that rejects with 429 when the client
// address group exceeds its bucket.
func (rl *RateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !rl.get(service.ClientKey(c.ClientIP())).Allow() {
			c.Header("Retry-After", "1")
			c.AbortWithStatus(http.StatusTooManyRequests)
			return
		}
		c.Next()
	}
}
