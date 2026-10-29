package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// BodyLimit caps the request body size, so a handler that reads the whole body
// into memory cannot be made to allocate without bound.
func BodyLimit(max int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, max)
		c.Next()
	}
}

// baselineCSP is the policy applied to every response. It allows nothing to
// load, which suits the JSON, downloads and files the server sends. The SPA
// document replaces it with the policy SvelteKit bakes into index.html (script
// hashes and the rest), and the preview and rawfile handlers replace it with
// their own sandbox policy.
const baselineCSP = "default-src 'none'; frame-ancestors 'none'; object-src 'none'; " +
	"base-uri 'self'; form-action 'self'"

// SecurityHeaders sets conservative security headers on every response.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		h.Set("Content-Security-Policy", baselineCSP)
		c.Next()
	}
}

// NoSharedCache keeps registry replies out of shared caches by default: what a
// reply holds depends on the caller's token, so a cache must never hand one
// caller's reply to another. A handler may set a looser policy for public data.
func NoSharedCache(c *gin.Context) {
	c.Header("Cache-Control", "private, no-store")
	c.Header("Vary", "Authorization")
	c.Next()
}
