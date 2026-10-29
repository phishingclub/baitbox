package middleware

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// LogServerErrors logs every reply with a 5xx status by method and route
// pattern, so a server fault shows in the log even when the handler only sends
// a generic message. The raw path is left out, as it is caller controlled.
func LogServerErrors() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		status := c.Writer.Status()
		if status >= http.StatusInternalServerError {
			route := c.FullPath()
			if route == "" {
				route = "(no route)"
			}
			log.Printf("server error: %s %s -> %d", c.Request.Method, route, status)
		}
	}
}
