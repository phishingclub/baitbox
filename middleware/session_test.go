package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/phishingclub/baitbox/database"
)

// routeWithOperator mounts path behind a stub that sets the operator, then the
// password change check, the same order RequireAPI uses.
func routeWithOperator(a *Auth, op *database.Operator, method, path string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	e := gin.New()
	e.Handle(method, path, func(c *gin.Context) {
		if a.blockedByPasswordChange(c, op) {
			return
		}
		c.Status(http.StatusOK)
	})
	return e
}

func TestPasswordChangeGate(t *testing.T) {
	flagged := &database.Operator{MustChangePassword: true}
	cases := []struct {
		name    string
		force   bool
		op      *database.Operator
		method  string
		pattern string
		path    string
		want    int
	}{
		{"prod blocks admin api", true, flagged, "GET", "/api/v1/admin/stats", "/api/v1/admin/stats", http.StatusForbidden},
		{"prod blocks export", true, flagged, "GET", "/admin/export", "/admin/export", http.StatusForbidden},
		{"prod allows me", true, flagged, "GET", "/api/v1/me", "/api/v1/me", http.StatusOK},
		{"prod allows change password", true, flagged, "POST", "/api/v1/admin/change-password", "/api/v1/admin/change-password", http.StatusOK},
		{"prod matches the route not the raw path", true, flagged, "GET", "/api/v1/admin/packages/:ns/:name", "/api/v1/admin/packages/me/change-password", http.StatusForbidden},
		{"dev does not block", false, flagged, "GET", "/api/v1/admin/stats", "/api/v1/admin/stats", http.StatusOK},
		{"unflagged operator passes", true, &database.Operator{}, "GET", "/api/v1/admin/stats", "/api/v1/admin/stats", http.StatusOK},
	}
	for _, tc := range cases {
		a := NewAuth(nil, tc.force)
		w := httptest.NewRecorder()
		routeWithOperator(a, tc.op, tc.method, tc.pattern).ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != tc.want {
			t.Errorf("%s: got %d want %d", tc.name, w.Code, tc.want)
		}
	}
}
