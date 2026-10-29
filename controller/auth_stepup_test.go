package controller

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/phishingclub/baitbox/config"
	"github.com/phishingclub/baitbox/crypto"
	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/middleware"
	"github.com/phishingclub/baitbox/repository"
	"github.com/phishingclub/baitbox/service"
	"gorm.io/gorm"
)

const testPassword = "password-12345"

// stepUpHarness is the admin API mounted behind the real session guard over a
// temp database, with one signed in operator.
type stepUpHarness struct {
	t         *testing.T
	db        *gorm.DB
	engine    *gin.Engine
	operators *service.OperatorService
	sessions  *service.SessionService
	opID      string
	cookie    string
	auditLog  *bytes.Buffer
	// throttled counts 429 replies that proof waited out.
	throttled int
}

func newStepUpHarness(t *testing.T) *stepUpHarness {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := database.Open(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	hash, err := crypto.HashPassword(testPassword)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	op := database.Operator{Username: "xena", PasswordHash: hash}
	if err := db.Create(&op).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	operators := service.NewOperatorService(repository.NewOperatorRepository(db))
	sessions := service.NewSessionService(repository.NewSessionRepository(db))
	tokens := service.NewTokenService(repository.NewTokenRepository(db))
	auditLog := &bytes.Buffer{}
	audit := service.NewAuditServiceTo(auditLog)
	passkeys, err := service.NewWebAuthnService(repository.NewWebAuthnRepository(db), &config.Config{Env: "dev"})
	if err != nil {
		t.Fatalf("webauthn: %v", err)
	}
	guard := middleware.NewAuth(sessions, false)
	api := NewAdminAPI(AdminAPIDeps{
		Tokens: tokens, Operators: operators, Audit: audit,
		Passkeys: passkeys, Sessions: sessions, Guard: guard,
	})
	engine := gin.New()
	engine.Group("/api/v1/admin", guard.RequireAPI()).
		POST("/change-password", api.ChangePassword).
		POST("/mfa/disable", api.MFADisable).
		GET("/stepup", api.StepUpStatus).
		POST("/stepup", api.StepUp).
		POST("/operators", api.OperatorCreate).
		DELETE("/operators/:id", api.OperatorDelete).
		POST("/tokens", api.TokenCreate).
		PATCH("/tokens/:id", api.TokenUpdate).
		POST("/tokens/:id/revoke", api.TokenRevoke)
	auth := NewAuth(AuthDeps{
		Operators: operators, Sessions: sessions, Audit: audit, Passkeys: passkeys, Guard: guard,
	})
	engine.POST("/api/v1/login", auth.LoginJSON)
	engine.POST("/api/v1/login/passkey/begin", auth.PasskeyLoginBegin)
	engine.POST("/api/v1/login/passkey/finish", auth.PasskeyLoginFinish)
	engine.POST("/api/v1/logout", auth.LogoutJSON)
	raw, err := sessions.Create(op.ID, 0, "192.0.2.1")
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	return &stepUpHarness{t: t, db: db, engine: engine, operators: operators, sessions: sessions, opID: op.ID, cookie: raw, auditLog: auditLog}
}

func (h *stepUpHarness) do(method, path string, body any) (int, map[string]any) {
	h.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, "/api/v1/admin"+path, &buf)
	req.RemoteAddr = "192.0.2.1:4000"
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: middleware.SessionCookieName, Value: h.cookie})
	w := httptest.NewRecorder()
	h.engine.ServeHTTP(w, req)
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// proof sends a proof of identity, waiting out any 429 by its Retry-After, which
// the reply must carry.
func (h *stepUpHarness) proof(method, path string, body any) (int, map[string]any) {
	h.t.Helper()
	for {
		code, out := h.do(method, path, body)
		if code != http.StatusTooManyRequests {
			return code, out
		}
		h.throttled++
		secs, _ := out["retryAfter"].(float64)
		if secs < 1 || secs > 60 {
			h.t.Fatalf("429 without a usable retryAfter: %v", out)
		}
		time.Sleep(time.Duration(secs) * time.Second)
	}
}

// loginReply posts to the login route from ip and returns the status, the
// Retry-After header and the body.
func (h *stepUpHarness) loginReply(username, password, ip string) (int, string, map[string]any) {
	h.t.Helper()
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(map[string]string{"username": username, "password": password})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/login", &buf)
	req.RemoteAddr = ip + ":4000"
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.engine.ServeHTTP(w, req)
	out := map[string]any{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, w.Header().Get("Retry-After"), out
}

func (h *stepUpHarness) login(username, password string) (int, map[string]any) {
	h.t.Helper()
	code, _, out := h.loginReply(username, password, "192.0.2.1")
	return code, out
}

func (h *stepUpHarness) stepUp() {
	h.t.Helper()
	if code, out := h.do(http.MethodPost, "/stepup", map[string]string{"password": testPassword}); code != http.StatusOK {
		h.t.Fatalf("step up: %d %v", code, out)
	}
}

func (h *stepUpHarness) count(q *gorm.DB) int64 {
	h.t.Helper()
	var n int64
	if err := q.Count(&n).Error; err != nil {
		h.t.Fatalf("count: %v", err)
	}
	return n
}

func wantStepUpRequired(t *testing.T, what string, code int, out map[string]any) {
	t.Helper()
	if code != http.StatusForbidden || out["stepUpRequired"] != true {
		t.Fatalf("%s without step up: %d %v", what, code, out)
	}
}

func TestCredentialRoutesNeedStepUp(t *testing.T) {
	h := newStepUpHarness(t)

	// creating an operator
	newOp := map[string]string{"username": "yuri", "password": "another-password-1"}
	code, out := h.do(http.MethodPost, "/operators", newOp)
	wantStepUpRequired(t, "operator create", code, out)
	if h.count(h.db.Model(&database.Operator{}).Where("username = ?", "yuri")) != 0 {
		t.Fatal("operator created without step up")
	}
	// bad input is refused before the grant is spent
	h.stepUp()
	if code, _ := h.do(http.MethodPost, "/operators", map[string]string{"username": "yuri", "password": "short"}); code != http.StatusBadRequest {
		t.Fatalf("bad input: %d", code)
	}
	if code, out := h.do(http.MethodPost, "/operators", newOp); code != http.StatusOK {
		t.Fatalf("operator create after step up: %d %v", code, out)
	}
	// the grant is single use
	code, out = h.do(http.MethodPost, "/operators", map[string]string{"username": "zack", "password": "another-password-1"})
	wantStepUpRequired(t, "second operator create", code, out)

	// deleting an operator
	var yuri database.Operator
	if err := h.db.Where("username = ?", "yuri").First(&yuri).Error; err != nil {
		t.Fatalf("load: %v", err)
	}
	code, out = h.do(http.MethodDelete, "/operators/"+yuri.ID, nil)
	wantStepUpRequired(t, "operator delete", code, out)
	if h.count(h.db.Model(&database.Operator{}).Where("id = ?", yuri.ID)) != 1 {
		t.Fatal("operator deleted without step up")
	}
	h.stepUp()
	if code, out := h.do(http.MethodDelete, "/operators/"+yuri.ID, nil); code != http.StatusOK {
		t.Fatalf("operator delete after step up: %d %v", code, out)
	}

	// minting a token
	tok := map[string]any{"name": "ci", "namespaces": []string{"*"}}
	code, out = h.do(http.MethodPost, "/tokens", tok)
	wantStepUpRequired(t, "token create", code, out)
	if h.count(h.db.Model(&database.Token{}).Where("name = ?", "ci")) != 0 {
		t.Fatal("token created without step up")
	}
	h.stepUp()
	code, out = h.do(http.MethodPost, "/tokens", tok)
	if code != http.StatusOK || out["token"] == nil {
		t.Fatalf("token create after step up: %d %v", code, out)
	}
	id, _ := out["id"].(string)

	// widening a token's allowed IPs
	code, out = h.do(http.MethodPatch, "/tokens/"+id, map[string]any{"allowedCidrs": []string{}})
	wantStepUpRequired(t, "token update", code, out)
	h.stepUp()
	if code, out := h.do(http.MethodPatch, "/tokens/"+id, map[string]any{"allowedCidrs": []string{"10.0.0.0/8"}}); code != http.StatusOK {
		t.Fatalf("token update after step up: %d %v", code, out)
	}

	// revoking only takes access away, so it needs no step up
	if code, out := h.do(http.MethodPost, "/tokens/"+id+"/revoke", nil); code != http.StatusOK {
		t.Fatalf("token revoke: %d %v", code, out)
	}
}

func TestWrongStepUpRevokesSessionNotLogin(t *testing.T) {
	h := newStepUpHarness(t)
	for i := 0; i < service.SessionSecondFactorLimit-1; i++ {
		if code, out := h.proof(http.MethodPost, "/stepup", map[string]string{"password": "wrong"}); code != http.StatusBadRequest {
			t.Fatalf("wrong password %d: %d %v", i, code, out)
		}
	}
	if h.throttled == 0 {
		t.Fatal("wrong proofs were never throttled")
	}
	code, out := h.proof(http.MethodPost, "/stepup", map[string]string{"password": "wrong"})
	if code != http.StatusUnauthorized || out["signedOut"] != true {
		t.Fatalf("session not revoked at the limit: %d %v", code, out)
	}
	if _, err := h.sessions.Validate(h.cookie, "192.0.2.1"); err == nil {
		t.Fatal("session still valid after revoke")
	}
	if code, _ := h.do(http.MethodGet, "/stepup", nil); code != http.StatusUnauthorized {
		t.Fatalf("revoked session still served: %d", code)
	}
	if h.auditCount("Operator.SessionRevoked", func(l map[string]any) bool { return l["userId"] == h.opID }) != 1 {
		t.Fatal("revoke not audited")
	}
	// the operator can still log in at once: the login throttle was not touched.
	if code, out := h.login("xena", testPassword); code != http.StatusOK {
		t.Fatalf("login after session revoke: %d %v", code, out)
	}
}

func TestWrongMFADisableCodesRevokeSession(t *testing.T) {
	h := newStepUpHarness(t)
	secret := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	if err := h.db.Model(&database.Operator{}).Where("id = ?", h.opID).
		Updates(map[string]any{"mfa_secret": secret, "mfa_enabled": true}).Error; err != nil {
		t.Fatalf("enable mfa: %v", err)
	}
	// a code that is not 6 digits never matches
	for i := 0; i < service.SessionSecondFactorLimit-1; i++ {
		if code, out := h.proof(http.MethodPost, "/mfa/disable", map[string]string{"code": "xxxxxx"}); code != http.StatusBadRequest {
			t.Fatalf("wrong code %d: %d %v", i, code, out)
		}
	}
	code, out := h.proof(http.MethodPost, "/mfa/disable", map[string]string{"code": "xxxxxx"})
	if code != http.StatusUnauthorized || out["signedOut"] != true {
		t.Fatalf("session not revoked at the limit: %d %v", code, out)
	}
	if err := h.operators.SecondFactorWait(h.opID, "192.0.2.1"); err != nil {
		t.Fatalf("session side wrong codes throttled the login: %v", err)
	}
	op, _ := h.operators.GetOperator(h.opID)
	if !op.MFAEnabled {
		t.Fatal("mfa turned off by wrong codes")
	}
}

func TestLoginThrottleRepliesRetryAfter(t *testing.T) {
	h := newStepUpHarness(t)
	const ip = "198.51.100.20"
	var retry string
	for i := 0; i < 10; i++ {
		code, ra, out := h.loginReply("xena", "wrong", ip)
		if code == http.StatusTooManyRequests {
			retry = ra
			if out["retryAfter"] == nil {
				t.Fatalf("429 body without retryAfter: %v", out)
			}
			break
		}
		if code != http.StatusUnauthorized {
			t.Fatalf("wrong password %d: %d %v", i, code, out)
		}
	}
	secs, err := strconv.Atoi(retry)
	if err != nil || secs < 1 {
		t.Fatalf("no usable Retry-After: %q", retry)
	}
	// inside the wait the right password gets the same 429, unchecked.
	if code, ra, _ := h.loginReply("xena", testPassword, ip); code != http.StatusTooManyRequests || ra == "" {
		t.Fatalf("right password inside the wait: %d %q", code, ra)
	}
	// another address is not slowed.
	if code, _, out := h.loginReply("xena", testPassword, "198.51.100.21"); code != http.StatusOK {
		t.Fatalf("login from another address: %d %v", code, out)
	}
	time.Sleep(time.Duration(secs) * time.Second)
	if code, _, out := h.loginReply("xena", testPassword, ip); code != http.StatusOK {
		t.Fatalf("right password after the wait: %d %v", code, out)
	}
}

func TestDeleteMissingOperatorNotFound(t *testing.T) {
	h := newStepUpHarness(t)
	h.stepUp()
	code, out := h.do(http.MethodDelete, "/operators/no-such-operator", nil)
	if code != http.StatusNotFound {
		t.Fatalf("missing operator: %d %v", code, out)
	}
	// the only operator is still guarded as the last one.
	h.stepUp()
	code, out = h.do(http.MethodDelete, "/operators/"+h.opID, nil)
	if code != http.StatusBadRequest || out["error"] != "cannot delete the last operator" {
		t.Fatalf("last operator: %d %v", code, out)
	}
}

// TestBusyChangePasswordKeepsProofCount: a change refused because every hash
// slot is busy must not clear the session's count of wrong proofs, or a stolen
// session could dodge the revoke by timing a request against a busy server.
func TestBusyChangePasswordKeepsProofCount(t *testing.T) {
	h := newStepUpHarness(t)
	change := func(current string) (int, map[string]any) {
		return h.proof(http.MethodPost, "/change-password", map[string]string{"current": current, "next": "a new password 123"})
	}
	for i := 0; i < service.SessionSecondFactorLimit-1; i++ {
		if code, out := change("wrong"); code != http.StatusBadRequest {
			t.Fatalf("wrong password %d: %d %v", i, code, out)
		}
	}
	// wait out the session wait so the busy request reaches the hash.
	for h.sessions.ProofWait(h.cookie) != nil {
		time.Sleep(100 * time.Millisecond)
	}
	release := crypto.HoldHashSlots()
	code, out := h.do(http.MethodPost, "/change-password", map[string]string{"current": testPassword, "next": "a new password 123"})
	release()
	if code != http.StatusTooManyRequests {
		t.Fatalf("busy change: %d %v", code, out)
	}
	code, out = change("wrong")
	if code != http.StatusUnauthorized || out["signedOut"] != true {
		t.Fatalf("busy reply cleared the count, session not revoked: %d %v", code, out)
	}
}
