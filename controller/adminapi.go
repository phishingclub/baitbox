package controller

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/manifest"
	"github.com/phishingclub/baitbox/middleware"
	"github.com/phishingclub/baitbox/model"
	"github.com/phishingclub/baitbox/repository"
	"github.com/phishingclub/baitbox/service"
	"github.com/phishingclub/baitbox/utils"
)

// maxPerPage caps a page size so a request cannot ask for an unbounded result.
const maxPerPage = 200

// listQuery reads pagination, sort and search from the request into a QueryArgs.
// The sort column is passed through verbatim; the repository rejects it unless it
// is in that table's order allowlist, so an unknown or crafted column can never
// reach SQL. It returns the clamped page and perPage for the response.
func listQuery(c *gin.Context) (*repository.QueryArgs, int, int) {
	page := 1
	if v, err := strconv.Atoi(c.Query("page")); err == nil && v > 1 {
		page = v
	}
	perPage := 50
	if v, err := strconv.Atoi(c.Query("perPage")); err == nil && v > 0 {
		perPage = v
	}
	if perPage > maxPerPage {
		perPage = maxPerPage
	}
	q := &repository.QueryArgs{
		Offset:  (page - 1) * perPage,
		Limit:   perPage,
		OrderBy: strings.TrimSpace(c.Query("sort")),
		Desc:    c.Query("dir") == "desc",
		Search:  strings.TrimSpace(c.Query("q")),
		// package list filters, ignored by the namespaces list. Bound as values.
		FilterType:      strings.TrimSpace(c.Query("type")),
		FilterNamespace: strings.TrimSpace(c.Query("namespace")),
		FilterTag:       strings.TrimSpace(c.Query("tag")),
	}
	return q, page, perPage
}

// AdminAPI routes are session guarded and behind the admin IP allowlist, both
// wired in server.
type AdminAPI struct {
	reg       *service.RegistryService
	tokens    *service.TokenService
	stats     *service.StatsService
	operators *service.OperatorService
	audit     *service.AuditService
	passkeys  *service.WebAuthnService
	sessions  *service.SessionService
	guard     *middleware.Auth
}

// AdminAPIDeps is what NewAdminAPI needs.
type AdminAPIDeps struct {
	Registry  *service.RegistryService
	Tokens    *service.TokenService
	Stats     *service.StatsService
	Operators *service.OperatorService
	Audit     *service.AuditService
	Passkeys  *service.WebAuthnService
	Sessions  *service.SessionService
	Guard     *middleware.Auth
}

// NewAdminAPI returns the AdminAPI controller.
func NewAdminAPI(d AdminAPIDeps) *AdminAPI {
	return &AdminAPI{
		reg:       d.Registry,
		tokens:    d.Tokens,
		stats:     d.Stats,
		operators: d.Operators,
		audit:     d.Audit,
		passkeys:  d.Passkeys,
		sessions:  d.Sessions,
		guard:     d.Guard,
	}
}

// passkeyRegCookie carries the WebAuthn registration challenge token between the
// begin and finish of enrolling a passkey.
const passkeyRegCookie = "bs_pk_reg"

// passkeyStepUpCookie carries the WebAuthn challenge token between the begin and
// finish of a passkey step up.
const passkeyStepUpCookie = "bs_pk_step"

// sessionCookie returns the raw session cookie of the request, which keys the
// step up grants.
func sessionCookie(c *gin.Context) string {
	v, _ := c.Cookie(middleware.SessionCookieName)
	return v
}

// requireStepUp consumes the session's step up grant. Without one it replies
// 403 with stepUpRequired so the SPA asks the operator to prove it is them, and
// returns false. Second factor changes, operator changes and token creation or
// widening call it before doing anything that changes state.
func (a *AdminAPI) requireStepUp(c *gin.Context, op *database.Operator, action string) bool {
	if a.sessions.ConsumeStepUp(sessionCookie(c), op.ID) {
		return true
	}
	a.logAudit(c, action, false, map[string]any{"reason": "step up required"})
	c.JSON(http.StatusForbidden, gin.H{"error": "confirm it is you first", "stepUpRequired": true})
	return false
}

// proofFailed counts a wrong proof of identity against the request's session;
// see sessionProofFailed.
func (a *AdminAPI) proofFailed(c *gin.Context) bool {
	return sessionProofFailed(c, a.sessions, a.logAudit)
}

// beginProof starts checking a proof of identity on the request's session; see
// sessionBeginProof.
func (a *AdminAPI) beginProof(c *gin.Context, action string) bool {
	return sessionBeginProof(c, a.sessions, action, a.logAudit)
}

// reissueSession starts a fresh session for the operator after every session of
// theirs was dropped, and sets its cookie. authEpoch is the epoch the drop
// returned. It reports false when no session could be started, so the operator
// is signed out.
func (a *AdminAPI) reissueSession(c *gin.Context, op *database.Operator, authEpoch int64) bool {
	id, err := a.sessions.Create(op.ID, authEpoch, c.ClientIP())
	if err != nil {
		return false
	}
	setSessionCookie(c, id)
	return true
}

// StepUpStatus reports which proofs the operator can give to confirm it is them
// before a second factor change.
func (a *AdminAPI) StepUpStatus(c *gin.Context) {
	op := middleware.OperatorFromContext(c)
	totp, passkey, password, err := a.operators.StepUpMethods(op.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not read status"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"totp": totp, "passkey": passkey, "password": password})
}

// StepUp checks a TOTP code (when two factor is on) or the current password
// (when no second factor exists) and grants this session one second factor
// change for a few minutes. Failures count against this session only.
func (a *AdminAPI) StepUp(c *gin.Context) {
	var req struct {
		Code     string `json:"code"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	op := middleware.OperatorFromContext(c)
	if !a.beginProof(c, "Operator.StepUp") {
		return
	}
	err := a.operators.StepUp(op.ID, req.Code, req.Password)
	switch {
	case err == nil:
	case errors.Is(err, service.ErrStepUpPasskey):
		a.sessions.ProofSkipped(sessionCookie(c))
		c.JSON(http.StatusBadRequest, gin.H{"error": "confirm with your passkey", "passkeyRequired": true})
		return
	case errors.Is(err, service.ErrStepUpRequired):
		a.sessions.ProofSkipped(sessionCookie(c))
		c.JSON(http.StatusBadRequest, gin.H{"error": "enter your code or password"})
		return
	case errors.Is(err, service.ErrThrottled):
		// the server was too busy to check it, so it does not count.
		a.sessions.ProofSkipped(sessionCookie(c))
		replyThrottled(c, err)
		return
	case errors.Is(err, service.ErrInvalidCredentials):
		a.logAudit(c, "Operator.StepUp", false, nil)
		if a.proofFailed(c) {
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "that did not match"})
		return
	default:
		a.sessions.ProofSkipped(sessionCookie(c))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not confirm"})
		return
	}
	a.sessions.ProofSucceeded(sessionCookie(c))
	a.sessions.GrantStepUp(sessionCookie(c), op.ID)
	a.logAudit(c, "Operator.StepUp", true, nil)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// StepUpPasskeyBegin returns a WebAuthn assertion challenge for a passkey step
// up. While this session is inside a proof wait it answers 429 instead.
func (a *AdminAPI) StepUpPasskeyBegin(c *gin.Context) {
	op := middleware.OperatorFromContext(c)
	if replyThrottled(c, a.sessions.ProofWait(sessionCookie(c))) {
		return
	}
	options, token, err := a.passkeys.BeginStepUp(op, requestOrigin(c))
	if errors.Is(err, service.ErrNoPasskeys) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no passkeys registered for this account"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not start passkey check"})
		return
	}
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(passkeyStepUpCookie, token, 180, "/", "", true, true)
	c.JSON(http.StatusOK, options)
}

// StepUpPasskeyFinish verifies the passkey assertion and, when it belongs to the
// signed in operator, grants this session one second factor change. It is
// throttled per session, and a failed assertion counts against this session
// only.
func (a *AdminAPI) StepUpPasskeyFinish(c *gin.Context) {
	op := middleware.OperatorFromContext(c)
	token, _ := c.Cookie(passkeyStepUpCookie)
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(passkeyStepUpCookie, "", -1, "/", "", true, true)
	if !a.beginProof(c, "Operator.StepUp") {
		return
	}
	got, failedOpID, err := a.passkeys.FinishStepUp(requestOrigin(c), token, c.Request)
	if err == nil && (got == nil || got.ID != op.ID) {
		err = errors.New("passkey belongs to another operator")
	}
	if err != nil {
		details := map[string]any{"method": "passkey"}
		if errors.Is(err, service.ErrPasskeyClone) {
			details["reason"] = "clone warning"
		}
		a.logAudit(c, "Operator.StepUp", false, details)
		// an assertion that was checked and failed, or one for another operator,
		// counts against the session; a missing or expired challenge does not.
		if failedOpID == "" && got == nil {
			a.sessions.ProofSkipped(sessionCookie(c))
		} else if a.proofFailed(c) {
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "passkey verification failed"})
		return
	}
	a.sessions.ProofSucceeded(sessionCookie(c))
	a.sessions.GrantStepUp(sessionCookie(c), op.ID)
	a.logAudit(c, "Operator.StepUp", true, map[string]any{"method": "passkey"})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// PasskeysList returns the current operator's registered passkeys.
func (a *AdminAPI) PasskeysList(c *gin.Context) {
	op := middleware.OperatorFromContext(c)
	rows, err := a.passkeys.List(op.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not list passkeys"})
		return
	}
	out := make([]gin.H, 0, len(rows))
	for i := range rows {
		out = append(out, gin.H{
			"id": rows[i].ID, "name": rows[i].Name,
			"createdAt": rows[i].CreatedAt, "lastUsedAt": rows[i].LastUsedAt,
		})
	}
	c.JSON(http.StatusOK, gin.H{"passkeys": out})
}

// PasskeyRegisterBegin returns WebAuthn creation options for a new passkey. It
// needs a fresh step up.
func (a *AdminAPI) PasskeyRegisterBegin(c *gin.Context) {
	op := middleware.OperatorFromContext(c)
	if !a.requireStepUp(c, op, "Operator.PasskeyAdded") {
		return
	}
	options, token, err := a.passkeys.BeginRegistration(op, requestOrigin(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not start enrollment"})
		return
	}
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(passkeyRegCookie, token, 180, "/", "", true, true)
	c.JSON(http.StatusOK, options)
}

// PasskeyRegisterFinish verifies the attestation and stores the passkey. The
// challenge was started by PasskeyRegisterBegin after a step up.
func (a *AdminAPI) PasskeyRegisterFinish(c *gin.Context) {
	op := middleware.OperatorFromContext(c)
	token, _ := c.Cookie(passkeyRegCookie)
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(passkeyRegCookie, "", -1, "/", "", true, true)
	name, err := service.ValidPasskeyName(c.Query("name"))
	if err != nil {
		a.logAudit(c, "Operator.PasskeyAdded", false, map[string]any{"reason": "invalid name"})
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	err = a.passkeys.FinishRegistration(op, requestOrigin(c), token, name, c.Request, sessionCookie(c))
	if err != nil {
		a.logAudit(c, "Operator.PasskeyAdded", false,
			map[string]any{"name": name, "reason": "registration not verified"})
		if errors.Is(err, service.ErrEnrollmentExpired) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		log.Printf("Operator.PasskeyAdded: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "the passkey could not be registered"})
		return
	}
	a.logAudit(c, "Operator.PasskeyAdded", true, map[string]any{"name": name})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// PasskeyDelete removes one of the operator's passkeys. It needs a fresh step up.
func (a *AdminAPI) PasskeyDelete(c *gin.Context) {
	op := middleware.OperatorFromContext(c)
	if !a.requireStepUp(c, op, "Operator.PasskeyRemoved") {
		return
	}
	err := a.passkeys.Delete(op.ID, c.Param("id"), sessionCookie(c))
	if errors.Is(err, service.ErrNotFound) {
		a.logAudit(c, "Operator.PasskeyRemoved", false, map[string]any{"id": c.Param("id"), "reason": "not found"})
		c.JSON(http.StatusNotFound, gin.H{"error": "passkey not found"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not remove passkey"})
		return
	}
	a.logAudit(c, "Operator.PasskeyRemoved", true, map[string]any{"id": c.Param("id")})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// MFAStatus reports whether the current operator has two factor turned on.
func (a *AdminAPI) MFAStatus(c *gin.Context) {
	op := middleware.OperatorFromContext(c)
	fresh, err := a.operators.GetOperator(op.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not read status"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"enabled": fresh.MFAEnabled})
}

// MFABegin returns a new TOTP secret + otpauth URI to enroll an authenticator.
// It needs a fresh step up. The secret stays server side for MFAConfirm.
func (a *AdminAPI) MFABegin(c *gin.Context) {
	op := middleware.OperatorFromContext(c)
	if !a.requireStepUp(c, op, "Operator.MFAEnabled") {
		return
	}
	secret, uri, err := a.operators.BeginMFAEnroll(op.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not start enrollment"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"secret": secret, "uri": uri})
}

// MFAConfirm enables two factor once the operator proves a code for the secret
// handed out by MFABegin. Every session of the operator is dropped and this
// request gets a fresh one.
func (a *AdminAPI) MFAConfirm(c *gin.Context) {
	var req struct {
		Code string `json:"code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		a.logAudit(c, "Operator.MFAEnabled", false, map[string]any{"reason": "invalid request"})
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	op := middleware.OperatorFromContext(c)
	epoch, err := a.operators.ConfirmMFAEnroll(op.ID, req.Code)
	if errors.Is(err, service.ErrNoPendingMFA) {
		a.logAudit(c, "Operator.MFAEnabled", false, map[string]any{"reason": "no enrollment in progress"})
		c.JSON(http.StatusBadRequest, gin.H{"error": "enrollment expired, start again"})
		return
	}
	if errors.Is(err, service.ErrInvalidCredentials) {
		a.logAudit(c, "Operator.MFAEnabled", false, map[string]any{"reason": "wrong code"})
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "that code did not match; check the time on your device and try again",
		})
		return
	}
	if err != nil {
		a.logAudit(c, "Operator.MFAEnabled", false, map[string]any{"reason": "could not save"})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not enable two factor"})
		return
	}
	a.logAudit(c, "Operator.MFAEnabled", true, nil)
	if !a.reissueSession(c, op, epoch) {
		c.JSON(http.StatusOK, gin.H{"ok": true, "signedOut": true})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// MFADisable turns off two factor after verifying a current code. It is
// throttled per session, and a wrong code counts against this session only.
func (a *AdminAPI) MFADisable(c *gin.Context) {
	var req struct {
		Code string `json:"code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	op := middleware.OperatorFromContext(c)
	if !a.beginProof(c, "Operator.MFADisabled") {
		return
	}
	err := a.operators.DisableMFA(op.ID, req.Code, sessionCookie(c))
	if errors.Is(err, service.ErrMFANotEnabled) {
		// no code was checked, so the count of wrong proofs is not cleared.
		a.sessions.ProofSkipped(sessionCookie(c))
		c.JSON(http.StatusOK, gin.H{"ok": true})
		return
	}
	if errors.Is(err, service.ErrInvalidCredentials) {
		a.logAudit(c, "Operator.MFADisabled", false, nil)
		if a.proofFailed(c) {
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "that code did not match"})
		return
	}
	if err != nil {
		a.sessions.ProofSkipped(sessionCookie(c))
		a.logAudit(c, "Operator.MFADisabled", false, nil)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not turn off two factor"})
		return
	}
	a.sessions.ProofSucceeded(sessionCookie(c))
	a.logAudit(c, "Operator.MFADisabled", true, nil)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// OperatorsList returns the operator accounts, marking the current one.
func (a *AdminAPI) OperatorsList(c *gin.Context) {
	ops, err := a.operators.ListOperators()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not list operators"})
		return
	}
	self := middleware.OperatorFromContext(c)
	out := make([]gin.H, 0, len(ops))
	for i := range ops {
		out = append(out, gin.H{
			"id": ops[i].ID, "username": ops[i].Username, "createdAt": ops[i].CreatedAt,
			"self": self.ID == ops[i].ID,
		})
	}
	c.JSON(http.StatusOK, gin.H{"operators": out})
}

// OperatorCreate adds a new operator account. It creates a new login, so it
// needs a fresh step up. The input is checked first so a typo does not spend the
// grant; CreateOperator checks it again after the grant is consumed.
func (a *AdminAPI) OperatorCreate(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if err := a.operators.ValidateNewOperator(req.Username, req.Password); err != nil {
		replyRefused(c, "Operator.Create", "could not create the operator", err)
		return
	}
	if !a.requireStepUp(c, middleware.OperatorFromContext(c), "Operator.Create") {
		return
	}
	op, err := a.operators.CreateOperator(req.Username, req.Password)
	if err != nil {
		a.logAudit(c, "Operator.Create", false, map[string]any{"username": strings.TrimSpace(req.Username)})
		if replyThrottled(c, err) {
			return
		}
		replyRefused(c, "Operator.Create", "could not create the operator", err)
		return
	}
	a.logAudit(c, "Operator.Create", true, map[string]any{"username": op.Username})
	c.JSON(http.StatusOK, gin.H{"id": op.ID, "username": op.Username})
}

// OperatorDelete removes an operator account (never the last one). It changes
// another account, so it needs a fresh step up.
func (a *AdminAPI) OperatorDelete(c *gin.Context) {
	id := c.Param("id")
	if !a.requireStepUp(c, middleware.OperatorFromContext(c), "Operator.Delete") {
		return
	}
	if err := a.operators.DeleteOperator(id); err != nil {
		a.logAudit(c, "Operator.Delete", false, map[string]any{"id": id})
		if errors.Is(err, service.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "operator not found"})
			return
		}
		if errors.Is(err, service.ErrLastOperator) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not delete operator"})
		return
	}
	a.logAudit(c, "Operator.Delete", true, map[string]any{"id": id})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// logAudit records a sensitive operation performed by the current operator.
func (a *AdminAPI) logAudit(c *gin.Context, action string, success bool, details map[string]any) {
	op := middleware.OperatorFromContext(c)
	a.audit.Record(action, op.ID, op.Username, c.ClientIP(), success, details)
}

// auditFailed records a failed action with a short reason and the given
// details. It never takes secrets.
func (a *AdminAPI) auditFailed(c *gin.Context, action, reason string, details map[string]any) {
	d := map[string]any{"reason": reason}
	for k, v := range details {
		d[k] = v
	}
	a.logAudit(c, action, false, d)
}

// replyRefused answers a failed package action. A validation refusal is sent as
// written; an internal fault is logged and the client gets only fallback.
func replyRefused(c *gin.Context, action, fallback string, err error) {
	if service.IsValidation(err) {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	log.Printf("%s: %v", action, err)
	c.JSON(http.StatusInternalServerError, gin.H{"error": fallback})
}

// replyListError answers a failed list read: a sort column outside the allowlist
// is a bad request, anything else a server fault whose text stays in the log.
func replyListError(c *gin.Context, action string, err error) {
	if errors.Is(err, repository.ErrOrderColumn) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid sort column"})
		return
	}
	log.Printf("%s: %v", action, err)
	c.JSON(http.StatusInternalServerError, gin.H{"error": "could not load the list"})
}

// previewURLs returns the admin serve URLs for a package's preview images, in
// gallery order, so listings and the detail page can render thumbnails.
func (a *AdminAPI) previewURLs(nsName, name, pkgID string) []string {
	ps, err := a.reg.PreviewsByPackageID(pkgID)
	if err != nil {
		return []string{}
	}
	urls := make([]string, 0, len(ps))
	for i := range ps {
		urls = append(urls, "/api/v1/admin/packages/"+nsName+"/"+name+"/previews/"+ps[i].BlobSHA256)
	}
	return urls
}

// PreviewsList returns a package's preview image URLs.
func (a *AdminAPI) PreviewsList(c *gin.Context) {
	ns := c.Param("ns")
	name := c.Param("name")
	_, pkg, _, err := a.reg.Resolve(ns, name, "latest")
	if err != nil {
		// an unknown package, or one with no version, lists no previews.
		c.JSON(http.StatusOK, gin.H{"previews": []string{}})
		return
	}
	c.JSON(http.StatusOK, gin.H{"previews": a.previewURLs(ns, name, pkg.ID)})
}

// PreviewAdd stores one preview image (base64) as package metadata.
func (a *AdminAPI) PreviewAdd(c *gin.Context) {
	extendRead(c, largeBodyReadTimeout)
	var req struct {
		Content string `json:"content"` // base64
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Content == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	raw, err := base64.StdEncoding.DecodeString(req.Content)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "content is not valid base64"})
		return
	}
	sha, err := a.reg.AddPreviewImage(c.Param("ns"), c.Param("name"), raw)
	if errors.Is(err, service.ErrNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if err != nil {
		replyRefused(c, "Package.PreviewAdd", "could not store the preview image", err)
		return
	}
	a.logAudit(c, "Package.PreviewAdd", true, map[string]any{"package": c.Param("ns") + "/" + c.Param("name")})
	url := "/api/v1/admin/packages/" + c.Param("ns") + "/" + c.Param("name") + "/previews/" + sha
	c.JSON(http.StatusOK, gin.H{"sha": sha, "url": url})
}

// PreviewReorder sets the gallery order of a package's preview images from an
// ordered list of blob shas (the drag and drop order in the UI).
func (a *AdminAPI) PreviewReorder(c *gin.Context) {
	var req struct {
		Order []string `json:"order"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if err := a.reg.ReorderPreviews(c.Param("ns"), c.Param("name"), req.Order); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "could not reorder previews"})
		return
	}
	a.logAudit(c, "Package.PreviewReorder", true, map[string]any{"package": c.Param("ns") + "/" + c.Param("name")})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// PreviewServe streams a preview image blob.
func (a *AdminAPI) PreviewServe(c *gin.Context) {
	rc, mediaType, err := a.reg.OpenPreview(c.Param("ns"), c.Param("name"), c.Param("sha"))
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}
	defer rc.Close()
	c.Header("Content-Type", mediaType)
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Content-Security-Policy", "sandbox")
	c.Header("Cache-Control", "private, max-age=300")
	_, _ = io.Copy(c.Writer, rc)
}

// PreviewDelete removes one preview image.
func (a *AdminAPI) PreviewDelete(c *gin.Context) {
	pkgRef := map[string]any{"package": c.Param("ns") + "/" + c.Param("name")}
	if err := a.reg.DeletePreview(c.Param("ns"), c.Param("name"), c.Param("sha")); err != nil {
		a.auditFailed(c, "Package.PreviewDelete", "could not delete", pkgRef)
		c.JSON(http.StatusBadRequest, gin.H{"error": "could not delete preview"})
		return
	}
	a.logAudit(c, "Package.PreviewDelete", true, pkgRef)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// PackageSource returns a version's payload files + manifest so the UI can load
// it back into the author wizard to publish a new version.
func (a *AdminAPI) PackageSource(c *gin.Context) {
	v, m, files, err := a.reg.VersionContent(c.Param("ns"), c.Param("name"), c.Param("version"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	out := make([]gin.H, 0, len(files))
	for p, b := range files {
		out = append(out, gin.H{"path": p, "content": base64.StdEncoding.EncodeToString(b)})
	}
	c.JSON(http.StatusOK, gin.H{
		"type":           m.Type,
		"version":        v.Version,
		"description":    m.Description,
		"tags":           m.Tags,
		"preview":        m.Preview,
		"variables":      m.Variables,
		"dependencies":   m.Dependencies,
		"shareVariables": m.ShareVariables,
		"attachments":    service.PackageAttachments(files),
		"files":          out,
	})
}

// PackageArchive streams the package archive for a version to an operator. It
// does not count as a download.
func (a *AdminAPI) PackageArchive(c *gin.Context) {
	_, pkg, v, err := a.reg.Resolve(c.Param("ns"), c.Param("name"), c.Param("version"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	rc, err := a.reg.OpenArchiveNoCount(v)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "open archive"})
		return
	}
	defer rc.Close()
	c.Header("Content-Type", "application/gzip")
	c.Header("Content-Disposition", attachmentDisposition(pkg.Name+"-"+v.Version+".tar.gz"))
	c.Status(http.StatusOK)
	_, _ = io.Copy(c.Writer, rc)
}

// PackageDelete removes a package and all its versions.
func (a *AdminAPI) PackageDelete(c *gin.Context) {
	pkgRef := map[string]any{"package": c.Param("ns") + "/" + c.Param("name")}
	err := a.reg.DeletePackage(c.Param("ns"), c.Param("name"))
	var depErr *service.DependentsError
	if errors.As(err, &depErr) {
		a.auditFailed(c, "Package.Delete", "has dependents", pkgRef)
		c.JSON(http.StatusConflict, gin.H{"error": depErr.Error(), "dependents": depErr.Dependents})
		return
	}
	if errors.Is(err, service.ErrNotFound) {
		a.auditFailed(c, "Package.Delete", "not found", pkgRef)
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if err != nil {
		a.auditFailed(c, "Package.Delete", "could not delete", pkgRef)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not delete the package"})
		return
	}
	a.logAudit(c, "Package.Delete", true, pkgRef)
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// PackageMove moves a package to another namespace, repacking every version
// under the new id. The target namespace must exist and must not already have a
// package of this name.
func (a *AdminAPI) PackageMove(c *gin.Context) {
	var req struct {
		ToNamespace string `json:"toNamespace"`
		NewName     string `json:"newName"`
	}
	pkgRef := map[string]any{"package": c.Param("ns") + "/" + c.Param("name")}
	if err := c.ShouldBindJSON(&req); err != nil {
		a.auditFailed(c, "Package.Move", "invalid request", pkgRef)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	newName := strings.TrimSpace(req.NewName)
	if newName != "" && !model.ValidPackageName(newName) {
		a.auditFailed(c, "Package.Move", "invalid name", pkgRef)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "name must be lowercase letters, numbers, dots, dashes or underscores",
		})
		return
	}
	if err := a.reg.MovePackage(c.Param("ns"), c.Param("name"), req.ToNamespace, newName); err != nil {
		a.auditFailed(c, "Package.Move", "move refused", pkgRef)
		if errors.Is(err, service.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		if errors.Is(err, service.ErrConcurrentChange) {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		replyRefused(c, "Package.Move", "could not move the package", err)
		return
	}
	finalName := newName
	if finalName == "" {
		finalName = c.Param("name")
	}
	a.logAudit(c, "Package.Move", true, map[string]any{
		"package": c.Param("ns") + "/" + c.Param("name"), "to": req.ToNamespace + "/" + finalName,
	})
	c.JSON(http.StatusOK, gin.H{"status": "moved", "namespace": req.ToNamespace, "name": finalName})
}

// PackageMetaUpdate edits metadata in place without publishing a new version;
// the per version manifests are untouched.
func (a *AdminAPI) PackageMetaUpdate(c *gin.Context) {
	var req struct {
		Title       string   `json:"title"`
		Description string   `json:"description"`
		Tags        []string `json:"tags"`
	}
	pkgRef := map[string]any{"package": c.Param("ns") + "/" + c.Param("name")}
	if err := c.ShouldBindJSON(&req); err != nil {
		a.auditFailed(c, "Package.MetaUpdate", "invalid request", pkgRef)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	title := strings.TrimSpace(req.Title)
	description := strings.TrimSpace(req.Description)
	if err := model.ValidatePackageMeta(title, description); err != nil {
		a.auditFailed(c, "Package.MetaUpdate", "invalid details", pkgRef)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	tags := model.CleanTags(req.Tags)
	err := a.reg.UpdatePackageMeta(
		c.Param("ns"), c.Param("name"), title, description, strings.Join(tags, ","),
	)
	if err != nil {
		a.auditFailed(c, "Package.MetaUpdate", "update refused", pkgRef)
		if errors.Is(err, service.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		replyRefused(c, "Package.MetaUpdate", "could not update the package details", err)
		return
	}
	a.logAudit(c, "Package.MetaUpdate", true, map[string]any{"package": c.Param("ns") + "/" + c.Param("name")})
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// VersionYank sets or clears the yanked flag on a version.
func (a *AdminAPI) VersionYank(c *gin.Context) {
	var req struct {
		Yanked bool `json:"yanked"`
	}
	_ = c.ShouldBindJSON(&req)
	pkgID := c.Param("ns") + "/" + c.Param("name")
	warnings, err := a.reg.YankVersion(c.Param("ns"), c.Param("name"), c.Param("version"), req.Yanked)
	if err != nil {
		a.auditFailed(c, "Version.Yank", "not found",
			map[string]any{"package": pkgID, "version": c.Param("version")})
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	a.logAudit(c, "Version.Yank", true, map[string]any{
		"package": pkgID, "version": c.Param("version"), "bundlesOverCap": warnings,
	})
	c.JSON(http.StatusOK, gin.H{"status": "updated", "warnings": bundleCapWarnings(warnings)})
}

// VersionDelete removes one version of a package.
func (a *AdminAPI) VersionDelete(c *gin.Context) {
	warnings, err := a.reg.DeleteVersion(c.Param("ns"), c.Param("name"), c.Param("version"))
	if err != nil {
		ref := map[string]any{"package": c.Param("ns") + "/" + c.Param("name"), "version": c.Param("version")}
		if errors.Is(err, service.ErrLastVersion) {
			a.auditFailed(c, "Version.Delete", "last version", ref)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		a.auditFailed(c, "Version.Delete", "not found", ref)
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	a.logAudit(c, "Version.Delete", true, map[string]any{
		"package":        c.Param("ns") + "/" + c.Param("name"),
		"version":        c.Param("version"),
		"bundlesOverCap": warnings,
	})
	c.JSON(http.StatusOK, gin.H{"status": "deleted", "warnings": bundleCapWarnings(warnings)})
}

// bundleCapWarnings turns the bundles a version change pushed over the install
// cap into messages for the operator. It returns an empty list, never null.
func bundleCapWarnings(bundles []string) []string {
	out := []string{}
	for _, b := range bundles {
		out = append(out, fmt.Sprintf("Bundle %s now unpacks to more than the %d MiB Phishing Club "+
			"installs, so it will fail to install until the bundle or this package changes",
			b, service.MaxBundleInstallBytes>>20))
	}
	return out
}

// --- Packages ---

// PackagesList returns a page of packages with their namespace name.
func (a *AdminAPI) PackagesList(c *gin.Context) {
	q, page, perPage := listQuery(c)
	namespaces, _ := a.reg.Namespaces(nil)
	nsName := map[string]string{}
	nsColor := map[string]string{}
	nsVis := map[string]string{}
	for i := range namespaces {
		nsName[namespaces[i].ID] = namespaces[i].Name
		nsColor[namespaces[i].ID] = namespaces[i].Color
		nsVis[namespaces[i].ID] = a.reg.EffectiveVisibility(namespaces[i].Visibility)
	}
	packages, err := a.reg.Packages(q)
	if err != nil {
		replyListError(c, "Package.List", err)
		return
	}
	total, err := a.reg.CountPackages(q)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "list"})
		return
	}
	out := make([]gin.H, 0, len(packages))
	for i := range packages {
		p := &packages[i]
		out = append(out, gin.H{
			"namespace": nsName[p.NamespaceID], "namespaceColor": nsColor[p.NamespaceID],
			"name": p.Name, "title": p.Title, "type": p.Type,
			"visibility": nsVis[p.NamespaceID], "downloadCount": p.DownloadCount,
			"description": p.Description, "tags": utils.SplitTrim(p.Tags, ","), "updatedAt": p.UpdatedAt,
		})
	}
	c.JSON(http.StatusOK, gin.H{"packages": out, "total": total, "page": page, "perPage": perPage})
}

// PackageDependents returns the packages with a version that depends on this
// one, so the UI can say why a delete is refused or warn before a move.
func (a *AdminAPI) PackageDependents(c *gin.Context) {
	deps, err := a.reg.DependentsOf(c.Param("ns"), c.Param("name"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not check dependents"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"dependents": deps})
}

// PackageDetail returns a package and its versions.
func (a *AdminAPI) PackageDetail(c *gin.Context) {
	ns, pkg, _, err := a.reg.Resolve(c.Param("ns"), c.Param("name"), "latest")
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	versions, _ := a.reg.Versions(pkg.ID)
	vout := make([]gin.H, 0, len(versions))
	for i := range versions {
		vout = append(vout, gin.H{
			"version": versions[i].Version, "yanked": versions[i].Yanked,
			"size": versions[i].Size, "createdAt": versions[i].CreatedAt,
			"downloadCount": versions[i].DownloadCount,
		})
	}
	c.JSON(http.StatusOK, gin.H{
		"namespace": ns.Name, "namespaceColor": ns.Color, "name": pkg.Name, "title": pkg.Title, "type": pkg.Type,
		"description": pkg.Description, "tags": utils.SplitTrim(pkg.Tags, ","),
		"visibility":    a.reg.EffectiveVisibility(ns.Visibility),
		"downloadCount": pkg.DownloadCount, "versions": vout,
		"previewImages": a.previewURLs(ns.Name, pkg.Name, pkg.ID),
		"previewMax":    service.MaxPreviewImages,
	})
}

// PackageAuthor builds the archive on the server from content authored in the
// browser and stores it as a new version.
func (a *AdminAPI) PackageAuthor(c *gin.Context) {
	extendRead(c, largeBodyReadTimeout)
	var req struct {
		Namespace      string                `json:"namespace"`
		Name           string                `json:"name"`
		Title          string                `json:"title"`
		Type           string                `json:"type"`
		Version        string                `json:"version"`
		Description    string                `json:"description"`
		Tags           []string              `json:"tags"`
		Preview        string                `json:"preview"`
		Variables      []manifest.Variable   `json:"variables"`
		Dependencies   []manifest.Dependency `json:"dependencies"`
		ShareVariables *bool                 `json:"shareVariables"`
		Files          []struct {
			Path    string `json:"path"`
			Content string `json:"content"` // base64
		} `json:"files"`
		// package meta preview images (not shipped in the archive)
		PreviewImages []struct {
			Content string `json:"content"` // base64
		} `json:"previewImages"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		a.auditFailed(c, "Package.Publish", "invalid request", nil)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	pkgRef := map[string]any{"package": req.Namespace + "/" + req.Name, "version": req.Version}
	req.Title = strings.TrimSpace(req.Title)
	req.Description = strings.TrimSpace(req.Description)
	// the required fields and the free text caps are the model's rules: SQLite does
	// not enforce the column size tags, so the publish path caps title and
	// description exactly as the meta edit path does.
	if err := (model.Package{
		Namespace: req.Namespace, Name: req.Name, Type: req.Type, Version: req.Version,
		Title: req.Title, Description: req.Description,
	}).Validate(); err != nil {
		a.auditFailed(c, "Package.Publish", "invalid package", pkgRef)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// archive files and meta preview images arrive base64 encoded.
	files := map[string][]byte{}
	for _, f := range req.Files {
		raw, err := base64.StdEncoding.DecodeString(f.Content)
		if err != nil {
			a.auditFailed(c, "Package.Publish", "file not valid base64", pkgRef)
			c.JSON(http.StatusBadRequest, gin.H{"error": "file " + f.Path + " is not valid base64"})
			return
		}
		files[f.Path] = raw
	}
	previews := make([][]byte, 0, len(req.PreviewImages))
	for _, pi := range req.PreviewImages {
		raw, derr := base64.StdEncoding.DecodeString(pi.Content)
		if derr != nil {
			continue
		}
		previews = append(previews, raw)
	}
	v, failedPreviews, err := a.reg.AuthorPackage(service.AuthoredPackage{
		Namespace: req.Namespace, Name: req.Name, Type: req.Type, Version: req.Version,
		Title: req.Title, Description: req.Description, Tags: model.CleanTags(req.Tags),
		Preview:   req.Preview,
		Variables: req.Variables, Dependencies: req.Dependencies, ShareVariables: req.ShareVariables,
		Files: files, PreviewImages: previews,
	})
	switch {
	case err == nil:
		a.logAudit(c, "Package.Publish", true, map[string]any{
			"package": req.Namespace + "/" + req.Name, "version": v.Version, "failedPreviews": failedPreviews,
		})
		c.JSON(http.StatusOK, gin.H{
			"namespace": req.Namespace, "name": req.Name,
			"version": v.Version, "failedPreviews": failedPreviews,
		})
	case errors.Is(err, service.ErrVersionExists):
		a.auditFailed(c, "Package.Publish", "version exists", pkgRef)
		c.JSON(http.StatusConflict, gin.H{"error": "that version already exists; bump the version"})
	case errors.Is(err, service.ErrConcurrentChange):
		a.auditFailed(c, "Package.Publish", "concurrent change", pkgRef)
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	default:
		a.auditFailed(c, "Package.Publish", "publish refused", pkgRef)
		replyRefused(c, "Package.Publish", "could not publish the package", err)
	}
}

// TagsList returns every tag a package carries with its color, empty when none is
// set, so the UI can list each tag in use and render its chip in its color. The
// admin sees every package, so tags on private packages are listed too.
func (a *AdminAPI) TagsList(c *gin.Context) {
	tags, err := a.reg.ListTagsInUse()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "list tags"})
		return
	}
	out := []gin.H{}
	for i := range tags {
		out = append(out, gin.H{"name": tags[i].Name, "color": tags[i].Color})
	}
	c.JSON(http.StatusOK, gin.H{"tags": out})
}

// TagSetColor sets the global color for a tag name. An empty or unknown color
// clears it. The tag name is normalized the same way package tags are.
func (a *AdminAPI) TagSetColor(c *gin.Context) {
	var req struct {
		Name  string `json:"name"`
		Color string `json:"color"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	names := model.CleanTags([]string{req.Name})
	if len(names) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "a tag name is required"})
		return
	}
	color := model.NormalizeColor(req.Color)
	if err := a.reg.SetTagColor(names[0], color); err != nil {
		if errors.Is(err, service.ErrTagNotInUse) {
			c.JSON(http.StatusNotFound, gin.H{
				"error": "no package uses that tag yet; save it on a package first, then set its color",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not set tag color"})
		return
	}
	a.logAudit(c, "Tag.SetColor", true, map[string]any{"tag": names[0], "color": color})
	c.JSON(http.StatusOK, gin.H{"status": "saved"})
}

// DraftSave stores an unpublished authoring payload for a package address. The
// body is the full author request, so publishing a draft later replays it. One
// draft per namespace and name: saving overwrites the previous.
func (a *AdminAPI) DraftSave(c *gin.Context) {
	extendRead(c, largeBodyReadTimeout)
	raw, err := c.GetRawData()
	if err != nil || len(raw) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	var meta struct {
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
		Title     string `json:"title"`
		Type      string `json:"type"`
		Version   string `json:"version"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil || meta.Namespace == "" || meta.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "namespace and name are required"})
		return
	}
	if err := (model.Namespace{Name: meta.Namespace}).Validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if !model.ValidPackageName(meta.Name) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "package name must be lowercase letters, numbers, dots, dashes and underscores",
		})
		return
	}
	d := &database.Draft{
		Namespace: meta.Namespace, Name: meta.Name, Title: strings.TrimSpace(meta.Title),
		Type: meta.Type, Version: meta.Version, Body: string(raw),
	}
	if err := a.reg.SaveDraft(d); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not save draft"})
		return
	}
	a.logAudit(c, "Draft.Save", true, map[string]any{"package": meta.Namespace + "/" + meta.Name})
	c.JSON(http.StatusOK, gin.H{"status": "saved"})
}

// DraftsList lists saved drafts for the drafts view, newest first.
func (a *AdminAPI) DraftsList(c *gin.Context) {
	drafts, err := a.reg.ListDrafts()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "list drafts"})
		return
	}
	out := []gin.H{}
	for i := range drafts {
		d := &drafts[i]
		out = append(out, gin.H{
			"namespace": d.Namespace, "name": d.Name, "title": d.Title,
			"type": d.Type, "version": d.Version, "updatedAt": d.UpdatedAt,
		})
	}
	c.JSON(http.StatusOK, gin.H{"drafts": out})
}

// DraftGet returns one draft's full author body so the workbench can reopen it.
func (a *AdminAPI) DraftGet(c *gin.Context) {
	d, err := a.reg.GetDraft(c.Param("ns"), c.Param("name"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.Data(http.StatusOK, "application/json", []byte(d.Body))
}

// DraftDelete discards a draft.
func (a *AdminAPI) DraftDelete(c *gin.Context) {
	if err := a.reg.DeleteDraft(c.Param("ns"), c.Param("name")); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not delete draft"})
		return
	}
	a.logAudit(c, "Draft.Delete", true, map[string]any{"package": c.Param("ns") + "/" + c.Param("name")})
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// ChangePassword changes the signed in operator's password. It drops other
// sessions, so the caller is signed out and must log in again.
func (a *AdminAPI) ChangePassword(c *gin.Context) {
	op := middleware.OperatorFromContext(c)
	var req struct {
		Current  string `json:"current"`
		Next     string `json:"next"`
		Username string `json:"username"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if len(req.Next) < 12 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "new password must be at least 12 characters"})
		return
	}
	// the first login of the seeded account must also replace the shared default
	// username, so no install keeps a name every attacker already knows.
	if a.guard.PasswordChangeRequired(op) && service.HasDefaultUsername(op) &&
		(strings.TrimSpace(req.Username) == "" || strings.EqualFold(strings.TrimSpace(req.Username), op.Username)) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "choose a username other than admin"})
		return
	}
	oldUsername := op.Username
	if !a.beginProof(c, "Operator.ChangePassword") {
		return
	}
	epoch, err := a.operators.ChangePassword(op.ID, req.Current, req.Next, req.Username)
	switch {
	case err == nil, errors.Is(err, service.ErrNewPasswordBusy), errors.Is(err, service.ErrPasswordUnchanged),
		errors.Is(err, service.ErrInvalidUsername), errors.Is(err, service.ErrUsernameTaken):
		// the current password was checked and was right.
		a.sessions.ProofSucceeded(sessionCookie(c))
	case errors.Is(err, service.ErrInvalidCredentials):
		a.logAudit(c, "Operator.ChangePassword", false, map[string]any{"reason": "current password incorrect"})
		if a.proofFailed(c) {
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "current password is incorrect"})
		return
	case errors.Is(err, service.ErrThrottled):
		// the server was too busy to check it, so it does not count.
		a.sessions.ProofSkipped(sessionCookie(c))
		replyThrottled(c, err)
		return
	default:
		// the change may have stopped before the password was checked, so the
		// count is left as it is.
		a.sessions.ProofSkipped(sessionCookie(c))
	}
	if errors.Is(err, service.ErrNewPasswordBusy) {
		secs := int(service.BusyWait / time.Second)
		c.Header("Retry-After", strconv.Itoa(secs))
		c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error(), "retryAfter": secs})
		return
	}
	if errors.Is(err, service.ErrPasswordUnchanged) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "new password must differ from the current one"})
		return
	}
	if errors.Is(err, service.ErrInvalidUsername) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username must be 3 to 64 characters and not admin"})
		return
	}
	if errors.Is(err, service.ErrUsernameTaken) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "an operator with that username already exists"})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not change password"})
		return
	}
	a.logAudit(c, "Operator.ChangePassword", true, nil)
	updated, gerr := a.operators.GetOperator(op.ID)
	if gerr != nil {
		updated = op
	}
	if updated.Username != oldUsername {
		a.audit.Record("Operator.Rename", op.ID, updated.Username, c.ClientIP(), true,
			map[string]any{"from": oldUsername, "to": updated.Username})
	}
	// every session was dropped, including this one; issue a fresh session id so
	// the operator stays signed in here and anything holding the old id is out.
	id, err := a.sessions.Create(op.ID, epoch, c.ClientIP())
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"status": "changed", "username": updated.Username, "signedOut": true})
		return
	}
	setSessionCookie(c, id)
	// with no second factor the password is the step up proof, and it was just
	// checked, so the new session may add a first factor without asking again.
	if _, _, passwordOnly, serr := a.operators.StepUpMethods(op.ID); serr == nil && passwordOnly {
		a.sessions.GrantStepUp(id, op.ID)
	}
	c.JSON(http.StatusOK, gin.H{"status": "changed", "username": updated.Username})
}

// Stats returns registry totals for the dashboard.
func (a *AdminAPI) Stats(c *gin.Context) {
	counts, err := a.stats.Counts()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "stats"})
		return
	}
	c.JSON(http.StatusOK, counts)
}

// --- Namespaces ---

// NamespacesList returns a page of namespaces with package and download counts.
func (a *AdminAPI) NamespacesList(c *gin.Context) {
	q, page, perPage := listQuery(c)
	ns, err := a.reg.Namespaces(q)
	if err != nil {
		replyListError(c, "Namespace.List", err)
		return
	}
	total, err := a.reg.CountNamespaces(q)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "list"})
		return
	}
	// the package count shows how much each namespace holds and why a non empty
	// one cannot be deleted. A failed count shows zero rather than failing the list.
	count, downloads, _ := a.reg.NamespaceTotals()
	out := make([]gin.H, 0, len(ns))
	for i := range ns {
		out = append(out, gin.H{
			"id": ns[i].ID, "name": ns[i].Name,
			"description": ns[i].Description, "visibility": a.reg.EffectiveVisibility(ns[i].Visibility),
			"color":         ns[i].Color,
			"packageCount":  count[ns[i].ID],
			"downloadCount": downloads[ns[i].ID],
		})
	}
	c.JSON(http.StatusOK, gin.H{"namespaces": out, "total": total, "page": page, "perPage": perPage})
}

func (a *AdminAPI) NamespaceCreate(c *gin.Context) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Visibility  string `json:"visibility"`
		Color       string `json:"color"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Name == "" {
		a.auditFailed(c, "Namespace.Create", "name is required", nil)
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	nsRef := map[string]any{"name": req.Name}
	req.Description = strings.TrimSpace(req.Description)
	if err := (model.Namespace{Name: req.Name, Description: req.Description}).Validate(); err != nil {
		a.auditFailed(c, "Namespace.Create", "invalid namespace", nil)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ns, err := a.reg.CreateNamespace(
		req.Name, req.Description, normalizeVisibility(req.Visibility), model.NormalizeColor(req.Color),
	)
	if errors.Is(err, service.ErrPublicDisabled) {
		a.auditFailed(c, "Namespace.Create", "public namespaces are off", nsRef)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if errors.Is(err, service.ErrNamespaceExists) {
		a.auditFailed(c, "Namespace.Create", "name taken", nsRef)
		c.JSON(http.StatusConflict, gin.H{"error": "a namespace with that name already exists"})
		return
	}
	if err != nil {
		a.auditFailed(c, "Namespace.Create", "could not create", nsRef)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "create"})
		return
	}
	a.logAudit(c, "Namespace.Create", true, map[string]any{"name": req.Name})
	c.JSON(http.StatusOK, gin.H{"id": ns.ID})
}

func (a *AdminAPI) NamespaceUpdate(c *gin.Context) {
	var req struct {
		Description string `json:"description"`
		Visibility  string `json:"visibility"`
		Color       string `json:"color"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	req.Description = strings.TrimSpace(req.Description)
	if err := model.ValidateNamespaceDescription(req.Description); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	id := c.Param("id")
	ns, err := a.reg.GetNamespaceByID(id)
	if err != nil || ns == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	newVisibility := normalizeVisibility(req.Visibility)
	details := map[string]any{
		"id": id, "name": ns.Name,
		"oldVisibility": ns.Visibility, "newVisibility": newVisibility,
	}
	if err := a.reg.UpdateNamespace(id, req.Description, newVisibility); err != nil {
		details["reason"] = err.Error()
		a.logAudit(c, "Namespace.Update", false, details)
		if errors.Is(err, service.ErrPublicDisabled) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if errors.Is(err, service.ErrVisibilityRefused) {
			// the reason names the package version the change would break, which
			// the operator needs to resolve it.
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update"})
		return
	}
	if err := a.reg.SetNamespaceColor(id, model.NormalizeColor(req.Color)); err != nil {
		details["reason"] = "color update failed"
		a.logAudit(c, "Namespace.Update", false, details)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update"})
		return
	}
	a.logAudit(c, "Namespace.Update", true, details)
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

// NamespaceRenameImpact reports the consequences of renaming a namespace so the
// UI can warn before the operator confirms: packages that change address, external
// packages that would break, and tokens that follow the rename.
func (a *AdminAPI) NamespaceRenameImpact(c *gin.Context) {
	ns, err := a.reg.GetNamespaceByID(c.Param("id"))
	if err != nil || ns == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	pkgs, external, tokens, err := a.reg.NamespaceRenameImpact(ns.Name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "impact"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"name": ns.Name, "packages": pkgs,
		"externalDependents": utils.NonNil(external), "tokensAffected": tokens,
	})
}

// NamespaceRename changes a namespace name, repacking every package it owns under
// the new address. Old addresses stop resolving, so this is a deliberate action
// with consequences surfaced by NamespaceRenameImpact.
func (a *AdminAPI) NamespaceRename(c *gin.Context) {
	var req struct {
		NewName string `json:"newName"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		a.auditFailed(c, "Namespace.Rename", "invalid request", map[string]any{"id": c.Param("id")})
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	ns, err := a.reg.GetNamespaceByID(c.Param("id"))
	if err != nil || ns == nil {
		a.auditFailed(c, "Namespace.Rename", "not found", map[string]any{"id": c.Param("id")})
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	newName := strings.TrimSpace(req.NewName)
	if err := (model.Namespace{Name: newName}).Validate(); err != nil {
		a.auditFailed(c, "Namespace.Rename", "invalid name", map[string]any{"from": ns.Name})
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if newName == ns.Name {
		c.JSON(http.StatusOK, gin.H{"status": "renamed", "name": ns.Name})
		return
	}
	if existing, err := a.reg.GetNamespace(newName); err == nil && existing != nil {
		a.auditFailed(c, "Namespace.Rename", "name taken", map[string]any{"from": ns.Name, "to": newName})
		c.JSON(http.StatusConflict, gin.H{"error": "a namespace with that name already exists"})
		return
	}
	if err := a.reg.RenameNamespace(ns.Name, newName); err != nil {
		a.auditFailed(c, "Namespace.Rename", "rename refused", map[string]any{"from": ns.Name, "to": newName})
		switch {
		case errors.Is(err, service.ErrNamespaceExists):
			c.JSON(http.StatusConflict, gin.H{"error": "a namespace with that name already exists"})
		case errors.Is(err, service.ErrNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		case errors.Is(err, service.ErrConcurrentChange):
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		default:
			replyRefused(c, "Namespace.Rename", "could not rename the namespace", err)
		}
		return
	}
	a.logAudit(c, "Namespace.Rename", true, map[string]any{"from": ns.Name, "to": newName})
	c.JSON(http.StatusOK, gin.H{"status": "renamed", "name": newName})
}

func (a *AdminAPI) NamespaceDelete(c *gin.Context) {
	err := a.reg.DeleteNamespace(c.Param("id"))
	if errors.Is(err, service.ErrNamespaceNotEmpty) {
		a.auditFailed(c, "Namespace.Delete", "not empty", map[string]any{"id": c.Param("id")})
		c.JSON(http.StatusConflict, gin.H{"error": "namespace still has packages; delete them first"})
		return
	}
	if err != nil {
		a.auditFailed(c, "Namespace.Delete", "could not delete", map[string]any{"id": c.Param("id")})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete"})
		return
	}
	a.logAudit(c, "Namespace.Delete", true, map[string]any{"id": c.Param("id")})
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

// --- Tokens ---

func (a *AdminAPI) TokensList(c *gin.Context) {
	tokens, err := a.tokens.List()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "list"})
		return
	}
	out := make([]gin.H, 0, len(tokens))
	for i := range tokens {
		out = append(out, gin.H{
			"id": tokens[i].ID, "name": tokens[i].Name,
			"prefix": tokens[i].Prefix, "revoked": tokens[i].Revoked,
			"entitlements": tokens[i].Entitlements,
			"allowedCidrs": tokens[i].AllowedCIDRs,
			"lastUsedAt":   tokens[i].LastUsedAt, "expiresAt": tokens[i].ExpiresAt,
			"createdBy": tokens[i].CreatedBy,
		})
	}
	c.JSON(http.StatusOK, gin.H{"tokens": out})
}

func (a *AdminAPI) TokenCreate(c *gin.Context) {
	var req struct {
		Name          string   `json:"name"`
		Namespaces    []string `json:"namespaces"`
		AllowedCIDRs  []string `json:"allowedCidrs"`
		ExpiresInDays int      `json:"expiresInDays"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Name == "" {
		a.auditFailed(c, "Token.Create", "name is required", nil)
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	// an entitlement must be the wildcard or a real namespace slug, and each allowed
	// entry a CIDR or bare IP, so a typo cannot mint a token scoped to a namespace
	// that can never exist or restricted to an address range it never matches. an
	// empty allowlist leaves the token unrestricted by source IP.
	if err := (model.Token{Entitlements: req.Namespaces, AllowedCIDRs: req.AllowedCIDRs}).Validate(); err != nil {
		a.auditFailed(c, "Token.Create", "invalid token settings", map[string]any{"name": req.Name})
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := a.tokens.CheckScopes(req.Namespaces); err != nil {
		a.auditFailed(c, "Token.Create", "invalid token settings", map[string]any{"name": req.Name})
		replyRefused(c, "Token.Create", "could not create the token", err)
		return
	}
	expiresAt := service.TokenExpiry(req.ExpiresInDays)
	// minting a token creates a credential, so it needs a fresh step up. The input
	// was checked above so a typo does not spend the grant.
	op := middleware.OperatorFromContext(c)
	if !a.requireStepUp(c, op, "Token.Create") {
		return
	}
	// attribute the token to the operator who created it, so it is revoked when
	// that operator is deleted.
	clear, tok, err := a.tokens.Create(req.Name, req.Namespaces, req.AllowedCIDRs, expiresAt, op.ID, op.Username)
	if err != nil {
		a.auditFailed(c, "Token.Create", "could not create", map[string]any{"name": req.Name})
		replyRefused(c, "Token.Create", "could not create the token", err)
		return
	}
	// the clear token is returned exactly once. id + prefix let callers manage it.
	a.logAudit(c, "Token.Create", true, map[string]any{"name": req.Name})
	c.JSON(http.StatusOK, gin.H{"token": clear, "id": tok.ID, "prefix": tok.Prefix})
}

func (a *AdminAPI) TokenRevoke(c *gin.Context) {
	if err := a.tokens.Revoke(c.Param("id")); err != nil {
		if errors.Is(err, service.ErrNotFound) {
			a.logAudit(c, "Token.Revoke", false, map[string]any{"id": c.Param("id"), "reason": "not found"})
			c.JSON(http.StatusNotFound, gin.H{"error": "token not found"})
			return
		}
		a.auditFailed(c, "Token.Revoke", "could not revoke", map[string]any{"id": c.Param("id")})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "revoke"})
		return
	}
	a.logAudit(c, "Token.Revoke", true, map[string]any{"id": c.Param("id")})
	c.JSON(http.StatusOK, gin.H{"status": "revoked"})
}

// TokenUpdate edits only the source IP allowlist; an empty list clears it.
// Widening where a credential works needs a fresh step up. The token must exist
// before the grant is spent.
func (a *AdminAPI) TokenUpdate(c *gin.Context) {
	var req struct {
		AllowedCIDRs []string `json:"allowedCidrs"`
	}
	id := c.Param("id")
	ref := map[string]any{"id": id}
	if err := c.ShouldBindJSON(&req); err != nil {
		a.auditFailed(c, "Token.Update", "invalid request", ref)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if err := model.ValidateAllowedCIDRs(req.AllowedCIDRs); err != nil {
		a.auditFailed(c, "Token.Update", "invalid allowlist", ref)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	exists, err := a.tokens.Exists(id)
	if err != nil {
		a.auditFailed(c, "Token.Update", "could not look up token", ref)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update"})
		return
	}
	if !exists {
		a.auditFailed(c, "Token.Update", "not found", ref)
		c.JSON(http.StatusNotFound, gin.H{"error": "token not found"})
		return
	}
	if !a.requireStepUp(c, middleware.OperatorFromContext(c), "Token.Update") {
		return
	}
	if err := a.tokens.SetAllowedCIDRs(id, req.AllowedCIDRs); err != nil {
		if errors.Is(err, service.ErrNotFound) {
			a.auditFailed(c, "Token.Update", "not found", ref)
			c.JSON(http.StatusNotFound, gin.H{"error": "token not found"})
			return
		}
		a.auditFailed(c, "Token.Update", "could not update", ref)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update"})
		return
	}
	a.logAudit(c, "Token.Update", true, ref)
	c.JSON(http.StatusOK, gin.H{"status": "updated"})
}

func (a *AdminAPI) TokenDelete(c *gin.Context) {
	if err := a.tokens.Delete(c.Param("id")); err != nil {
		if errors.Is(err, service.ErrNotFound) {
			a.logAudit(c, "Token.Delete", false, map[string]any{"id": c.Param("id"), "reason": "not found"})
			c.JSON(http.StatusNotFound, gin.H{"error": "token not found"})
			return
		}
		a.auditFailed(c, "Token.Delete", "could not delete", map[string]any{"id": c.Param("id")})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete"})
		return
	}
	a.logAudit(c, "Token.Delete", true, map[string]any{"id": c.Param("id")})
	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}

func normalizeVisibility(v string) string {
	if v == database.VisibilityPublic {
		return database.VisibilityPublic
	}
	return database.VisibilityPrivate
}
