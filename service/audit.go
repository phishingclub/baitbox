package service

import (
	"context"
	"io"
	"log/slog"
	"log/syslog"
	"os"
	"strings"
	"time"
)

// AuditService writes one JSON line per sensitive operation to stderr, so the
// events end up in the journal. The line follows the Phishing Club audit line
// (level, ts, msg "audit", name, ip, userId, details) with the operator username
// and success in place of authorized, since a failed login or code is not a
// permission check.
type AuditService struct {
	log *slog.Logger
}

// NewAuditService returns an AuditService that writes to stderr.
func NewAuditService() *AuditService {
	return NewAuditServiceTo(os.Stderr)
}

// NewCLIAuditService returns an AuditService for the command line resets. They
// run outside the service, so stderr is only the terminal; the line is also sent
// to syslog under the service's identifier, so `journalctl -t baitbox` shows it.
func NewCLIAuditService() *AuditService {
	if sl, err := syslog.New(syslog.LOG_AUTH|syslog.LOG_NOTICE, "baitbox"); err == nil {
		return NewAuditServiceTo(io.MultiWriter(os.Stderr, sl))
	}
	return NewAuditService()
}

// NewAuditServiceTo returns an AuditService that writes to w.
func NewAuditServiceTo(w io.Writer) *AuditService {
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{ReplaceAttr: zapStyle})
	return &AuditService{log: slog.New(h)}
}

// zapStyle renames the time and level keys to match a zap production line: ts
// as unix seconds and a lower case level.
func zapStyle(groups []string, a slog.Attr) slog.Attr {
	if len(groups) > 0 {
		return a
	}
	switch a.Key {
	case slog.TimeKey:
		t := a.Value.Time()
		return slog.Float64("ts", float64(t.UnixNano())/float64(time.Second))
	case slog.LevelKey:
		return slog.String(slog.LevelKey, strings.ToLower(a.Value.String()))
	}
	return a
}

// Record logs one audit event. The actor is empty for an unauthenticated action
// such as a failed login; details never carry secrets.
func (s *AuditService) Record(action, operatorID, username, ip string, success bool, details map[string]any) {
	s.log.LogAttrs(context.Background(), slog.LevelInfo, "audit",
		slog.String("name", action),
		slog.String("ip", ip),
		slog.String("userId", operatorID),
		slog.String("username", username),
		slog.Bool("success", success),
		slog.Any("details", details),
	)
}
