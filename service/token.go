package service

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"strings"
	"time"

	"github.com/phishingclub/baitbox/crypto"
	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/repository"
)

// ErrInvalidToken is returned when a bearer token is missing, unknown, revoked
// or expired.
var ErrInvalidToken = errors.New("invalid token")

// TokenService issues and verifies bearer tokens and checks entitlements. Only
// the sha256 of a token is stored; the clear value is shown once at creation.
type TokenService struct {
	repo *repository.TokenRepository
}

// NewTokenService returns a TokenService.
func NewTokenService(repo *repository.TokenRepository) *TokenService {
	return &TokenService{repo: repo}
}

// maxTokenDays caps a token lifetime so a typo cannot create an absurd one.
const maxTokenDays = 3650

// TokenExpiry returns the expiry for a token that lasts days from now, capped
// at maxTokenDays. Zero or less means no expiry and returns nil.
func TokenExpiry(days int) *time.Time {
	if days <= 0 {
		return nil
	}
	if days > maxTokenDays {
		days = maxTokenDays
	}
	t := time.Now().AddDate(0, 0, days)
	return &t
}

// Create issues a read token. entitlements lists the namespaces it may read; a
// single "*" entry means all. Every named namespace must exist, see CheckScopes.
// operatorID and createdBy record the operator who minted the token, so it is
// attributable and can be revoked when that operator is removed. The clear token
// is returned once.
func (s *TokenService) Create(
	name string,
	entitlements, allowedCIDRs []string,
	expiresAt *time.Time,
	operatorID, createdBy string,
) (string, *database.Token, error) {
	clear, hash := crypto.NewBearerToken()
	entJSON, _ := json.Marshal(entitlements)
	cidrJSON, _ := json.Marshal(allowedCIDRs)
	t := database.Token{
		TokenHash:    hash,
		Prefix:       crypto.TokenPrefix(clear),
		Name:         name,
		Entitlements: string(entJSON),
		AllowedCIDRs: string(cidrJSON),
		ExpiresAt:    expiresAt,
		OperatorID:   operatorID,
		CreatedBy:    createdBy,
	}
	missing, err := s.repo.CreateScoped(&t, entitlements)
	if err != nil {
		return "", nil, err
	}
	if len(missing) > 0 {
		return "", nil, unknownNamespaces(missing)
	}
	return clear, &t, nil
}

// CheckScopes refuses entitlements that name a namespace that does not exist,
// with a ValidationError naming them. A token scoped to a missing name would read
// nothing now, and would read a namespace created later under that name.
func (s *TokenService) CheckScopes(entitlements []string) error {
	missing, err := s.repo.MissingNamespaces(entitlements)
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		return unknownNamespaces(missing)
	}
	return nil
}

// unknownNamespaces is the refusal for token scopes that name missing
// namespaces. The names already passed the namespace slug rules.
func unknownNamespaces(names []string) error {
	return invalidf("no namespace named %s exists; a token can only be scoped to existing namespaces",
		strings.Join(names, ", "))
}

// Authenticate resolves a bearer token to its record, rejecting revoked or
// expired tokens and tokens used from a source IP outside their allowed CIDRs,
// and stamps last used. clientIP is the real client IP resolved by the server.
func (s *TokenService) Authenticate(bearer, clientIP string) (*database.Token, error) {
	bearer = crypto.ParseBearer(bearer)
	if bearer == "" {
		return nil, ErrInvalidToken
	}
	hash := crypto.HashToken(bearer)
	t, err := s.repo.FindByHash(hash)
	if err != nil {
		return nil, err
	}
	if t == nil {
		return nil, ErrInvalidToken
	}
	if t.Revoked {
		return nil, ErrInvalidToken
	}
	if t.ExpiresAt != nil && time.Now().After(*t.ExpiresAt) {
		return nil, ErrInvalidToken
	}
	if !ipAllowed(t.AllowedCIDRs, clientIP) {
		return nil, ErrInvalidToken
	}
	if err := s.repo.UpdateLastUsed(t.ID, time.Now()); err != nil {
		log.Printf("token last used: %v", err)
	}
	return t, nil
}

// SetAllowedCIDRs replaces a token's source IP allowlist. An empty slice clears
// the restriction so the token is usable from any IP. It returns ErrNotFound
// when no token has the id.
func (s *TokenService) SetAllowedCIDRs(id string, allowedCIDRs []string) error {
	cidrJSON, _ := json.Marshal(allowedCIDRs)
	n, err := s.repo.SetAllowedCIDRs(id, string(cidrJSON))
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// Exists reports whether a token with the id exists.
func (s *TokenService) Exists(id string) (bool, error) {
	return s.repo.Exists(id)
}

// Revoke marks a token revoked. It returns ErrNotFound when no token has the id.
func (s *TokenService) Revoke(id string) error {
	n, err := s.repo.Revoke(id)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete removes a token permanently. It returns ErrNotFound when no token has
// the id.
func (s *TokenService) Delete(id string) error {
	n, err := s.repo.Delete(id)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// List returns all tokens for the admin UI (hashes are never exposed by the
// json tag on the model).
func (s *TokenService) List() ([]database.Token, error) {
	return s.repo.List()
}

// CanRead reports whether a token may read a namespace, using the namespaces it
// is entitled to (a single "*" grants all). Tokens are read only.
func (s *TokenService) CanRead(t *database.Token, namespace string) bool {
	if t == nil {
		return false
	}
	return listAllows(t.Entitlements, namespace)
}

// ipAllowed reports whether clientIP is permitted by a json list of CIDRs or bare
// IPs. An empty or absent list means the token is not IP restricted. When a list
// is present it fails closed: an unparseable client IP is rejected.
func ipAllowed(jsonCIDRs, clientIP string) bool {
	if strings.TrimSpace(jsonCIDRs) == "" {
		return true
	}
	var items []string
	if err := json.Unmarshal([]byte(jsonCIDRs), &items); err != nil {
		return false
	}
	if len(items) == 0 {
		return true
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}
	for _, c := range items {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if _, network, err := net.ParseCIDR(c); err == nil {
			if network.Contains(ip) {
				return true
			}
			continue
		}
		if host := net.ParseIP(c); host != nil && host.Equal(ip) {
			return true
		}
	}
	return false
}

// listAllows reports whether a JSON string list contains namespace or the
// wildcard "*".
func listAllows(jsonList, namespace string) bool {
	var items []string
	if err := json.Unmarshal([]byte(jsonList), &items); err != nil {
		return false
	}
	for _, it := range items {
		if it == "*" || it == namespace {
			return true
		}
	}
	return false
}
