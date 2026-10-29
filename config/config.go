// Package config loads and exposes Bait Box runtime settings from a JSON file.
// It mirrors the plain file load used by the sibling projects: read the file,
// unmarshal, and expose typed getters. Validation of proxy settings happens in
// the client IP resolver at startup, not here.
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// ACME holds the Let's Encrypt account settings.
type ACME struct {
	Email string `json:"email"`
}

// Administration is the listener for the operator admin UI and admin API. It
// is separate from the registry listener so it can be restricted on its own;
// the usual control is IPSecurity.AdminAllowed, which keeps passkeys and TLS
// working for allowed clients. Its port must differ from the registry port. An
// empty address defaults to loopback (see applyDefaults) for the SSH tunnel
// model, but then the browser must open the admin by tls_host so the passkey
// origin and TLS cert still match, which is why the shipped config binds a port.
type Administration struct {
	Address string `json:"address"`
	// TLSHost is the admin host name. Passkeys are bound to it.
	TLSHost string `json:"tls_host"`
	// Disabled turns the admin listener off; only the registry is served. It is
	// set from the admin UI or the -disable-admin flag, and only a change to the
	// config file (or -enable-admin) turns the admin back on.
	Disabled bool `json:"disabled"`
}

// Registry is the registry listener that Phishing Club installs reach.
type Registry struct {
	Address string `json:"address"`
	TLSHost string `json:"tls_host"`
	// MaxDownload caps one compressed package archive upload, MaxFile one file
	// inside it, MaxUnpacked the sum of every unpacked file, and MaxFiles the file
	// count. They bound package archives only; a whole registry import or export
	// bundle has its own larger caps.
	MaxDownload int64 `json:"max_download"`
	MaxFile     int64 `json:"max_file"`
	MaxUnpacked int64 `json:"max_unpacked,omitempty"`
	MaxFiles    int   `json:"max_files,omitempty"`
	// Public lets callers without a token read public namespaces. When false
	// every registry request needs a valid token.
	Public bool `json:"public"`
}

// Default package archive caps, used when the config leaves a key unset.
const (
	DefaultMaxDownload = 16 << 20
	DefaultMaxFile     = 16 << 20
	DefaultMaxUnpacked = 32 << 20
	DefaultMaxFiles    = 2000
)

// Database is the SQLite database file.
type Database struct {
	Path string `json:"path"`
}

// Blobs is the directory package content is stored in.
type Blobs struct {
	Path string `json:"path"`
}

// IPSecurity holds the admin allowlist and the reverse proxy settings used to
// resolve the real client IP when Bait Box runs behind Cloudflare or another
// front.
type IPSecurity struct {
	// AdminAllowed restricts the admin UI to these client IPs or CIDR ranges.
	// Empty allows all. The registry listener is never restricted.
	AdminAllowed    []string `json:"admin_allowed"`
	TrustedProxies  []string `json:"trusted_proxies"`
	TrustedIPHeader string   `json:"trusted_ip_header"`
}

// Config is the full runtime configuration. Keys shared with Phishing Club
// use the same names.
type Config struct {
	Env string `json:"env"`
	// TLSAuto gets certificates from Let's Encrypt for both listeners. When
	// false a self signed certificate is served, for running behind a front
	// that terminates the public certificate.
	TLSAuto        bool           `json:"tls_auto"`
	ACME           ACME           `json:"acme"`
	Administration Administration `json:"administration"`
	Registry       Registry       `json:"registry"`
	Database       Database       `json:"database"`
	Blobs          Blobs          `json:"blobs"`
	IPSecurity     IPSecurity     `json:"ip_security"`
}

// Load reads and parses the config file at path.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return &c, nil
}

// Validate runs the same checks Load does, for a config built in code (the
// interactive installer) instead of read from a file.
func (c *Config) Validate() error {
	return c.validate()
}

// WriteFile saves the config as indented JSON readable only by its owner.
func (c *Config) WriteFile(path string) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// SetAdminDisabled sets administration.disabled in the config file at path and
// leaves every other value as written. The file keeps its mode and owner, so
// root can run it on a file the service user owns.
func SetAdminDisabled(path string, disabled bool) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return fmt.Errorf("parse config %s: %w", path, err)
	}
	c.Administration.Disabled = disabled
	out, err := json.MarshalIndent(&c, "", "  ")
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.json")
	if err != nil {
		return fmt.Errorf("write config %s: %w", path, err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(out, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), info.Mode().Perm()); err != nil {
		return err
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && os.Geteuid() == 0 {
		if err := os.Chown(tmp.Name(), int(st.Uid), int(st.Gid)); err != nil {
			return err
		}
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		// a config bind mounted as a single file cannot be replaced, so write
		// it in place instead.
		if werr := os.WriteFile(path, append(out, '\n'), info.Mode().Perm()); werr != nil {
			return fmt.Errorf("write config %s: %w", path, werr)
		}
	}
	return nil
}

// AdminURL returns the address of the admin UI: the admin host on the admin
// listener port, without the port when it is 443.
func (c *Config) AdminURL() string {
	if c.Administration.TLSHost == "" {
		return ""
	}
	return httpsURL(c.Administration.TLSHost, c.Administration.Address)
}

// httpsURL joins host with the port of addr, leaving out port 443.
func httpsURL(host, addr string) string {
	if _, port, err := net.SplitHostPort(addr); err == nil && port != "" && port != "443" {
		return "https://" + net.JoinHostPort(host, port)
	}
	return "https://" + host
}

// validate rejects a config whose env is not exactly "dev" or "prod", so a typo
// never runs with dev behaviour, and one where the admin and registry listeners
// would share one port, since that puts the admin surface on the registry listener,
// one whose admin allowlist holds an entry that is not an IP or CIDR range, and
// one whose database path would change the SQLite connection options.
func (c *Config) validate() error {
	if c.Env != "dev" && c.Env != "prod" {
		return fmt.Errorf("env %q must be \"dev\" or \"prod\"", c.Env)
	}
	// the path is followed by connection options in the SQLite DSN, so these
	// characters would add or change options.
	if strings.ContainsAny(c.Database.Path, "?&#") {
		return fmt.Errorf("database.path %q must not contain '?', '&' or '#'", c.Database.Path)
	}
	_, pubPort, err := net.SplitHostPort(c.Registry.Address)
	if err != nil {
		return fmt.Errorf("registry.address %q: %w", c.Registry.Address, err)
	}
	_, adminPort, err := net.SplitHostPort(c.Administration.Address)
	if err != nil {
		return fmt.Errorf("administration.address %q: %w", c.Administration.Address, err)
	}
	if pubPort == adminPort {
		return fmt.Errorf(
			"administration.address %q must use a different port than registry.address %q",
			c.Administration.Address, c.Registry.Address,
		)
	}
	// an entry the allowlist cannot parse would be skipped at runtime, so the admin
	// UI would not be limited the way the operator wrote it.
	for _, e := range c.IPSecurity.AdminAllowed {
		if _, _, err := net.ParseCIDR(e); err == nil {
			continue
		}
		if net.ParseIP(e) == nil {
			return fmt.Errorf("ip_security.admin_allowed entry %q is not an IP address or CIDR range", e)
		}
	}
	return nil
}

func (c *Config) applyDefaults() {
	if c.Registry.Address == "" {
		c.Registry.Address = ":443"
	}
	if c.Administration.Address == "" {
		// loopback by default so a config without the key never exposes the admin
		// surface; reach it over an SSH tunnel or set an explicit address.
		c.Administration.Address = "127.0.0.1:8443"
	}
	if c.Registry.MaxDownload <= 0 {
		c.Registry.MaxDownload = DefaultMaxDownload
	}
	if c.Registry.MaxFile <= 0 {
		c.Registry.MaxFile = DefaultMaxFile
	}
	if c.Registry.MaxUnpacked <= 0 {
		c.Registry.MaxUnpacked = DefaultMaxUnpacked
		// a config that sets a larger single file cap keeps it usable: the total
		// must hold at least one file of that size.
		if c.Registry.MaxFile > c.Registry.MaxUnpacked {
			c.Registry.MaxUnpacked = c.Registry.MaxFile
		}
	}
	if c.Registry.MaxFiles <= 0 {
		c.Registry.MaxFiles = DefaultMaxFiles
	}
}

// IsProd reports whether this is a production environment.
func (c *Config) IsProd() bool { return c.Env == "prod" }

// HostList returns every configured hostname, used to drive cert issuance.
func (c *Config) HostList() []string {
	seen := map[string]bool{}
	out := []string{}
	for _, h := range []string{c.Registry.TLSHost, c.Administration.TLSHost} {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}

// AdminOrigins returns the browser origins the admin UI is served from: the
// admin host on the default HTTPS port (behind a front) and on the admin
// listener port when that is not 443.
func (c *Config) AdminOrigins() []string {
	out := []string{"https://" + c.Administration.TLSHost}
	if u := httpsURL(c.Administration.TLSHost, c.Administration.Address); u != out[0] {
		out = append(out, u)
	}
	return out
}

// RegistryURL returns the address Phishing Club installs use to reach the
// registry listener: registry.tls_host on the registry port. It is empty when no
// host is configured.
func (c *Config) RegistryURL() string {
	host := strings.TrimSpace(c.Registry.TLSHost)
	if host == "" {
		return ""
	}
	return httpsURL(host, c.Registry.Address)
}
