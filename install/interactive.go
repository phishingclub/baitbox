package install

import (
	"fmt"
	"net"
	"net/mail"
	"regexp"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/phishingclub/baitbox/config"
	"github.com/phishingclub/baitbox/utils"
)

var (
	titleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#0B3D91")).
			Bold(true).
			Padding(1, 2)
	focusedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#1E88E5")).
			Bold(true)
	blurredStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#5C8DD6"))
	cursorStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF9E43"))
	helpStyle    = lipgloss.NewStyle().Italic(true).Foreground(lipgloss.Color("#90A4AE"))
	errorStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#F44336")).Bold(true)
	buttonStyle  = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#43A047")).
			Bold(true).
			Padding(0, 3)
	sectionStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#6A1B9A")).
			Bold(true).
			Padding(0, 1)
	modeStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#FF5722")).
			Bold(true).
			Padding(0, 1)
)

// field keys, used to read the answers back.
const (
	fDomain         = "domain"
	fListen         = "registry_port"
	fAdminListen    = "admin_port"
	fAutoTLS        = "auto_tls"
	fACMEEmail      = "acme_email"
	fAdminHost      = "admin_host"
	fAdminAllowIPs  = "admin_allowed"
	fTrustedProxies = "trusted_proxies"
	fForwardHeader  = "trusted_ip_header"
)

// sameAsDomain is shown as the admin host default when it follows the domain.
const sameAsDomain = "same as domain"

// field is one question. An empty answer keeps def; shown replaces def in the
// prompt when set.
type field struct {
	key         string
	label       string
	def         string
	shown       string
	placeholder string
	help        string
	section     string
	advanced    bool
}

// questions returns every question with defaults taken from base, so a
// reinstall offers the current values.
func questions(base *config.Config) []field {
	autoTLS := strconv.FormatBool(base.TLSAuto)
	domain := base.Registry.TLSHost
	adminHost := base.Administration.TLSHost
	if adminHost == domain {
		adminHost = ""
	}
	return []field{
		{
			key: fDomain, label: "Domain", def: domain,
			placeholder: "registry.example.com",
			help: "domain name only, no https:// and no port. Phishing Club installs reach the " +
				"registry on it, and the admin UI uses it too unless Admin host (F2) is set",
			section: "Server",
		},
		{
			key: fListen, label: "Registry port", def: listenShown(base.Registry.Address),
			placeholder: "443",
			help: "port of the registry API that Phishing Club installs connect to. " +
				"Let's Encrypt validates on port 443, so with auto TLS keep 443 unless 443 is forwarded here",
			section: "Server",
		},
		{
			key: fAdminListen, label: "Admin port", def: listenShown(base.Administration.Address),
			placeholder: "8443",
			help: "port of the admin UI and API, must differ from the registry port. Firewall it or " +
				"set Admin allowed IPs (F2). host:port such as 127.0.0.1:8443 binds one address only",
			section: "Server",
		},
		{
			key: fAutoTLS, label: "Use auto TLS", def: autoTLS,
			placeholder: "true/false",
			help: "true gets certificates from Let's Encrypt. false uses a self signed certificate, " +
				"for running behind a TLS terminating front such as Cloudflare",
			section: "Server",
		},
		{
			key: fACMEEmail, label: "ACME email", def: base.ACME.Email,
			placeholder: "you@example.com",
			help:        "email for Let's Encrypt notices, needed when auto TLS is true",
			section:     "Server",
		},
		{
			key: fAdminHost, label: "Admin host", def: adminHost, shown: sameAsDomain,
			placeholder: "admin.example.com",
			help: "separate domain name for the admin UI, no https:// and no port. Passkeys are " +
				"bound to it, so changing it later breaks them. Type none to use the domain",
			section: "Server", advanced: true,
		},
		{
			key: fAdminAllowIPs, label: "Admin allowed IPs",
			def:         strings.Join(base.IPSecurity.AdminAllowed, ","),
			placeholder: "203.0.113.4,10.0.0.0/8",
			help:        "comma separated IPs or CIDR ranges allowed to use the admin; empty allows all",
			section:     "Security", advanced: true,
		},
		{
			key: fTrustedProxies, label: "Trusted proxies",
			def:         strings.Join(base.IPSecurity.TrustedProxies, ","),
			placeholder: "173.245.48.0/20",
			help:        "comma separated IPs or CIDR ranges of the front that forwards requests",
			section:     "Security", advanced: true,
		},
		{
			key: fForwardHeader, label: "Trusted IP header", def: base.IPSecurity.TrustedIPHeader,
			placeholder: "CF-Connecting-IP",
			help:        "header carrying the real client IP, read only from trusted proxies",
			section:     "Security", advanced: true,
		},
	}
}

// listenShown turns a listen address into the answer form: the port alone when
// it binds every address, host:port otherwise.
func listenShown(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		if err != nil {
			return addr
		}
		return port
	}
	return addr
}

// parseListen accepts a port or host:port and returns a listen address.
func parseListen(name, s string) (string, error) {
	addr := s
	if !strings.Contains(s, ":") {
		addr = ":" + s
	}
	_, port, err := net.SplitHostPort(addr)
	n, perr := strconv.Atoi(port)
	if err != nil || perr != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("%s %q must be a port from 1 to 65535, or host:port", name, s)
	}
	return addr, nil
}

// parseBool accepts true/false and yes/no.
func parseBool(name, s string) (bool, error) {
	switch strings.ToLower(s) {
	case "true", "yes", "y":
		return true, nil
	case "false", "no", "n":
		return false, nil
	}
	return false, fmt.Errorf("%s must be true or false", name)
}

var hostnameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// BuildConfig applies answers (key to value, empty meaning keep the default)
// to a copy of base and checks the result.
func BuildConfig(base *config.Config, answers map[string]string) (*config.Config, error) {
	cfg := *base
	val := func(k string) string {
		for _, q := range questions(base) {
			if q.key == k {
				v := strings.TrimSpace(answers[k])
				if strings.EqualFold(v, "none") {
					return ""
				}
				if v != "" {
					return v
				}
				return q.def
			}
		}
		return ""
	}

	domain := strings.ToLower(val(fDomain))
	if !hostnameRe.MatchString(domain) {
		return nil, fmt.Errorf("domain %q must be a domain name only, without https:// or a port", domain)
	}
	adminHost := strings.ToLower(val(fAdminHost))
	if adminHost == "" {
		adminHost = domain
	}
	if !hostnameRe.MatchString(adminHost) {
		return nil, fmt.Errorf("admin host %q must be a domain name only, without https:// or a port", adminHost)
	}
	cfg.Registry.TLSHost = domain
	cfg.Administration.TLSHost = adminHost

	autoTLS, err := parseBool("use auto TLS", val(fAutoTLS))
	if err != nil {
		return nil, err
	}
	cfg.TLSAuto = autoTLS
	if autoTLS {
		email := val(fACMEEmail)
		if _, err := mail.ParseAddress(email); err != nil || strings.HasPrefix(email, "REPLACE_") {
			return nil, fmt.Errorf("auto TLS needs a valid ACME email")
		}
		cfg.ACME.Email = email
	} else {
		cfg.ACME.Email = val(fACMEEmail)
	}

	if cfg.Registry.Address, err = parseListen("registry port", val(fListen)); err != nil {
		return nil, err
	}
	if cfg.Administration.Address, err = parseListen("admin port", val(fAdminListen)); err != nil {
		return nil, err
	}

	ips := &cfg.IPSecurity
	if ips.AdminAllowed, err = parseIPList("admin allowed IPs", val(fAdminAllowIPs)); err != nil {
		return nil, err
	}
	if ips.TrustedProxies, err = parseIPList("trusted proxies", val(fTrustedProxies)); err != nil {
		return nil, err
	}
	ips.TrustedIPHeader = val(fForwardHeader)
	if ips.TrustedIPHeader != "" && len(ips.TrustedProxies) == 0 {
		return nil, fmt.Errorf("a forwarded IP header needs trusted proxies, or any client could set its own IP")
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// parseIPList splits a comma separated list and requires each entry to be an
// IP or a CIDR range.
func parseIPList(name, s string) ([]string, error) {
	out := utils.SplitTrim(s, ",")
	for _, e := range out {
		if net.ParseIP(e) == nil {
			if _, _, err := net.ParseCIDR(e); err != nil {
				return nil, fmt.Errorf("%s: %q is not an IP or CIDR range", name, e)
			}
		}
	}
	return out, nil
}

// configModel is the interactive form. Inputs exist for every question; basic
// mode shows only the basic ones, and values survive switching modes.
type configModel struct {
	title     string
	base      *config.Config
	fields    []field
	inputs    []textinput.Model
	advanced  bool
	focus     int // position within visible(), len(visible()) is the button
	err       error
	result    *config.Config
	confirmed bool
}

func newConfigModel(title string, base *config.Config) configModel {
	m := configModel{title: title, base: base, fields: questions(base)}
	for _, f := range m.fields {
		t := textinput.New()
		t.Cursor.Style = cursorStyle
		t.CharLimit = 512
		t.Placeholder = f.placeholder
		def := f.def
		if def == "" {
			def = f.shown
		}
		if def == "" {
			def = "none"
		}
		t.Prompt = fmt.Sprintf("%s [%s]: ", f.label, def)
		m.inputs = append(m.inputs, t)
	}
	m.applyFocus()
	return m
}

// visible returns the input indexes shown in the current mode.
func (m configModel) visible() []int {
	var out []int
	for i, f := range m.fields {
		if m.advanced || !f.advanced {
			out = append(out, i)
		}
	}
	return out
}

func (m *configModel) applyFocus() {
	vis := m.visible()
	for i := range m.inputs {
		m.inputs[i].Blur()
		m.inputs[i].PromptStyle = blurredStyle
		m.inputs[i].TextStyle = blurredStyle
	}
	if m.focus < len(vis) {
		i := vis[m.focus]
		m.inputs[i].Focus()
		m.inputs[i].PromptStyle = focusedStyle
		m.inputs[i].TextStyle = focusedStyle
	}
}

func (m configModel) Init() tea.Cmd { return textinput.Blink }

func (m configModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "ctrl+c", "esc":
			return m, tea.Quit
		case "f1", "f2":
			m.advanced = key.String() == "f2"
			m.focus = 0
			m.applyFocus()
			return m, nil
		case "tab", "shift+tab", "enter", "up", "down":
			vis := m.visible()
			if key.String() == "enter" && m.focus == len(vis) {
				answers := map[string]string{}
				for i, f := range m.fields {
					answers[f.key] = m.inputs[i].Value()
				}
				cfg, err := BuildConfig(m.base, answers)
				if err != nil {
					m.err = err
					return m, nil
				}
				m.result = cfg
				m.confirmed = true
				return m, tea.Quit
			}
			if key.String() == "up" || key.String() == "shift+tab" {
				m.focus--
			} else {
				m.focus++
			}
			if m.focus > len(vis) {
				m.focus = 0
			} else if m.focus < 0 {
				m.focus = len(vis)
			}
			m.applyFocus()
			return m, nil
		}
	}
	cmds := make([]tea.Cmd, len(m.inputs))
	for i := range m.inputs {
		m.inputs[i], cmds[i] = m.inputs[i].Update(msg)
	}
	return m, tea.Batch(cmds...)
}

func (m configModel) View() string {
	var b strings.Builder
	b.WriteString("\n" + titleStyle.Render(" "+m.title+" ") + "\n\n")
	if m.err != nil {
		b.WriteString(errorStyle.Render("Error: "+m.err.Error()) + "\n\n")
	}
	mode := "Basic"
	if m.advanced {
		mode = "Advanced"
	}
	keys := helpStyle.Render("(F1: Basic | F2: Advanced, Enter on Install to finish, Esc to cancel)")
	b.WriteString("Mode: " + modeStyle.Render(mode) + "  " + keys + "\n")
	b.WriteString(helpStyle.Render(
		"Leave a field empty to keep the value in brackets, or type none to clear it.",
	) + "\n")

	section := ""
	for pos, i := range m.visible() {
		f := m.fields[i]
		if f.section != section {
			section = f.section
			b.WriteString("\n" + sectionStyle.Render(" "+section+" ") + "\n")
		}
		b.WriteString(m.inputs[i].View() + "\n")
		if pos == m.focus {
			b.WriteString("  " + helpStyle.Render(f.help) + "\n")
		}
	}
	button := blurredStyle
	if m.focus == len(m.visible()) {
		button = buttonStyle
	}
	b.WriteString("\n" + button.Render(" Install ") + "\n")
	return b.String()
}

// AskConfig runs the interactive form with defaults from base. It returns the
// checked config, or ok=false when the operator cancelled.
func AskConfig(title string, base *config.Config) (*config.Config, bool, error) {
	// read keys from the terminal even when stdin is the piped install script.
	return askConfig(title, base, tea.WithInputTTY())
}

func askConfig(title string, base *config.Config, opts ...tea.ProgramOption) (*config.Config, bool, error) {
	p := tea.NewProgram(newConfigModel(title, base), opts...)
	final, err := p.Run()
	if err != nil {
		return nil, false, fmt.Errorf("interactive installer: %w", err)
	}
	m := final.(configModel)
	if !m.confirmed {
		return nil, false, nil
	}
	return m.result, true, nil
}

// DefaultConfig returns the production config a fresh install starts from.
func DefaultConfig() *config.Config {
	return &config.Config{
		Env:            "prod",
		TLSAuto:        true,
		Administration: config.Administration{Address: ":8443"},
		Registry: config.Registry{
			Address:     ":443",
			MaxDownload: config.DefaultMaxDownload,
			MaxFile:     config.DefaultMaxFile,
			MaxUnpacked: config.DefaultMaxUnpacked,
			MaxFiles:    config.DefaultMaxFiles,
		},
		Database:   config.Database{Path: installDir + "/" + dataDir + "/baitbox.sqlite3"},
		Blobs:      config.Blobs{Path: installDir + "/" + dataDir + "/blobs"},
		IPSecurity: config.IPSecurity{AdminAllowed: []string{}, TrustedProxies: []string{}},
	}
}
