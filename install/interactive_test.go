package install

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/phishingclub/baitbox/config"
)

func basicAnswers() map[string]string {
	return map[string]string{
		fDomain:    "Registry.Example.com",
		fACMEEmail: "ops@example.com",
	}
}

func TestBuildConfigBasic(t *testing.T) {
	cfg, err := BuildConfig(DefaultConfig(), basicAnswers())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if cfg.Registry.TLSHost != "registry.example.com" || cfg.Administration.TLSHost != "registry.example.com" {
		t.Fatalf("hosts: %q %q", cfg.Registry.TLSHost, cfg.Administration.TLSHost)
	}
	if cfg.Registry.Address != ":443" || cfg.Administration.Address != ":8443" || !cfg.TLSAuto || cfg.Env != "prod" {
		t.Fatalf("defaults not kept: %+v", cfg)
	}
	if cfg.RegistryURL() != "https://registry.example.com" || cfg.AdminURL() != "https://registry.example.com:8443" {
		t.Fatalf("urls: %q %q", cfg.RegistryURL(), cfg.AdminURL())
	}
	if len(cfg.HostList()) != 1 {
		t.Fatalf("host list: %v", cfg.HostList())
	}
}

func TestBuildConfigPortsAndTLS(t *testing.T) {
	a := basicAnswers()
	a[fListen] = "2053"
	a[fAdminListen] = "127.0.0.1:2096"
	a[fAutoTLS] = "no"
	a[fACMEEmail] = "none"
	a[fAdminHost] = "Admin.Example.com"
	cfg, err := BuildConfig(DefaultConfig(), a)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if cfg.Registry.Address != ":2053" || cfg.Administration.Address != "127.0.0.1:2096" || cfg.TLSAuto || cfg.Administration.TLSHost != "admin.example.com" {
		t.Fatalf("answers not applied: %+v", cfg)
	}
	// the prompt shows a port alone, or host:port when bound to one address
	q := questions(cfg)
	shown := map[string]string{}
	for _, f := range q {
		shown[f.key] = f.def
	}
	if shown[fListen] != "2053" || shown[fAdminListen] != "127.0.0.1:2096" || shown[fAutoTLS] != "false" || shown[fAdminHost] != "admin.example.com" {
		t.Fatalf("reinstall defaults: %v", shown)
	}
}

func TestBuildConfigRejects(t *testing.T) {
	cases := map[string]map[string]string{
		"domain with scheme":     {fDomain: "https://reg.example.com"},
		"domain with port":       {fDomain: "reg.example.com:443"},
		"admin host with port":   {fAdminHost: "admin.example.com:8443"},
		"placeholder host":       {fAdminHost: "REPLACE_WITH_ADMIN_HOST"},
		"auto tls without mail":  {fACMEEmail: "none"},
		"bad auto tls":           {fAutoTLS: "letsencrypt"},
		"same ports":             {fAdminListen: "443"},
		"bad port":               {fListen: "99999"},
		"word port":              {fListen: "https"},
		"bad allow list":         {fAdminAllowIPs: "10.0.0.0/8,not-an-ip"},
		"header without proxies": {fForwardHeader: "CF-Connecting-IP"},
	}
	for name, change := range cases {
		a := basicAnswers()
		for k, v := range change {
			a[k] = v
		}
		if _, err := BuildConfig(DefaultConfig(), a); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestBuildConfigReinstallDefaultsAndClear(t *testing.T) {
	first := basicAnswers()
	first[fAutoTLS] = "false"
	first[fAdminAllowIPs] = "203.0.113.4, 10.0.0.0/8"
	first[fTrustedProxies] = "173.245.48.0/20"
	first[fForwardHeader] = "CF-Connecting-IP"
	installed, err := BuildConfig(DefaultConfig(), first)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	if installed.TLSAuto || strings.Join(installed.IPSecurity.AdminAllowed, ",") != "203.0.113.4,10.0.0.0/8" {
		t.Fatalf("first config: %+v", installed)
	}

	// empty answers keep every installed value
	again, err := BuildConfig(installed, map[string]string{})
	if err != nil {
		t.Fatalf("reinstall with defaults: %v", err)
	}
	if again.Registry.TLSHost != "registry.example.com" || again.TLSAuto || again.IPSecurity.TrustedIPHeader != "CF-Connecting-IP" || len(again.IPSecurity.AdminAllowed) != 2 {
		t.Fatalf("defaults lost on reinstall: %+v", again)
	}

	// none clears optional values
	cleared, err := BuildConfig(installed, map[string]string{fAdminAllowIPs: "none", fForwardHeader: "none", fTrustedProxies: "none"})
	if err != nil {
		t.Fatalf("clear: %v", err)
	}
	if len(cleared.IPSecurity.AdminAllowed) != 0 || cleared.IPSecurity.TrustedIPHeader != "" || len(cleared.IPSecurity.TrustedProxies) != 0 {
		t.Fatalf("none did not clear: %+v", cleared)
	}
}

func TestConfigModelKeepsValuesAcrossModes(t *testing.T) {
	m := newConfigModel("t", DefaultConfig())
	m.inputs[0].SetValue("reg.example.com")
	m.advanced = true
	m.applyFocus()
	m.advanced = false
	m.applyFocus()
	if m.inputs[0].Value() != "reg.example.com" {
		t.Fatal("switching modes lost a typed value")
	}
	if got := len(m.visible()); got != 5 {
		t.Fatalf("basic mode shows %d questions, want 5", got)
	}
}

// keys feeds key presses to the form one at a time, the way a terminal does.
type keys struct{ parts []string }

func (k *keys) Read(p []byte) (int, error) {
	if len(k.parts) == 0 {
		time.Sleep(50 * time.Millisecond)
		return 0, io.EOF
	}
	time.Sleep(20 * time.Millisecond)
	n := copy(p, k.parts[0])
	k.parts = k.parts[1:]
	return n, nil
}

func TestAskConfigDrivenByKeys(t *testing.T) {
	in := &keys{parts: []string{"reg.example.com", "\t", "\t", "\t", "\t", "ops@example.com", "\t", "\r"}}
	cfg, ok, err := askConfig("t", DefaultConfig(), tea.WithInput(in), tea.WithOutput(io.Discard))
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if cfg.Registry.TLSHost != "reg.example.com" || cfg.Administration.TLSHost != "reg.example.com" || cfg.ACME.Email != "ops@example.com" {
		t.Fatalf("answers not applied: %+v", cfg)
	}

	// an invalid answer keeps the form open with an error; esc then cancels
	in = &keys{parts: []string{"https://bad", "\t", "\t", "\t", "\t", "\t", "\r", "\x1b"}}
	_, ok, err = askConfig("t", DefaultConfig(), tea.WithInput(in), tea.WithOutput(io.Discard))
	if err != nil || ok {
		t.Fatalf("invalid then cancel: ok=%v err=%v", ok, err)
	}
}

// The non interactive template must ship the same archive caps as the
// interactive installer.
func TestConfigTemplateMatchesDefaultCaps(t *testing.T) {
	raw, err := installFiles.ReadFile("config.template.json")
	if err != nil {
		t.Fatal(err)
	}
	var tmpl config.Config
	if err := json.Unmarshal(raw, &tmpl); err != nil {
		t.Fatal(err)
	}
	want := DefaultConfig().Registry
	got := tmpl.Registry
	if got.MaxDownload != want.MaxDownload || got.MaxFile != want.MaxFile ||
		got.MaxUnpacked != want.MaxUnpacked || got.MaxFiles != want.MaxFiles {
		t.Fatalf("template caps %d/%d/%d/%d, defaults %d/%d/%d/%d",
			got.MaxDownload, got.MaxFile, got.MaxUnpacked, got.MaxFiles,
			want.MaxDownload, want.MaxFile, want.MaxUnpacked, want.MaxFiles)
	}
}
