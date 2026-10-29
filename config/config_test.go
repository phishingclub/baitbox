package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestValidateRejectsSharedPort(t *testing.T) {
	cases := []struct {
		listen, admin string
		ok            bool
	}{
		{":443", "127.0.0.1:8443", true},
		{":443", ":8443", true},
		{":443", ":443", false},
		{":443", "127.0.0.1:443", false},
		{":443", "nope", false},
	}
	for _, tc := range cases {
		c := &Config{Env: "prod", Registry: Registry{Address: tc.listen}, Administration: Administration{Address: tc.admin}}
		if err := c.validate(); (err == nil) != tc.ok {
			t.Errorf("listen %q admin %q: got err %v, want ok %v", tc.listen, tc.admin, err, tc.ok)
		}
	}
}

func TestAdminAddressDefaultsToLoopback(t *testing.T) {
	c := &Config{}
	c.applyDefaults()
	if c.Administration.Address != "127.0.0.1:8443" {
		t.Fatalf("administration.address default %q", c.Administration.Address)
	}
}

func TestAdminOrigins(t *testing.T) {
	c := &Config{Administration: Administration{TLSHost: "admin.example.com", Address: ":8443"}}
	want := []string{"https://admin.example.com", "https://admin.example.com:8443"}
	if got := c.AdminOrigins(); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	c.Administration.Address = ":443"
	if got := c.AdminOrigins(); !reflect.DeepEqual(got, want[:1]) {
		t.Fatalf("got %v want %v", got, want[:1])
	}
}

func TestRegistryURL(t *testing.T) {
	cases := []struct {
		name string
		c    Config
		want string
	}{
		{
			"default port",
			Config{Registry: Registry{Address: ":443", TLSHost: "reg.example.com"}},
			"https://reg.example.com",
		},
		{
			"other port",
			Config{Registry: Registry{Address: ":8112", TLSHost: "registry.baitbox.test"}},
			"https://registry.baitbox.test:8112",
		},
		{"unset", Config{Registry: Registry{Address: ":443"}}, ""},
	}
	for _, tc := range cases {
		if got := tc.c.RegistryURL(); got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}

func TestSetAdminDisabledKeepsValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	orig := `{"env":"prod","tls_auto":true,"acme":{"email":"ops@example.com"},"administration":{"address":":8443","tls_host":"a.example.com"},"registry":{"address":":443","tls_host":"r.example.com"},"ip_security":{"admin_allowed":["10.0.0.0/8"]}}`
	if err := os.WriteFile(path, []byte(orig), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := SetAdminDisabled(path, true); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Administration.Disabled || c.Administration.TLSHost != "a.example.com" || !c.TLSAuto || c.ACME.Email != "ops@example.com" || c.IPSecurity.AdminAllowed[0] != "10.0.0.0/8" {
		t.Fatalf("values changed: %+v", c)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode changed to %v", info.Mode().Perm())
	}
	if err := SetAdminDisabled(path, false); err != nil {
		t.Fatal(err)
	}
	if c, _ = Load(path); c.Administration.Disabled {
		t.Fatal("enable did not clear the key")
	}
	if err := SetAdminDisabled(filepath.Join(t.TempDir(), "missing.json"), true); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestValidateEnvFailsClosed(t *testing.T) {
	for _, env := range []string{"dev", "prod"} {
		c := &Config{Env: env, Registry: Registry{Address: ":443"}, Administration: Administration{Address: ":8443"}}
		if err := c.validate(); err != nil {
			t.Errorf("env %q rejected: %v", env, err)
		}
	}
	for _, env := range []string{"", "Prod", "production", "development", " dev"} {
		c := &Config{Env: env, Registry: Registry{Address: ":443"}, Administration: Administration{Address: ":8443"}}
		if c.validate() == nil {
			t.Errorf("env %q accepted", env)
		}
	}
}

func TestArchiveLimitDefaults(t *testing.T) {
	c := &Config{}
	c.applyDefaults()
	r := c.Registry
	if r.MaxDownload != 16<<20 || r.MaxFile != 16<<20 || r.MaxUnpacked != 32<<20 || r.MaxFiles != 2000 {
		t.Fatalf("defaults = %+v", r)
	}
	// explicit values are kept, and a single file cap larger than the default
	// total raises the unset total so one file of that size still fits.
	c = &Config{Registry: Registry{MaxDownload: 64 << 20, MaxFile: 128 << 20}}
	c.applyDefaults()
	r = c.Registry
	if r.MaxDownload != 64<<20 || r.MaxFile != 128<<20 || r.MaxUnpacked != 128<<20 || r.MaxFiles != 2000 {
		t.Fatalf("explicit values = %+v", r)
	}
	c = &Config{Registry: Registry{MaxUnpacked: 8 << 20, MaxFiles: 50}}
	c.applyDefaults()
	if c.Registry.MaxUnpacked != 8<<20 || c.Registry.MaxFiles != 50 {
		t.Fatalf("explicit totals = %+v", c.Registry)
	}
}

func TestValidateRejectsBadAdminAllowed(t *testing.T) {
	base := func(allowed []string) *Config {
		return &Config{
			Env:            "prod",
			Registry:       Registry{Address: ":443"},
			Administration: Administration{Address: "127.0.0.1:8443"},
			IPSecurity:     IPSecurity{AdminAllowed: allowed},
		}
	}
	for _, ok := range [][]string{nil, {}, {"10.0.0.1"}, {"10.0.0.0/8", "2001:db8::/32", "::1"}} {
		if err := base(ok).Validate(); err != nil {
			t.Errorf("%v: unexpected error %v", ok, err)
		}
	}
	for _, bad := range [][]string{{"10.0.0.300"}, {"10.0.0.1", "office"}, {" 10.0.0.1"}, {"10.0.0.0/33"}, {""}} {
		err := base(bad).Validate()
		if err == nil {
			t.Errorf("%v: accepted", bad)
			continue
		}
		if !strings.Contains(err.Error(), "admin_allowed") {
			t.Errorf("%v: error does not name the setting: %v", bad, err)
		}
	}
}

func TestLoadRejectsBadAdminAllowed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	body := `{"env":"prod","ip_security":{"admin_allowed":["10.0.0.1","not-an-ip"]}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), `"not-an-ip"`) {
		t.Fatalf("Load error %v, want one naming the entry", err)
	}
}

func TestValidateRejectsDatabasePathOptions(t *testing.T) {
	cases := []struct {
		path string
		ok   bool
	}{
		{"/var/lib/baitbox/baitbox.sqlite3", true},
		{"data/baitbox.sqlite3", true},
		{"/data/db?_foreign_keys=off", false},
		{"/data/db&_journal_mode=DELETE", false},
		{"/data/db#x", false},
	}
	for _, tc := range cases {
		c := &Config{
			Env:            "prod",
			Registry:       Registry{Address: ":443"},
			Administration: Administration{Address: "127.0.0.1:8443"},
			Database:       Database{Path: tc.path},
		}
		err := c.validate()
		if (err == nil) != tc.ok {
			t.Errorf("path %q: got err %v, want ok %v", tc.path, err, tc.ok)
		}
		if err != nil && !strings.Contains(err.Error(), "database.path") {
			t.Errorf("path %q: error %q does not name database.path", tc.path, err)
		}
	}
}
