package model

import (
	"errors"
	"strings"
	"testing"
)

func TestPackageValidate(t *testing.T) {
	tests := []struct {
		name    string
		pkg     Package
		wantErr error
	}{
		{
			"valid",
			Package{Namespace: "acme", Name: "thing", Type: "page", Version: "1.0.0", Title: "T", Description: "D"},
			nil,
		},
		{
			"missing version",
			Package{Namespace: "acme", Name: "thing", Type: "page"},
			ErrPackageFieldsRequired,
		},
		{
			"missing type",
			Package{Namespace: "acme", Name: "thing", Version: "1.0.0"},
			ErrPackageFieldsRequired,
		},
		{
			"title too long",
			Package{Namespace: "acme", Name: "thing", Type: "page", Version: "1.0.0", Title: strings.Repeat("x", 256)},
			ErrTitleTooLong,
		},
		{
			"description too long",
			Package{Namespace: "acme", Name: "thing", Type: "page", Version: "1.0.0", Description: strings.Repeat("y", 4001)},
			ErrDescriptionTooLong,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.pkg.Validate()
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidatePackageMetaBoundaries(t *testing.T) {
	// exactly at the cap is allowed; one rune over is rejected.
	if err := ValidatePackageMeta(strings.Repeat("x", MaxTitleRunes), ""); err != nil {
		t.Fatalf("title at cap rejected: %v", err)
	}
	if err := ValidatePackageMeta(strings.Repeat("x", MaxTitleRunes+1), ""); !errors.Is(err, ErrTitleTooLong) {
		t.Fatalf("title over cap: %v", err)
	}
	if err := ValidatePackageMeta("", strings.Repeat("y", MaxDescriptionRunes)); err != nil {
		t.Fatalf("description at cap rejected: %v", err)
	}
	if err := ValidatePackageMeta("", strings.Repeat("y", MaxDescriptionRunes+1)); !errors.Is(err, ErrDescriptionTooLong) {
		t.Fatalf("description over cap: %v", err)
	}
	// rune counting, not bytes: a multi-byte char at the cap stays valid.
	if err := ValidatePackageMeta(strings.Repeat("é", MaxTitleRunes), ""); err != nil {
		t.Fatalf("multibyte title at cap rejected: %v", err)
	}
}

func TestNamespaceValidate(t *testing.T) {
	valid := []string{"acme", "acme-corp", "a", "x9", "a----b"}
	for _, n := range valid {
		if err := (Namespace{Name: n}).Validate(); err != nil {
			t.Fatalf("namespace %q should be valid: %v", n, err)
		}
	}
	invalid := []string{"", "Acme", "-acme", "acme_corp", "acme/corp", "acme corp", strings.Repeat("a", 65)}
	for _, n := range invalid {
		if err := (Namespace{Name: n}).Validate(); !errors.Is(err, ErrInvalidNamespaceName) {
			t.Fatalf("namespace %q should be invalid, got %v", n, err)
		}
	}
}

func TestCleanTags(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{"trim and lowercase", []string{"  O365 ", "Login"}, []string{"o365", "login"}},
		{"drop empties", []string{"", "   ", "ok"}, []string{"ok"}},
		{"dedupe case insensitive", []string{"tag", "TAG", "tag"}, []string{"tag"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := CleanTags(tc.in)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}

	// each tag is capped at maxTagLen (32) bytes.
	long := strings.Repeat("a", 40)
	got := CleanTags([]string{long})
	if len(got) != 1 || len(got[0]) != 32 {
		t.Fatalf("tag length not capped: %d", len(got[0]))
	}

	// at most maxTags (20) distinct tags are kept.
	many := make([]string, 0, 30)
	for i := 0; i < 30; i++ {
		many = append(many, string(rune('a'+i%26))+string(rune('0'+i/26)))
	}
	if n := len(CleanTags(many)); n != 20 {
		t.Fatalf("tag count not capped: %d, want 20", n)
	}
}

func TestTokenValidate(t *testing.T) {
	// entitlements: wildcard and valid slugs pass; a bad slug fails.
	if err := (Token{Entitlements: []string{"*"}}).Validate(); err != nil {
		t.Fatalf("wildcard entitlement rejected: %v", err)
	}
	if err := (Token{Entitlements: []string{"acme", "acme-corp"}}).Validate(); err != nil {
		t.Fatalf("valid entitlements rejected: %v", err)
	}
	if err := (Token{Entitlements: []string{"BadNS"}}).Validate(); !errors.Is(err, ErrInvalidEntitlement) {
		t.Fatalf("bad entitlement: %v", err)
	}

	// allowed CIDRs: CIDR and bare IP pass; garbage fails.
	if err := (Token{AllowedCIDRs: []string{"10.0.0.0/8", "192.168.1.1", "::1"}}).Validate(); err != nil {
		t.Fatalf("valid cidrs rejected: %v", err)
	}
	if err := (Token{AllowedCIDRs: []string{"not-an-ip"}}).Validate(); !errors.Is(err, ErrInvalidAllowedCIDR) {
		t.Fatalf("bad cidr: %v", err)
	}
}

func TestValidCIDR(t *testing.T) {
	valid := []string{"10.0.0.0/8", "192.168.0.0/16", "1.2.3.4", "::1", "2001:db8::/32", "  10.0.0.1  "}
	for _, s := range valid {
		if !ValidCIDR(s) {
			t.Fatalf("%q should be a valid CIDR or IP", s)
		}
	}
	invalid := []string{"", "garbage", "10.0.0.0/33", "999.1.1.1", "10.0.0.1/"}
	for _, s := range invalid {
		if ValidCIDR(s) {
			t.Fatalf("%q should be invalid", s)
		}
	}
}

func TestNamespaceDescriptionCap(t *testing.T) {
	if err := (Namespace{Name: "acme", Description: strings.Repeat("d", MaxNamespaceDescriptionRunes)}).Validate(); err != nil {
		t.Fatalf("description at cap rejected: %v", err)
	}
	if err := (Namespace{Name: "acme", Description: strings.Repeat("d", MaxNamespaceDescriptionRunes+1)}).Validate(); !errors.Is(err, ErrNamespaceDescriptionTooLong) {
		t.Fatalf("description over cap: %v", err)
	}
	if err := ValidateNamespaceDescription(strings.Repeat("é", MaxNamespaceDescriptionRunes)); err != nil {
		t.Fatalf("multibyte description at cap rejected: %v", err)
	}
}
