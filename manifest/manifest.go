// Package manifest defines the Bait Box archive manifest (baitbox.json) and
// its validation. A package archive is a tar.gz holding this manifest, a
// content/ payload and an assets/ tree. The manifest declares identity,
// dependencies, substitution variables and per file hashes; a content hash
// binds the payload.
package manifest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/mod/semver"
)

// Format is the manifest format identifier.
const Format = "baitbox/v1"

// FileName is the manifest file name inside an archive.
const FileName = "baitbox.json"

// MaxDependencies is the most packages one manifest may reference. Phishing Club
// refuses a bundle with more (registry maxDependencies and service
// maxBundleDependencies), so the two values must stay equal.
const MaxDependencies = 100

// Package types.
const (
	TypeEmail          = "email"
	TypePage           = "page"
	TypeAsset          = "asset"
	TypeAttachment     = "attachment"
	TypeScript         = "script"
	TypeProxy          = "proxy"
	TypeAllowDeny      = "allowdeny"
	TypeRemoteBrowser  = "remotebrowser"
	TypeReportTemplate = "reporttemplate"
	TypeDomain         = "domain"
	TypeSMTP           = "smtp"
	TypeWebhook        = "webhook"
	TypeAPISender      = "apisender"
	TypeOAuthProvider  = "oauthprovider"
	TypeTemplate       = "template"
	TypeBundle         = "bundle"
)

var validTypes = map[string]bool{
	TypeEmail: true, TypePage: true, TypeAsset: true, TypeAttachment: true,
	TypeScript: true, TypeProxy: true, TypeAllowDeny: true,
	TypeRemoteBrowser: true, TypeReportTemplate: true, TypeDomain: true,
	TypeSMTP: true, TypeWebhook: true, TypeAPISender: true, TypeOAuthProvider: true,
	TypeTemplate: true, TypeBundle: true,
}

// Variable types.
const (
	VarDomain = "domain"
	VarURL    = "url"
	VarSecret = "secret"
	VarText   = "text"
	VarEnum   = "enum"
)

var validVarTypes = map[string]bool{
	VarDomain: true, VarURL: true, VarSecret: true, VarText: true, VarEnum: true,
}

// PickAllowDeny is the pick kind for one of the installer's own allow or deny
// lists, which an asset's allowDeny list then names as its only list.
const PickAllowDeny = "allowDeny"

// validPickKinds are the entity kinds Phishing Club can list for a pick variable.
var validPickKinds = map[string]bool{
	"smtpConfiguration": true, "domain": true, "email": true, "page": true,
	"proxy": true, "apiSender": true, "oauthProvider": true,
	PickAllowDeny: true,
}

// Dependency is a required package and the semver range that satisfies it.
type Dependency struct {
	ID    string `json:"id"`
	Range string `json:"range"`
}

// Variable is a declared substitution point. A required secret variable is how
// a credential stays out of shipped content.
type Variable struct {
	Name        string  `json:"name"`
	Description string  `json:"description,omitempty"`
	Type        string  `json:"type"`
	Required    bool    `json:"required"`
	Default     *string `json:"default,omitempty"`
	// Options is the allowed value set for an enum variable, in author order. The
	// installer picks one. It is empty for every other type.
	Options []string `json:"options,omitempty"`
	// Pick, when set, names an entity kind the installer must choose from their own
	// existing entities at install (smtpConfiguration, domain, email, page, proxy,
	// apiSender, oauthProvider, allowDeny). The chosen entity name becomes the value,
	// which a campaign template slot, an api sender reference or an asset allowDeny
	// entry then resolves by name. Empty for an ordinary value variable.
	Pick string `json:"pick,omitempty"`
}

// Entry is one payload file and the hex sha256 of its bytes.
type Entry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Manifest is the parsed baitbox.json.
type Manifest struct {
	Format  string `json:"format"`
	ID      string `json:"id"`
	Type    string `json:"type"`
	Version string `json:"version"`
	// Title is the human display name shown in listings. It is free text and may
	// differ from the id slug. Metadata only, not part of the content hash, so it
	// can be corrected without republishing content.
	Title         string   `json:"title,omitempty"`
	MinAppVersion string   `json:"minAppVersion,omitempty"`
	Description   string   `json:"description,omitempty"`
	Tags          []string `json:"tags,omitempty"`
	// Preview is an optional bundled image under assets/ that represents the
	// package, shown as a thumbnail in the registry. It is metadata only and is
	// not part of the content hash.
	Preview      string       `json:"preview,omitempty"`
	Dependencies []Dependency `json:"dependencies,omitempty"`
	// ShareVariables applies to a bundle: when true (the default when absent) a
	// variable of the same name across the referenced packages is filled once and
	// shared; when false each referenced package collects its own value. Any
	// other package may not set it.
	ShareVariables *bool      `json:"shareVariables,omitempty"`
	Variables      []Variable `json:"variables,omitempty"`
	ContentHash    string     `json:"contentHash"`
	Entries        []Entry    `json:"entries"`
}

var (
	idRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}/[a-z0-9][a-z0-9._-]{0,127}$`)
	versionRe = regexp.MustCompile(`^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)
	nameRe    = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)
	nsRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
)

// ValidID reports whether id ("namespace/name") matches the published format.
func ValidID(id string) bool { return idRe.MatchString(id) }

// ValidVersion reports whether v is a valid semver string. The regex fixes the
// accepted shape (no leading v, no build metadata) and semver.IsValid applies
// the full semver rules, such as no leading zeros in numeric parts.
func ValidVersion(v string) bool {
	return versionRe.MatchString(v) && semver.IsValid("v"+v)
}

// ValidType reports whether t is a known package type.
func ValidType(t string) bool { return validTypes[t] }

// ValidEntryPath reports whether p is a canonical payload path: valid UTF-8,
// already clean, relative, and under content/ or assets/. A segment may not be
// empty, "." or "..", nor start or end with a space. A backslash, a control or
// format character (such as a bidi override or a zero width space) or a line or
// paragraph separator is refused too, since an extractor on another system may
// read a backslash as a separator and such characters hide what a name really
// is.
func ValidEntryPath(p string) bool {
	if p == "" || !utf8.ValidString(p) || path.Clean(p) != p || strings.HasPrefix(p, "/") || strings.Contains(p, "..") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
		first, _ := utf8.DecodeRuneInString(seg)
		last, _ := utf8.DecodeLastRuneInString(seg)
		if unicode.IsSpace(first) || unicode.IsSpace(last) {
			return false
		}
	}
	for _, r := range p {
		if r == '\\' || unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) {
			return false
		}
	}
	return strings.HasPrefix(p, "content/") || strings.HasPrefix(p, "assets/")
}

// FoldPath is the key two paths share when they differ only by letter case, so
// an archive cannot hold both and clash on a file system that ignores case.
func FoldPath(p string) string { return strings.ToLower(strings.ToUpper(p)) }

// ValidNamespace reports whether ns is a valid namespace slug.
func ValidNamespace(ns string) bool { return nsRe.MatchString(ns) }

// Parse unmarshals a manifest from JSON bytes. An unknown key is refused.
func Parse(b []byte) (*Manifest, error) {
	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	return &m, nil
}

// Namespace returns the namespace part of the id.
func (m *Manifest) Namespace() string {
	if i := strings.IndexByte(m.ID, '/'); i >= 0 {
		return m.ID[:i]
	}
	return ""
}

// PackageName returns the name part of the id.
func (m *Manifest) PackageName() string {
	if i := strings.IndexByte(m.ID, '/'); i >= 0 {
		return m.ID[i+1:]
	}
	return ""
}

// Validate checks the manifest is well formed.
func (m *Manifest) Validate() error {
	if m.Format != Format {
		return fmt.Errorf("unsupported format %q", m.Format)
	}
	if !idRe.MatchString(m.ID) {
		return fmt.Errorf("invalid id %q, want namespace/name", m.ID)
	}
	if !validTypes[m.Type] {
		return fmt.Errorf("invalid type %q", m.Type)
	}
	if !ValidVersion(m.Version) {
		return fmt.Errorf("invalid version %q, want semver", m.Version)
	}
	if len(m.Dependencies) > MaxDependencies {
		return fmt.Errorf("package references %d packages, the limit is %d", len(m.Dependencies), MaxDependencies)
	}
	seenDep := map[string]bool{}
	for _, d := range m.Dependencies {
		if !idRe.MatchString(d.ID) {
			return fmt.Errorf("invalid dependency id %q", d.ID)
		}
		if strings.TrimSpace(d.Range) == "" {
			return fmt.Errorf("dependency %q missing range", d.ID)
		}
		if d.ID == m.ID {
			return fmt.Errorf("dependency %q cannot be the package itself", d.ID)
		}
		if seenDep[d.ID] {
			return fmt.Errorf("duplicate dependency %q", d.ID)
		}
		seenDep[d.ID] = true
	}
	// a bundle references other packages and ties them together with a campaign
	// template; it carries no content of its own, so it needs at least one
	// dependency to be meaningful. visibility and no nesting rules need a registry
	// lookup and are enforced at publish, not here.
	if m.Type == TypeBundle && len(m.Dependencies) == 0 {
		return fmt.Errorf("a bundle must reference at least one package")
	}
	// only a bundle installs packages that could share variable names with it,
	// so the setting means nothing on any other package and is refused there.
	if m.Type != TypeBundle && m.ShareVariables != nil {
		return fmt.Errorf("shareVariables applies only to a bundle")
	}
	seenVar := map[string]bool{}
	for _, v := range m.Variables {
		if !nameRe.MatchString(v.Name) {
			return fmt.Errorf("invalid variable name %q", v.Name)
		}
		if seenVar[v.Name] {
			return fmt.Errorf("duplicate variable %q", v.Name)
		}
		seenVar[v.Name] = true
		if !validVarTypes[v.Type] {
			return fmt.Errorf("invalid variable type %q for %q", v.Type, v.Name)
		}
		// a secret value is supplied at install and never shipped, so it is always
		// required and carries no default.
		if v.Type == VarSecret {
			if v.Default != nil {
				return fmt.Errorf("secret variable %q cannot have a default", v.Name)
			}
			if !v.Required {
				return fmt.Errorf("secret variable %q must be required", v.Name)
			}
		}
		if v.Required && v.Default != nil {
			return fmt.Errorf("variable %q is required and cannot have a default", v.Name)
		}
		// a pick value must be the installer's own choice, so it has no default.
		if v.Pick != "" {
			if !validPickKinds[v.Pick] {
				return fmt.Errorf("variable %q picks the unknown kind %q", v.Name, v.Pick)
			}
			if v.Default != nil {
				return fmt.Errorf("pick variable %q cannot have a default", v.Name)
			}
			// a filtered asset must never install without its list, so a list
			// pick is always filled at install.
			if v.Pick == PickAllowDeny && !v.Required {
				return fmt.Errorf("list pick variable %q must be required", v.Name)
			}
		}
		if v.Type == VarEnum {
			if len(v.Options) == 0 {
				return fmt.Errorf("enum variable %q must list at least one option", v.Name)
			}
			seenOpt := map[string]bool{}
			for _, o := range v.Options {
				if o == "" {
					return fmt.Errorf("enum variable %q has an empty option", v.Name)
				}
				if seenOpt[o] {
					return fmt.Errorf("enum variable %q has a duplicate option %q", v.Name, o)
				}
				seenOpt[o] = true
			}
			if v.Default != nil && !seenOpt[*v.Default] {
				return fmt.Errorf("enum variable %q default %q is not one of its options", v.Name, *v.Default)
			}
		} else if len(v.Options) > 0 {
			return fmt.Errorf("variable %q has options but is not an enum", v.Name)
		}
	}
	if len(m.Entries) == 0 {
		return fmt.Errorf("manifest has no entries")
	}
	seenEntry := map[string]bool{}
	for _, e := range m.Entries {
		if !ValidEntryPath(e.Path) || len(e.SHA256) != 64 {
			return fmt.Errorf("invalid entry %q", e.Path)
		}
		if seenEntry[FoldPath(e.Path)] {
			return fmt.Errorf("duplicate entry %q (paths may not differ only by case)", e.Path)
		}
		seenEntry[FoldPath(e.Path)] = true
	}
	if m.Preview != "" {
		if !strings.HasPrefix(m.Preview, "assets/") {
			return fmt.Errorf("preview %q must be a bundled file under assets/", m.Preview)
		}
		if PreviewMediaType(m.Preview) == "" {
			return fmt.Errorf("preview %q must be a png, jpeg, gif or webp image", m.Preview)
		}
		found := false
		for _, e := range m.Entries {
			if e.Path == m.Preview {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("preview %q is not a bundled file", m.Preview)
		}
	}
	if m.ContentHash != ComputeContentHash(m.Entries) {
		return fmt.Errorf("content hash does not match entries")
	}
	return nil
}

// previewTypes maps the file extensions a preview image may have to the raster
// media type its bytes must sniff as.
var previewTypes = map[string]string{
	".png":  "image/png",
	".jpg":  "image/jpeg",
	".jpeg": "image/jpeg",
	".gif":  "image/gif",
	".webp": "image/webp",
}

// PreviewMediaType returns the raster media type a preview path's extension
// names, or empty when the extension is not an allowed image type.
func PreviewMediaType(p string) string {
	return previewTypes[strings.ToLower(path.Ext(p))]
}

// ComputeContentHash returns a deterministic hash binding the payload: the
// entries sorted by path, each written as "path:sha256\n", hashed with sha256.
func ComputeContentHash(entries []Entry) string {
	sorted := make([]Entry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	h := sha256.New()
	for _, e := range sorted {
		h.Write([]byte(e.Path))
		h.Write([]byte{':'})
		h.Write([]byte(e.SHA256))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}
