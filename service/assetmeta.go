package service

import (
	"fmt"
	"mime"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/manifest"
	"golang.org/x/net/http/httpguts"
	"gopkg.in/yaml.v3"
)

// Limits on the per asset settings in a data.yaml assets block. They match the
// Phishing Club asset model, which refuses longer values on install.
const (
	maxAssetNameLen        = 127
	maxAssetDescriptionLen = 255
	maxAssetContentTypeLen = 255
	maxAssetHeaderKeyLen   = 127
	maxAssetHeaderValueLen = 2048
	maxAssetHeaders        = 50
	maxAssetListNameLen    = 127
)

// blockedAssetHeaders are response headers an asset cannot set, since they
// control how the response itself is sent. Content-Type is set with the content
// type field instead. The keys are in canonical form and match Phishing Club.
var blockedAssetHeaders = map[string]bool{
	"Content-Length":    true,
	"Transfer-Encoding": true,
	"Connection":        true,
	"Keep-Alive":        true,
	"Upgrade":           true,
	"Te":                true,
	"Trailer":           true,
	"Proxy-Connection":  true,
	"Content-Type":      true,
}

// assetHeaderYAML is one response header in an assets block entry.
type assetHeaderYAML struct {
	Key   string `yaml:"key" json:"key"`
	Value string `yaml:"value" json:"value"`
}

// assetYAML is one entry of a data.yaml assets block: the settings Phishing Club
// applies to the file shipped at assets/<Path> when it installs it.
type assetYAML struct {
	Path        string            `yaml:"path"`
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	ContentType string            `yaml:"contentType"`
	Headers     []assetHeaderYAML `yaml:"headers"`
	AllowDeny   []string          `yaml:"allowDeny"`
}

// yamlBool is the allowed value of an allow deny list, read the way Phishing
// Club reads it: decoded into a Go bool by the same YAML decoder, so true,
// True, yes, on and the other spellings it takes mean the same here. A value
// it cannot decode is refused, since Phishing Club could not install it.
type yamlBool bool

func (b *yamlBool) UnmarshalYAML(node *yaml.Node) error {
	var v bool
	if err := node.Decode(&v); err != nil {
		return fmt.Errorf("allowed must be true or false, not %q", node.Value)
	}
	*b = yamlBool(v)
	return nil
}

// assetDocYAML is the part of a data.yaml the asset checks read: the assets
// block and the name and kind of each allow deny list the folder declares.
type assetDocYAML struct {
	Assets      []assetYAML `yaml:"assets"`
	AllowDenies []struct {
		Name    string   `yaml:"name"`
		Allowed yamlBool `yaml:"allowed"`
	} `yaml:"allowDenies"`
}

// isDataYAML reports whether an archive path is a content folder data.yaml.
func isDataYAML(p string) bool {
	return strings.HasPrefix(p, "content/") && strings.HasSuffix(p, "/data.yaml")
}

// ValidateAssetContentType checks a custom content type: empty, or a media type
// with a type and a subtype and no control characters.
func ValidateAssetContentType(ct string) error {
	if ct == "" {
		return nil
	}
	if len(ct) > maxAssetContentTypeLen {
		return fmt.Errorf("content type is longer than %d characters", maxAssetContentTypeLen)
	}
	if !httpguts.ValidHeaderFieldValue(ct) {
		return fmt.Errorf("content type contains invalid characters")
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return fmt.Errorf("invalid content type %q: %v", ct, err)
	}
	if major, minor, ok := strings.Cut(mt, "/"); !ok || major == "" || minor == "" {
		return fmt.Errorf("content type %q must be a type and subtype, such as text/html", ct)
	}
	return nil
}

// ValidateAssetHeader checks one response header an asset sends. The name must
// be a valid HTTP header name that is not blocked; the value is required and
// may not hold CR, LF, NUL or another control character except tab. Both are
// trimmed first, as Phishing Club does, and lengths count bytes.
func ValidateAssetHeader(key, value string) error {
	key = strings.TrimSpace(key)
	value = strings.TrimSpace(value)
	if key == "" {
		return fmt.Errorf("a header needs a name")
	}
	if len(key) > maxAssetHeaderKeyLen {
		return fmt.Errorf("header name %q is longer than %d characters", key, maxAssetHeaderKeyLen)
	}
	if !httpguts.ValidHeaderFieldName(key) {
		return fmt.Errorf("invalid header name %q", key)
	}
	if blockedAssetHeaders[http.CanonicalHeaderKey(key)] {
		if strings.EqualFold(key, "Content-Type") {
			return fmt.Errorf("use contentType to set Content-Type, not a header")
		}
		return fmt.Errorf("the %s header cannot be set on an asset", http.CanonicalHeaderKey(key))
	}
	if value == "" {
		return fmt.Errorf("header %q needs a value", key)
	}
	if len(value) > maxAssetHeaderValueLen {
		return fmt.Errorf("header %q value is longer than %d characters", key, maxAssetHeaderValueLen)
	}
	if strings.ContainsAny(value, "\r\n\x00") || !httpguts.ValidHeaderFieldValue(value) {
		return fmt.Errorf("header %q value contains invalid characters", key)
	}
	return nil
}

// validateAssetEntry checks the settings of one assets block entry, but not
// whether its file exists or is listed twice, which needs the whole package.
// Values are trimmed and lengths count bytes, as Phishing Club does.
func validateAssetEntry(a assetYAML) error {
	if len(strings.TrimSpace(a.Name)) > maxAssetNameLen {
		return fmt.Errorf("name is longer than %d bytes", maxAssetNameLen)
	}
	if len(strings.TrimSpace(a.Description)) > maxAssetDescriptionLen {
		return fmt.Errorf("description is longer than %d bytes", maxAssetDescriptionLen)
	}
	if err := ValidateAssetContentType(strings.TrimSpace(a.ContentType)); err != nil {
		return err
	}
	if len(a.Headers) > maxAssetHeaders {
		return fmt.Errorf("an asset can have at most %d response headers", maxAssetHeaders)
	}
	for _, h := range a.Headers {
		if err := ValidateAssetHeader(h.Key, h.Value); err != nil {
			return err
		}
	}
	seen := map[string]bool{}
	for _, raw := range a.AllowDeny {
		n := strings.TrimSpace(raw)
		if n == "" {
			return fmt.Errorf("allowDeny has an empty list name")
		}
		if len(n) > maxAssetListNameLen {
			return fmt.Errorf("allowDeny list name %q is longer than %d bytes", n, maxAssetListNameLen)
		}
		if seen[n] {
			return fmt.Errorf("allowDeny names the list %q twice", n)
		}
		seen[n] = true
	}
	if len(a.AllowDeny) > 0 {
		for _, h := range a.Headers {
			if http.CanonicalHeaderKey(strings.TrimSpace(h.Key)) != "Cache-Control" {
				continue
			}
			if err := ValidateFilteredCacheControl(strings.TrimSpace(h.Value)); err != nil {
				return err
			}
		}
	}
	return nil
}

// ValidateFilteredCacheControl checks a Cache-Control value on an asset with
// allow deny lists. Phishing Club sends such an asset with "private, no-store"
// unless it sets its own Cache-Control, so the value must keep the response
// out of shared caches: it must hold no-store or private and must not hold
// public or s-maxage. It matches the Phishing Club check.
func ValidateFilteredCacheControl(value string) error {
	keeps, opens := false, false
	for _, part := range strings.Split(value, ",") {
		name, _, _ := strings.Cut(part, "=")
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "no-store", "private":
			keeps = true
		case "public", "s-maxage":
			opens = true
		}
	}
	if !keeps || opens {
		return fmt.Errorf("an asset with allow/deny lists can only set a Cache-Control header that holds " +
			"no-store or private and does not hold public or s-maxage")
	}
	return nil
}

// validateAssetBlocks checks the assets block of every data.yaml in docs, keyed
// by archive path, for a package of type pkgType. assetFiles holds every file
// path under assets/ the package ships, without the assets/ prefix. Each entry
// must name a shipped file, a file may be described once across the package,
// and its settings must be ones Phishing Club accepts. Only an allowdeny package
// may declare allow deny lists; any other package uses the lists of the allowdeny
// packages it depends on, which checkAssetListRefs resolves against the
// registry. A data.yaml that is not valid YAML is refused, since its assets could
// not be checked.
func validateAssetBlocks(pkgType string, docs map[string][]byte, assetFiles map[string]bool) error {
	paths := make([]string, 0, len(docs))
	for p := range docs {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	parsed := make(map[string]*assetDocYAML, len(paths))
	for _, p := range paths {
		var dy assetDocYAML
		if err := yaml.Unmarshal(docs[p], &dy); err != nil {
			return fmt.Errorf("%s: the assets or allowDenies block is not valid: %v", p, err)
		}
		if len(dy.AllowDenies) > 0 && pkgType != manifest.TypeAllowDeny {
			return fmt.Errorf("%s: only an allow / deny package can declare allow / deny lists; "+
				"publish the list as its own allow / deny package in this namespace and pick it on the asset", p)
		}
		parsed[p] = &dy
	}
	described := map[string]string{}
	for _, p := range paths {
		for i, a := range parsed[p].Assets {
			if a.Path == "" {
				return fmt.Errorf("%s: asset %d has no path", p, i+1)
			}
			if !assetFiles[a.Path] {
				return fmt.Errorf("%s: asset %q is not a file in this package (want assets/%s)", p, a.Path, a.Path)
			}
			if prev, dup := described[a.Path]; dup {
				return fmt.Errorf("%s: asset %q is already described in %s", p, a.Path, prev)
			}
			described[a.Path] = p
			if err := validateAssetEntry(a); err != nil {
				return fmt.Errorf("%s: asset %q: %v", p, a.Path, err)
			}
		}
	}
	// a list name is how a dependent package and Phishing Club find a list, so it
	// must be unique across the package.
	if pkgType == manifest.TypeAllowDeny {
		if _, err := declaredLists(docs); err != nil {
			return err
		}
	}
	return nil
}

// validateFileAssetBlocks runs validateAssetBlocks over a payload keyed by
// archive path, as the author flow holds it.
func validateFileAssetBlocks(pkgType string, files map[string][]byte) error {
	docs := map[string][]byte{}
	assets := map[string]bool{}
	for p, b := range files {
		if isDataYAML(p) {
			docs[p] = b
		} else if strings.HasPrefix(p, "assets/") {
			assets[strings.TrimPrefix(p, "assets/")] = true
		}
	}
	return validateAssetBlocks(pkgType, docs, assets)
}

// pickVarRe matches an allowDeny entry that is a whole installer pick variable.
var pickVarRe = regexp.MustCompile(`^@@([A-Z_][A-Z0-9_]{0,63})@@$`)

// declaredLists returns the allow deny lists the data.yaml docs declare, by
// trimmed name, with whether each allows. A doc that does not parse fails, and
// so does a name declared twice, so a list package that cannot be read the one
// way Phishing Club reads it never resolves a name.
func declaredLists(docs map[string][]byte) (map[string]bool, error) {
	paths := make([]string, 0, len(docs))
	for p := range docs {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	out := map[string]bool{}
	where := map[string]string{}
	for _, p := range paths {
		var dy assetDocYAML
		if err := yaml.Unmarshal(docs[p], &dy); err != nil {
			return nil, fmt.Errorf("%s: %v", p, err)
		}
		for _, l := range dy.AllowDenies {
			n := strings.TrimSpace(l.Name)
			if n == "" {
				continue
			}
			if prev, dup := where[n]; dup {
				return nil, invalidf("%s: the list %q is already declared in %s, a list name may be used once per package",
					p, n, prev)
			}
			where[n] = p
			out[n] = bool(l.Allowed)
		}
	}
	return out, nil
}

// listsOfFunc returns the allow deny lists the archive of a stored version
// declares.
type listsOfFunc func(v *database.PackageVersion) (map[string]bool, error)

// cachedListsOf wraps listsOf so each archive is read once per call chain, keyed
// by its blob sha.
func cachedListsOf(listsOf listsOfFunc) listsOfFunc {
	type res struct {
		lists map[string]bool
		err   error
	}
	seen := map[string]res{}
	return func(v *database.PackageVersion) (map[string]bool, error) {
		if r, ok := seen[v.ArchiveBlobSHA256]; ok {
			return r.lists, r.err
		}
		l, err := listsOf(v)
		seen[v.ArchiveBlobSHA256] = res{l, err}
		return l, err
	}
}

// checkAssetListRefs resolves every allow deny list name the assets in docs use,
// for the package m filed in the namespace nsName. See assetListUses.
func checkAssetListRefs(
	nsName string, m *manifest.Manifest, docs map[string][]byte, latest latestFunc, listsOf listsOfFunc,
) error {
	_, err := assetListUses(nsName, m, docs, latest, listsOf)
	return err
}

// assetListUses resolves every allow deny list name the assets in docs use, for
// the package m filed in the namespace nsName, and returns each list name it
// resolved through a dependency with its kind. A name resolves when it is a
// whole installer pick variable (@@NAME@@ declared with pick allowDeny), or a list declared by the latest version of an allowdeny package
// that m depends on in the same namespace. Phishing Club installs those
// dependencies with the package, so the name always resolves there. Every
// dependency must resolve to such a package. A pick is the only list of its
// asset and has no kind. One asset may not mix allow and deny lists, and two dependencies may not declare
// the same name. Anything else is refused, so a package never names a list it
// does not ship. A bundle ships no assets and is not checked.
func assetListUses(
	nsName string, m *manifest.Manifest, docs map[string][]byte, latest latestFunc, listsOf listsOfFunc,
) (map[string]bool, error) {
	used := map[string]bool{}
	if m.Type == manifest.TypeBundle {
		return used, nil
	}
	paths := make([]string, 0, len(docs))
	for p := range docs {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	type ref struct {
		doc   string
		asset assetYAML
	}
	var refs []ref
	for _, p := range paths {
		var dy assetDocYAML
		if err := yaml.Unmarshal(docs[p], &dy); err != nil {
			return nil, invalidf("%s: the assets or allowDenies block is not valid: %v", p, err)
		}
		for _, a := range dy.Assets {
			if len(a.AllowDeny) > 0 {
				refs = append(refs, ref{doc: p, asset: a})
			}
		}
	}
	picks := map[string]bool{}
	for _, v := range m.Variables {
		if v.Pick == manifest.PickAllowDeny {
			picks[v.Name] = true
		}
	}
	// the lists the allowdeny packages m depends on declare, with the package
	// that declares each. A dependency that is missing, of another type or in
	// another namespace is refused even when no asset uses it, so it never
	// installs as something the package did not mean.
	kind := map[string]bool{}
	from := map[string]string{}
	for _, d := range m.Dependencies {
		dns, _, ok := splitID(d.ID)
		if !ok {
			return nil, invalidf("invalid dependency id %q", d.ID)
		}
		if dns != nsName {
			return nil, invalidf("the dependency %s is not in the namespace %s; a package can only depend on "+
				"allow / deny packages in its own namespace", d.ID, nsName)
		}
		v, err := latest(d.ID)
		if err != nil {
			return nil, err
		}
		if v == nil {
			return nil, invalidf("the dependency %s has no version that can be installed", d.ID)
		}
		dm, err := manifest.Parse([]byte(v.Manifest))
		if err != nil {
			return nil, fmt.Errorf("stored manifest of %s is unreadable: %w", d.ID, err)
		}
		if dm.Type != manifest.TypeAllowDeny {
			return nil, invalidf("the dependency %s is a %s package; a package can only depend on allow / deny packages",
				d.ID, dm.Type)
		}
		lists, err := listsOf(v)
		if err != nil {
			if IsValidation(err) {
				return nil, invalidf("the lists of %s cannot be read: %v", d.ID, err)
			}
			return nil, fmt.Errorf("could not read the lists of %s: %w", d.ID, err)
		}
		for n, allowed := range lists {
			if prev, dup := from[n]; dup && prev != d.ID {
				return nil, invalidf("the list %q is declared by both %s and %s, depend on only one of them", n, prev, d.ID)
			}
			from[n] = d.ID
			kind[n] = allowed
		}
	}
	for _, r := range refs {
		// an installer pick is the asset's only list: the installer chooses one
		// list for it, never on top of lists the package ships.
		if len(r.asset.AllowDeny) > 1 {
			for _, raw := range r.asset.AllowDeny {
				if pickVarRe.MatchString(strings.TrimSpace(raw)) {
					return nil, invalidf("%s: asset %q: a list chosen at install must be the asset's only list",
						r.doc, r.asset.Path)
				}
			}
		}
		allows, denies := 0, 0
		for _, raw := range r.asset.AllowDeny {
			n := strings.TrimSpace(raw)
			if mm := pickVarRe.FindStringSubmatch(n); mm != nil {
				if !picks[mm[1]] {
					return nil, invalidf("%s: asset %q: %s is not a variable that lets the installer pick an "+
						"allow / deny list", r.doc, r.asset.Path, n)
				}
				continue
			}
			allowed, ok := kind[n]
			if !ok {
				return nil, invalidf("%s: asset %q uses the list %q, but no allow / deny package in the namespace %s "+
					"that this package depends on declares it", r.doc, r.asset.Path, n, nsName)
			}
			used[n] = allowed
			if allowed {
				allows++
			} else {
				denies++
			}
		}
		if allows > 0 && denies > 0 {
			return nil, invalidf("%s: asset %q mixes allow and deny lists, use only allow lists or only deny lists",
				r.doc, r.asset.Path)
		}
	}
	return used, nil
}

// PackageAsset is the settings one data.yaml assets block gives a shipped file,
// returned with the package source so the editor can load them back and the
// package page can show them. Path is relative to assets/; File is the archive
// path so the view can match it to the file's thumbnail and size.
type PackageAsset struct {
	Path        string            `json:"path"`
	File        string            `json:"file"`
	Name        string            `json:"name,omitempty"`
	Description string            `json:"description,omitempty"`
	ContentType string            `json:"contentType,omitempty"`
	Headers     []assetHeaderYAML `json:"headers"`
	AllowDeny   []string          `json:"allowDeny"`
}

// PackageAssets reads the assets block of every content folder's data.yaml in
// files. A data.yaml that does not parse is skipped so the rest still show. The
// result is sorted by data.yaml path and keeps the author's order within one.
func PackageAssets(files map[string][]byte) []PackageAsset {
	paths := make([]string, 0, len(files))
	for p := range files {
		if isDataYAML(p) {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	out := []PackageAsset{}
	for _, p := range paths {
		var dy assetDocYAML
		if err := yaml.Unmarshal(files[p], &dy); err != nil {
			continue
		}
		for _, a := range dy.Assets {
			if a.Path == "" {
				continue
			}
			headers := a.Headers
			if headers == nil {
				headers = []assetHeaderYAML{}
			}
			allowDeny := a.AllowDeny
			if allowDeny == nil {
				allowDeny = []string{}
			}
			out = append(out, PackageAsset{
				Path: a.Path, File: "assets/" + a.Path, Name: a.Name,
				Description: a.Description, ContentType: a.ContentType,
				Headers: headers, AllowDeny: allowDeny,
			})
		}
	}
	return out
}

// PackageList is the name and kind of one allow deny list a package declares.
type PackageList struct {
	Name    string `json:"name"`
	Allowed bool   `json:"allowed"`
}

// PackageLists reads the allow deny lists every content folder's data.yaml in
// files declares, sorted by name, with the kind read the way Phishing Club reads
// it. A data.yaml that does not parse is skipped.
func PackageLists(files map[string][]byte) []PackageList {
	out := []PackageList{}
	for p, b := range files {
		if !isDataYAML(p) {
			continue
		}
		var dy assetDocYAML
		if err := yaml.Unmarshal(b, &dy); err != nil {
			continue
		}
		for _, l := range dy.AllowDenies {
			if n := strings.TrimSpace(l.Name); n != "" {
				out = append(out, PackageList{Name: n, Allowed: bool(l.Allowed)})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
