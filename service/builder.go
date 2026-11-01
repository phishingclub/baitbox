package service

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/phishingclub/baitbox/manifest"
)

// PackageSpec is the metadata the UI supplies to author a package. Entries and
// the content hash are computed from the files.
type PackageSpec struct {
	ID             string
	Type           string
	Version        string
	Title          string
	Description    string
	Tags           []string
	MinAppVersion  string
	Preview        string
	Variables      []manifest.Variable
	Dependencies   []manifest.Dependency
	ShareVariables *bool
}

// BuildArchive assembles a package archive (baitbox.json plus the payload)
// from files keyed by their archive path under content/ or assets/. It computes
// per file hashes and the content hash, validates the manifest, and returns the
// tar.gz. This is what lets an operator author and publish a package from the
// browser.
func BuildArchive(spec PackageSpec, files map[string][]byte) ([]byte, *manifest.Manifest, error) {
	names := make([]string, 0, len(files))
	for n := range files {
		if n != manifest.FileName && !strings.HasPrefix(n, "content/") && !strings.HasPrefix(n, "assets/") {
			return nil, nil, fmt.Errorf("file path not allowed: %q (must be under content/ or assets/)", n)
		}
		// the path must already be clean so it cannot escape its prefix with .. or //;
		// this mirrors the stricter check the server runs on install.
		if n != manifest.FileName && (path.Clean(n) != n || strings.Contains(n, "..")) {
			return nil, nil, fmt.Errorf("file path not allowed: %q", n)
		}
		if n != manifest.FileName {
			names = append(names, n)
		}
		// a content YAML file (the data.yaml manifest, or a proxy.yaml AiTM config) must
		// be parseable, so a malformed one is caught at publish with a clear message
		// instead of failing cryptically at install. assets are opaque payload and not
		// checked. unsubstituted @@VAR@@ tokens are plain text, so valid YAML still parses.
		if strings.HasPrefix(n, "content/") && (strings.HasSuffix(n, ".yaml") || strings.HasSuffix(n, ".yml")) {
			var probe any
			if err := yaml.Unmarshal(files[n], &probe); err != nil {
				return nil, nil, fmt.Errorf("%s is not valid YAML: %v", n, err)
			}
		}
	}
	if len(names) == 0 {
		return nil, nil, fmt.Errorf("a package needs at least one content or asset file")
	}
	if err := validateFileAssetBlocks(spec.Type, files); err != nil {
		return nil, nil, err
	}
	sort.Strings(names)

	entries := make([]manifest.Entry, 0, len(names))
	for _, n := range names {
		sum := sha256.Sum256(files[n])
		entries = append(entries, manifest.Entry{Path: n, SHA256: hex.EncodeToString(sum[:])})
	}
	m := &manifest.Manifest{
		Format:         manifest.Format,
		ID:             spec.ID,
		Type:           spec.Type,
		Version:        spec.Version,
		Title:          spec.Title,
		MinAppVersion:  spec.MinAppVersion,
		Description:    spec.Description,
		Tags:           spec.Tags,
		Preview:        spec.Preview,
		Dependencies:   spec.Dependencies,
		ShareVariables: spec.ShareVariables,
		Variables:      spec.Variables,
		ContentHash:    manifest.ComputeContentHash(entries),
		Entries:        entries,
	}
	if err := m.Validate(); err != nil {
		return nil, nil, err
	}
	mj, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, nil, err
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	write := func(name string, b []byte) error {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		_, err := tw.Write(b)
		return err
	}
	if err := write(manifest.FileName, mj); err != nil {
		return nil, nil, err
	}
	for _, n := range names {
		if err := write(n, files[n]); err != nil {
			return nil, nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, nil, err
	}
	return buf.Bytes(), m, nil
}

// validateBundleTemplates checks the campaign templates declared in a bundle's
// data.yaml files: a training template must name an after landing page. It runs
// before publish so an invalid bundle is rejected with a clear reason.
func validateBundleTemplates(files map[string][]byte) error {
	for p, b := range files {
		if !strings.HasPrefix(p, "content/") || !strings.HasSuffix(p, "/data.yaml") {
			continue
		}
		var dy struct {
			CampaignTemplates []struct {
				Name             string `yaml:"name"`
				IsTraining       bool   `yaml:"isTraining"`
				AfterLandingPage string `yaml:"afterLandingPage"`
			} `yaml:"campaignTemplates"`
		}
		if err := yaml.Unmarshal(b, &dy); err != nil {
			return fmt.Errorf("bundle data.yaml is not valid yaml")
		}
		for _, ct := range dy.CampaignTemplates {
			if ct.IsTraining && strings.TrimSpace(ct.AfterLandingPage) == "" {
				return fmt.Errorf("campaign template %s: a training template needs an after landing page", ct.Name)
			}
		}
	}
	return nil
}
