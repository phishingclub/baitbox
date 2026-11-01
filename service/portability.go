package service

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/manifest"
	"github.com/phishingclub/baitbox/model"
	"github.com/phishingclub/baitbox/repository"
	"github.com/phishingclub/baitbox/utils"
)

// ErrInvalidBundle means the uploaded file is not a readable Bait Box export
// bundle: bad gzip or tar, an unsupported format, a corrupt blob, or missing
// metadata. The operator sees this friendly message instead of a low level
// gzip or tar parse error.
var ErrInvalidBundle = errors.New("not a valid Bait Box export bundle")

// bundleFormat identifies the whole registry export bundle.
const bundleFormat = "baitbox-registry/v1"

// import bounds: a bundle may hold at most this many entries and this many total
// declared bytes, so a tar bomb cannot exhaust disk during an import.
const (
	maxBundleEntries = 100000
	maxBundleBytes   = 8 << 30
)

// inspectArchive is InspectArchiveSize; tests swap it to count calls.
var inspectArchive = InspectArchiveSize

// registryFileName is the metadata file at the root of an export bundle.
const registryFileName = "registry.json"

type nsDTO struct {
	Name        string `json:"name"`
	Visibility  string `json:"visibility"`
	Description string `json:"description"`
	Color       string `json:"color"`
}

type previewDTO struct {
	Sha       string `json:"sha"`
	MediaType string `json:"mediaType"`
	Position  int    `json:"position"`
}

type pkgDTO struct {
	Namespace   string       `json:"namespace"`
	Name        string       `json:"name"`
	Type        string       `json:"type"`
	Title       string       `json:"title,omitempty"`
	Description string       `json:"description"`
	Tags        string       `json:"tags,omitempty"`
	Previews    []previewDTO `json:"previews,omitempty"`
}

type verDTO struct {
	Namespace     string          `json:"namespace"`
	Name          string          `json:"name"`
	Version       string          `json:"version"`
	Manifest      json.RawMessage `json:"manifest"`
	ContentHash   string          `json:"contentHash"`
	ArchiveSha    string          `json:"archiveSha"`
	Size          int64           `json:"size"`
	MinAppVersion string          `json:"minAppVersion"`
	Yanked        bool            `json:"yanked"`
}

// tagColorDTO is the global color of one tag name.
type tagColorDTO struct {
	Name  string `json:"name"`
	Color string `json:"color"`
}

type exportBundle struct {
	Format     string   `json:"format"`
	Namespaces []nsDTO  `json:"namespaces"`
	Packages   []pkgDTO `json:"packages"`
	Versions   []verDTO `json:"versions"`
	// TagColors holds the color of each tag the bundle packages carry that has one.
	TagColors []tagColorDTO `json:"tagColors,omitempty"`
}

// ImportSummary reports what an import actually added (rows already present are
// kept and not counted), so the operator sees what an import changed.
type ImportSummary struct {
	Namespaces int `json:"namespaces"`
	// Packages is how many packages were newly created by this import.
	Packages int `json:"packages"`
	Versions int `json:"versions"`
	// Upgraded lists existing packages the bundle carried a newer version for, and
	// so updated. Skipped lists existing packages the bundle brought nothing newer
	// for, which were left untouched (their local metadata is not overwritten).
	Upgraded []string `json:"upgraded"`
	Skipped  []string `json:"skipped"`
	// Refused lists packages the import would not file, and Warnings says why for
	// each, for example private content whose namespace is public here. Nothing of
	// a refused package is written.
	Refused  []string `json:"refused"`
	Warnings []string `json:"warnings"`
}

// ExportBundle writes the whole registry (metadata plus archive blobs) as a
// tar.gz to w. registry.json is written first, then one blobs/<sha> entry per
// referenced archive. Operators, passkeys, tokens and drafts are never
// exported.
func (s *RegistryService) ExportBundle(w io.Writer) error {
	namespaces, err := s.repo.ListNamespaces(nil)
	if err != nil {
		return err
	}
	nsName := map[string]string{}
	bundle := exportBundle{Format: bundleFormat}
	for i := range namespaces {
		ns := &namespaces[i]
		nsName[ns.ID] = ns.Name
		bundle.Namespaces = append(bundle.Namespaces, s.namespaceDTO(ns))
	}
	packages, err := s.repo.ListPackages(nil)
	if err != nil {
		return err
	}
	blobSet := map[string]bool{}
	for i := range packages {
		p := &packages[i]
		if err := s.collectPackage(&bundle, nsName[p.NamespaceID], p, blobSet, false); err != nil {
			return err
		}
	}
	if err := s.collectTagColors(&bundle); err != nil {
		return err
	}
	return s.writeBundle(w, &bundle, blobSet)
}

// namespaceDTO is the exported form of a namespace, with its effective
// visibility.
func (s *RegistryService) namespaceDTO(ns *database.Namespace) nsDTO {
	return nsDTO{ns.Name, s.EffectiveVisibility(ns.Visibility), ns.Description, ns.Color}
}

// ExportPackageBundle writes one package as a portable bundle in the same tar.gz
// format as ExportBundle: its single namespace, the package, all its versions and
// previews, and only the blobs those reference. The bundle is a normal export
// bundle with one package, so ImportBundle reads it with no special case.
func (s *RegistryService) ExportPackageBundle(w io.Writer, namespaceName, packageName string, latestOnly bool) error {
	ns, err := s.repo.GetNamespace(namespaceName)
	if err != nil {
		return ErrNotFound
	}
	pkg, err := s.repo.GetPackage(ns.ID, packageName)
	if err != nil {
		return ErrNotFound
	}
	bundle := exportBundle{Format: bundleFormat}
	bundle.Namespaces = append(bundle.Namespaces, s.namespaceDTO(ns))
	blobSet := map[string]bool{}
	if err := s.collectPackage(&bundle, ns.Name, pkg, blobSet, latestOnly); err != nil {
		return err
	}
	if err := s.collectTagColors(&bundle); err != nil {
		return err
	}
	return s.writeBundle(w, &bundle, blobSet)
}

// bundleTagNames returns the cleaned tag names the bundle packages carry.
func bundleTagNames(pkgs []pkgDTO) map[string]bool {
	out := map[string]bool{}
	for i := range pkgs {
		if strings.TrimSpace(pkgs[i].Tags) == "" {
			continue
		}
		for _, t := range model.CleanTags(strings.Split(pkgs[i].Tags, ",")) {
			out[t] = true
		}
	}
	return out
}

// collectTagColors adds the color of every tag the bundle packages carry, so an
// import shows the same tag colors.
func (s *RegistryService) collectTagColors(bundle *exportBundle) error {
	names := bundleTagNames(bundle.Packages)
	if len(names) == 0 {
		return nil
	}
	tags, err := s.repo.ListTags()
	if err != nil {
		return err
	}
	for i := range tags {
		if tags[i].Color != "" && names[tags[i].Name] {
			bundle.TagColors = append(bundle.TagColors, tagColorDTO{Name: tags[i].Name, Color: tags[i].Color})
		}
	}
	return nil
}

// collectPackage appends one package's DTO, its versions and its preview images
// to the bundle, and records every blob they reference in blobSet so the writer
// ships those blobs.
func (s *RegistryService) collectPackage(
	bundle *exportBundle,
	nsName string,
	p *database.Package,
	blobSet map[string]bool,
	latestOnly bool,
) error {
	pd := pkgDTO{
		Namespace: nsName, Name: p.Name, Type: p.Type,
		Title: p.Title, Description: p.Description, Tags: p.Tags,
	}
	// preview images are package meta blobs; include them so an import keeps them.
	if previews, perr := s.repo.ListPackagePreviews(p.ID); perr == nil {
		for k := range previews {
			pd.Previews = append(pd.Previews, previewDTO{
				Sha:       previews[k].BlobSHA256,
				MediaType: previews[k].MediaType,
				Position:  previews[k].Position,
			})
			blobSet[previews[k].BlobSHA256] = true
		}
	}
	bundle.Packages = append(bundle.Packages, pd)
	versions, verr := s.repo.ListVersions(p.ID)
	if verr != nil {
		return verr
	}
	// a latest only export ships just the current version so the bundle stays small;
	// an empty current version (for example every version yanked) falls back to all.
	latest := ""
	if latestOnly {
		latest = s.CurrentVersion(p.ID)
	}
	for j := range versions {
		v := &versions[j]
		if latest != "" && v.Version != latest {
			continue
		}
		bundle.Versions = append(bundle.Versions, verDTO{
			Namespace: nsName, Name: p.Name, Version: v.Version,
			Manifest:    json.RawMessage(v.Manifest),
			ContentHash: v.ContentHash, ArchiveSha: v.ArchiveBlobSHA256,
			Size: v.Size, MinAppVersion: v.MinAppVersion, Yanked: v.Yanked,
		})
		blobSet[v.ArchiveBlobSHA256] = true
	}
	return nil
}

// writeBundle streams a built bundle as a tar.gz to w: registry.json first, then
// one blobs/<sha> entry per referenced blob.
func (s *RegistryService) writeBundle(w io.Writer, bundle *exportBundle, blobSet map[string]bool) error {
	gz := gzip.NewWriter(w)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	meta, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	hdr := &tar.Header{Name: registryFileName, Mode: 0o644, Size: int64(len(meta)), Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := tw.Write(meta); err != nil {
		return err
	}
	for sha := range blobSet {
		if err := s.writeBlobToTar(tw, sha); err != nil {
			return err
		}
	}
	return nil
}

func (s *RegistryService) writeBlobToTar(tw *tar.Writer, sha string) error {
	rc, err := s.blobs.Open(sha)
	if err != nil {
		return err
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		return err
	}
	hdr := &tar.Header{Name: "blobs/" + sha, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err = tw.Write(data)
	return err
}

// ImportBundle imports a registry export produced by ExportBundle. It is
// idempotent: existing namespaces, packages, versions and blobs are left in
// place. registry.json must be the first entry so metadata is known before the
// blobs stream in.
func (s *RegistryService) ImportBundle(r io.Reader) (*ImportSummary, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		// the parser error is not shown, only a plain reason.
		return nil, fmt.Errorf("%w: the file is not a gzip archive", ErrInvalidBundle)
	}
	defer gz.Close()
	// cap the whole unpacked stream, headers and skipped entries included.
	tr := tar.NewReader(&capReader{r: gz, left: maxBundleBytes + int64(maxBundleEntries+1)*streamSlackPerEntry})

	var bundle *exportBundle
	// shas of blobs that actually arrived in the tar, keyed by their computed hash.
	// referenced shas in registry.json must be in this set, so a bundle cannot name a
	// blob path it did not ship.
	stored := map[string]bool{}
	// every Put pins its blob, including one that then fails a check, so each is
	// listed here to be released.
	var pinned []string
	// when this returns, release the pins and remove any blob stored this run that
	// nothing references. The writes are one transaction, so on an error none of
	// these blobs is referenced and all are reclaimed; on success a crafted
	// bundle's extra unreferenced blobs are reclaimed rather than left on disk.
	defer func() {
		s.releaseBlobs(pinned)
		s.cleanupBlobs(pinned)
	}()
	// bound the tar so a crafted bundle cannot exhaust disk; written counts the bytes
	// actually stored (see the blobs branch), entries the number of tar entries.
	var entries, written int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: the archive contents are unreadable", ErrInvalidBundle)
		}
		// every entry counts, skipped ones too, so a flood of directory entries is
		// bounded like files.
		entries++
		if entries > maxBundleEntries {
			return nil, fmt.Errorf("%w: bundle has too many entries", ErrInvalidBundle)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		switch {
		case hdr.Name == registryFileName:
			meta, rerr := io.ReadAll(io.LimitReader(tr, 64<<20))
			if rerr != nil {
				return nil, rerr
			}
			var b exportBundle
			if jerr := json.Unmarshal(meta, &b); jerr != nil {
				return nil, fmt.Errorf("%w: %s is not valid JSON", ErrInvalidBundle, registryFileName)
			}
			if b.Format != bundleFormat {
				return nil, fmt.Errorf("%w: unsupported format %q", ErrInvalidBundle, b.Format)
			}
			bundle = &b
		case strings.HasPrefix(hdr.Name, "blobs/"):
			wantSha := strings.TrimPrefix(hdr.Name, "blobs/")
			gotSha, gotSize, perr := s.blobs.Put(tr, s.maxDownload)
			if perr != nil {
				if errors.Is(perr, ErrBlobTooLarge) {
					return nil, fmt.Errorf(
						"%w: a stored file is larger than the package archive limit of %d bytes",
						ErrInvalidBundle, s.maxDownload,
					)
				}
				return nil, fmt.Errorf("%w: a stored file could not be read", ErrInvalidBundle)
			}
			pinned = append(pinned, gotSha)
			if gotSha != wantSha {
				return nil, fmt.Errorf("%w: a stored file is corrupt", ErrInvalidBundle)
			}
			// count bytes actually stored, not the attacker declared header size.
			written += gotSize
			if written > maxBundleBytes {
				return nil, fmt.Errorf("%w: bundle is too large", ErrInvalidBundle)
			}
			stored[gotSha] = true
		default:
			return nil, fmt.Errorf("%w: unexpected entry %q", ErrInvalidBundle, hdr.Name)
		}
	}
	if bundle == nil {
		return nil, fmt.Errorf("%w: missing %s", ErrInvalidBundle, registryFileName)
	}
	return s.applyBundle(bundle, stored)
}

// import decisions for one package.
const (
	pkgNew     = "new"
	pkgUpgrade = "upgrade"
	pkgSkip    = "skip"
	pkgRefuse  = "refuse"
)

// verifiedVersion is one bundle version after its archive passed InspectArchiveSize.
type verifiedVersion struct {
	dto      verDTO
	m        *manifest.Manifest
	mjson    string
	size     int64
	unpacked int64 // sum of the unpacked file sizes
	existing bool  // the version is already stored locally
}

// row is the version row the import stores for vv, without its package id.
func (vv *verifiedVersion) row() database.PackageVersion {
	return database.PackageVersion{
		Version:           vv.m.Version,
		Manifest:          vv.mjson,
		MinAppVersion:     vv.m.MinAppVersion,
		ArchiveBlobSHA256: vv.dto.ArchiveSha,
		ContentHash:       vv.m.ContentHash,
		Size:              vv.size,
		UnpackedSize:      vv.unpacked,
		Yanked:            vv.dto.Yanked,
	}
}

// importPlan is one bundle package and everything known about it before any
// write: its verified versions and the local rows it would join.
type importPlan struct {
	dto      pkgDTO
	key      string
	versions []*verifiedVersion
	local    *database.Package
	localVs  []database.PackageVersion
	// localPreviews is the count of preview images the local package already has,
	// so an upgrade adds bundle previews only up to the gallery cap.
	localPreviews int
	status        string
}

// applyBundle validates a parsed bundle against the blobs that arrived, plans
// every write from reads done up front, and then applies the writes in one
// transaction. Every version archive is reverified before anything is decided,
// and the stored rows use the verified manifest, never the bundle fields.
func (s *RegistryService) applyBundle(b *exportBundle, stored map[string]bool) (*ImportSummary, error) {
	// --- static checks on the bundle, no database access ---
	if len(b.Namespaces) > maxBundleEntries || len(b.Packages) > maxBundleEntries ||
		len(b.Versions) > maxBundleEntries {
		return nil, fmt.Errorf("%w: bundle lists too many entries", ErrInvalidBundle)
	}
	nsVis := map[string]string{}
	nsDTOs := map[string]nsDTO{}
	var nsOrder []string
	var colorWarnings []string
	for _, ns := range b.Namespaces {
		if !manifest.ValidNamespace(ns.Name) {
			return nil, fmt.Errorf("%w: invalid namespace name", ErrInvalidBundle)
		}
		ns.Description = strings.TrimSpace(ns.Description)
		if err := (model.Namespace{Name: ns.Name, Description: ns.Description}).Validate(); err != nil {
			return nil, fmt.Errorf("%w: namespace %s: %v", ErrInvalidBundle, ns.Name, err)
		}
		// the color goes through the same allowlist as an admin edit. A value outside
		// it is dropped (no color) and the operator is told.
		if c := model.NormalizeColor(ns.Color); c != ns.Color {
			if strings.TrimSpace(ns.Color) != "" && c == "" {
				colorWarnings = append(colorWarnings,
					fmt.Sprintf("%s: color %q is not an allowed color and was cleared", ns.Name, ns.Color))
			}
			ns.Color = c
		}
		// on a private registry every namespace is created private.
		vis := s.EffectiveVisibility(ns.Visibility)
		if prev, ok := nsVis[ns.Name]; ok {
			// a namespace listed twice keeps the more private setting.
			if prev == database.VisibilityPrivate {
				vis = prev
			}
		} else {
			nsOrder = append(nsOrder, ns.Name)
			nsDTOs[ns.Name] = ns
		}
		nsVis[ns.Name] = vis
	}
	// previewSize holds the stored size of each preview blob, so its blob row
	// records the real size.
	previewSize := map[string]int64{}
	// previewType holds the sniffed type of each preview blob already checked.
	previewType := map[string]string{}
	plans := map[string]*importPlan{}
	var order []string
	for _, p := range b.Packages {
		key := p.Namespace + "/" + p.Name
		if !manifest.ValidID(key) {
			return nil, fmt.Errorf("%w: invalid package name", ErrInvalidBundle)
		}
		if _, ok := nsVis[p.Namespace]; !ok {
			return nil, fmt.Errorf(
				"%w: package %s names a namespace the bundle does not declare", ErrInvalidBundle, key)
		}
		if !manifest.ValidType(p.Type) {
			return nil, fmt.Errorf("%w: package %s has an invalid type", ErrInvalidBundle, key)
		}
		if plans[key] != nil {
			return nil, fmt.Errorf("%w: package %s is listed twice", ErrInvalidBundle, key)
		}
		// the editable metadata gets the same rules as the admin meta edit: trimmed,
		// the free text capped, and the tags cleaned.
		p.Title = strings.TrimSpace(p.Title)
		p.Description = strings.TrimSpace(p.Description)
		if err := model.ValidatePackageMeta(p.Title, p.Description); err != nil {
			return nil, fmt.Errorf("%w: package %s: %v", ErrInvalidBundle, key, err)
		}
		p.Tags = cleanTagList(p.Tags)
		if len(p.Previews) > MaxPreviewImages {
			return nil, fmt.Errorf(
				"%w: package %s has more than %d preview images", ErrInvalidBundle, key, MaxPreviewImages)
		}
		for _, pv := range p.Previews {
			if !stored[pv.Sha] {
				return nil, fmt.Errorf("%w: preview references a blob not in the bundle", ErrInvalidBundle)
			}
			if !allowedPreviewMediaType(pv.MediaType) {
				return nil, fmt.Errorf("%w: preview has an unsupported image type", ErrInvalidBundle)
			}
			// the same limits as an upload, and the bytes must be the type claimed. Each
			// distinct blob is read once, however many previews name it.
			detected, seen := previewType[pv.Sha]
			if !seen {
				d, err := s.checkStoredPreview(pv.Sha)
				if err != nil {
					return nil, fmt.Errorf("%w: preview image %s is not allowed (%v)",
						ErrInvalidBundle, pv.Sha, previewReason(err, d, pv.MediaType))
				}
				size, serr := s.blobs.Size(pv.Sha)
				if serr != nil {
					return nil, serr
				}
				previewType[pv.Sha] = d
				previewSize[pv.Sha] = size
				detected = d
			}
			if detected != pv.MediaType {
				return nil, fmt.Errorf("%w: preview image %s is not allowed (%v)",
					ErrInvalidBundle, pv.Sha, previewReason(nil, detected, pv.MediaType))
			}
		}
		plans[key] = &importPlan{dto: p, key: key}
		order = append(order, key)
	}
	// a tag color is kept only for a tag a bundle package carries, and only when it
	// is an allowlisted color, the same rules as an admin tag color edit. It is
	// applied later only for a tag a created or upgraded package really carries.
	carried := bundleTagNames(b.Packages)
	tagColors := map[string]string{}
	var tagOrder []string
	for _, tc := range b.TagColors {
		if !carried[tc.Name] {
			continue
		}
		c := model.NormalizeColor(tc.Color)
		if c == "" {
			if strings.TrimSpace(tc.Color) != "" {
				colorWarnings = append(colorWarnings,
					fmt.Sprintf("tag %s: color %q is not an allowed color and was cleared", tc.Name, tc.Color))
			}
			continue
		}
		if _, ok := tagColors[tc.Name]; !ok {
			tagOrder = append(tagOrder, tc.Name)
		}
		tagColors[tc.Name] = c
	}
	sum := &ImportSummary{Warnings: colorWarnings}
	// refuse marks a package as not imported and says why. A package is listed once
	// even when several of its versions fail.
	refuse := func(pl *importPlan, why string) {
		if pl.status == pkgRefuse {
			return
		}
		pl.status = pkgRefuse
		sum.Refused = append(sum.Refused, pl.key)
		sum.Warnings = append(sum.Warnings, pl.key+": "+why)
	}
	// every version archive is reverified the same way publish does, before any
	// decision uses it. InspectArchiveSize reparses the manifest, checks every file
	// hash, the caps and the path rules, and manifest.Validate enforces the content
	// hash. The bundle's own version string must equal the verified one, the
	// archive id must match the address it is filed under, and its type must match
	// the package type. A version that fails refuses its whole package, so the rest
	// of the bundle still imports.
	// the cheap checks run over every entry first, so a bundle that lists a huge
	// number of versions is refused before any archive is opened.
	seenVer := map[string]bool{}
	for _, v := range b.Versions {
		key := v.Namespace + "/" + v.Name
		if !manifest.ValidID(key) {
			return nil, fmt.Errorf("%w: invalid version identifier", ErrInvalidBundle)
		}
		if plans[key] == nil {
			return nil, fmt.Errorf("%w: version %s@%s has no package entry", ErrInvalidBundle, key, v.Version)
		}
		if seenVer[key+"@"+v.Version] {
			return nil, fmt.Errorf("%w: version %s@%s is listed twice", ErrInvalidBundle, key, v.Version)
		}
		seenVer[key+"@"+v.Version] = true
		if !shaRe.MatchString(v.ArchiveSha) {
			return nil, fmt.Errorf("%w: version %s@%s has an invalid archive reference",
				ErrInvalidBundle, key, v.Version)
		}
	}
	// each distinct archive is inspected once, however many entries name it.
	type inspected struct {
		m        *manifest.Manifest
		unpacked int64
		size     int64
		err      error
	}
	inspectedArchives := map[string]*inspected{}
	inspect := func(sha string) (*inspected, error) {
		if r := inspectedArchives[sha]; r != nil {
			return r, nil
		}
		blobPath, err := s.blobs.Path(sha)
		if err != nil {
			return nil, err
		}
		r := &inspected{}
		r.m, r.unpacked, r.err = inspectArchive(blobPath, s.limits)
		if r.err == nil {
			size, serr := s.blobs.Size(sha)
			if serr != nil {
				return nil, serr
			}
			r.size = size
		}
		inspectedArchives[sha] = r
		return r, nil
	}
	for _, v := range b.Versions {
		pl := plans[v.Namespace+"/"+v.Name]
		if pl.status == pkgRefuse {
			continue
		}
		if !manifest.ValidVersion(v.Version) {
			refuse(pl, "not imported because the bundle lists a version that is not a valid semver version")
			continue
		}
		if !stored[v.ArchiveSha] {
			refuse(pl, fmt.Sprintf(
				"not imported because version %s references an archive not in the bundle", v.Version))
			continue
		}
		ar, err := inspect(v.ArchiveSha)
		if err != nil {
			return nil, err
		}
		if ar.err != nil {
			refuse(pl, fmt.Sprintf("not imported because version %s failed its integrity check: %v", v.Version, ar.err))
			continue
		}
		m := ar.m
		if m.Namespace() != v.Namespace || m.PackageName() != v.Name {
			refuse(pl, fmt.Sprintf(
				"not imported because version %s archive identity does not match its address", v.Version))
			continue
		}
		if m.Version != v.Version {
			refuse(pl, fmt.Sprintf("not imported because version %s archive says version %s", v.Version, m.Version))
			continue
		}
		if m.Type != pl.dto.Type {
			refuse(pl, fmt.Sprintf(
				"not imported because version %s archive type %s does not match package type %s",
				v.Version, m.Type, pl.dto.Type))
			continue
		}
		mj, merr := json.Marshal(m)
		if merr != nil {
			return nil, merr
		}
		pl.versions = append(pl.versions, &verifiedVersion{
			dto: v, m: m, mjson: string(mj), size: ar.size, unpacked: ar.unpacked,
		})
	}

	// --- reads of local state, all before the transaction ---
	localNS := map[string]*database.Namespace{}
	for _, name := range nsOrder {
		if ns, err := s.repo.GetNamespace(name); err == nil && ns != nil {
			localNS[name] = ns
		}
	}
	// effectiveVis is the visibility a namespace has after the import: the local
	// setting when it exists, otherwise the bundle's.
	effectiveVis := func(name string) string {
		if ns := localNS[name]; ns != nil {
			return ns.Visibility
		}
		if v, ok := nsVis[name]; ok {
			return v
		}
		return s.liveVisibility(name)
	}
	for _, key := range order {
		pl := plans[key]
		if pl.status == pkgRefuse {
			continue
		}
		ns := localNS[pl.dto.Namespace]
		// visibility lives on the namespace only. Private content filed into a
		// namespace that is public here would become public, so it is refused.
		if ns != nil && s.EffectiveVisibility(ns.Visibility) == database.VisibilityPublic &&
			nsVis[pl.dto.Namespace] != database.VisibilityPublic {
			refuse(pl, fmt.Sprintf("not imported because the bundle marks namespace %s private "+
				"but it is public here, so the private content would become public", pl.dto.Namespace))
			continue
		}
		if ns != nil {
			if pkg, err := s.repo.GetPackage(ns.ID, pl.dto.Name); err == nil && pkg != nil {
				pl.local = pkg
				vs, lerr := s.repo.ListVersions(pkg.ID)
				if lerr != nil {
					return nil, lerr
				}
				pl.localVs = vs
				n, cerr := s.repo.CountPackagePreviews(pkg.ID)
				if cerr != nil {
					return nil, cerr
				}
				pl.localPreviews = int(n)
			}
		}
		if pl.local != nil && pl.local.Type != pl.dto.Type {
			refuse(pl, fmt.Sprintf(
				"not imported because it is a %s here and a %s in the bundle", pl.local.Type, pl.dto.Type))
			continue
		}
		have := map[string]bool{}
		for i := range pl.localVs {
			have[pl.localVs[i].Version] = true
		}
		for _, vv := range pl.versions {
			vv.existing = have[vv.m.Version]
		}
		// a package not present locally is created. One that already exists is only
		// touched when the bundle carries a newer verified version than the local
		// latest: then it is upgraded (new versions added, metadata refreshed).
		// Otherwise it is skipped entirely, so importing the same or an older
		// bundle never overwrites local edits.
		if pl.local == nil {
			// a new package with no version would be a row nothing can install, the
			// same state publish never leaves behind.
			if len(pl.versions) == 0 {
				refuse(pl, "not imported because the bundle carries no version of it")
				continue
			}
			pl.status = pkgNew
			continue
		}
		localMax := ""
		if lv := effectiveLatest(pl.localVs); lv != nil {
			localMax = lv.Version
		}
		bundleMax := ""
		for _, vv := range pl.versions {
			if bundleMax == "" || semverLess(bundleMax, vv.m.Version) {
				bundleMax = vv.m.Version
			}
		}
		if localMax == "" || (bundleMax != "" && semverLess(localMax, bundleMax)) {
			pl.status = pkgUpgrade
		} else {
			pl.status = pkgSkip
		}
	}
	// the dependency rules run on every version this import would add, the same
	// rules publish applies, against the namespace visibility after the import. A
	// dependency may be another package in this bundle. The bundle install cap is
	// checked the same way, on the latest versions the import leaves behind. A
	// package that fails is refused, and since that can break a package that
	// depends on it, the check repeats until nothing changes.
	depType := func(nsName, name string) (string, bool) {
		if pl := plans[nsName+"/"+name]; pl != nil && (pl.status == pkgNew || pl.status == pkgUpgrade) {
			return pl.dto.Type, true
		}
		return s.liveDepType(nsName, name)
	}
	for changed := true; changed; {
		changed = false
		for _, key := range order {
			pl := plans[key]
			if pl.status != pkgNew && pl.status != pkgUpgrade {
				continue
			}
			nsName := pl.dto.Namespace
			for _, vv := range pl.versions {
				if vv.existing {
					continue
				}
				err := s.checkDeps(
					pl.dto.Type, nsName, effectiveVis(nsName), vv.m.Dependencies, effectiveVis, depType)
				if err != nil {
					refuse(pl, fmt.Sprintf(
						"not imported because version %s breaks a dependency rule: %v", vv.m.Version, err))
					changed = true
					break
				}
				err = s.checkArchiveAssetLists(nsName, vv.m, vv.dto.ArchiveSha, importLatest(s.repo, plans))
				if err != nil {
					if !IsValidation(err) {
						return nil, err
					}
					refuse(pl, fmt.Sprintf(
						"not imported because version %s has an allow / deny list that does not resolve: %v",
						vv.m.Version, err))
					changed = true
					break
				}
			}
		}
		if changed {
			continue
		}
		over, err := s.importBundleRefusals(s.repo, plans, order)
		if err != nil {
			return nil, err
		}
		for _, key := range order {
			if why, ok := over[key]; ok {
				refuse(plans[key], why)
				changed = true
			}
		}
	}
	// a namespace new to this registry is created when the bundle files at least
	// one package into it, or lists it with no packages at all (an empty namespace
	// in the export). One whose packages were all refused is not created.
	nsPackages := map[string]int{}
	nsKept := map[string]bool{}
	for _, key := range order {
		pl := plans[key]
		nsPackages[pl.dto.Namespace]++
		if pl.status != pkgRefuse {
			nsKept[pl.dto.Namespace] = true
		}
	}
	createNS := map[string]bool{}
	for _, name := range nsOrder {
		if localNS[name] == nil && (nsPackages[name] == 0 || nsKept[name]) {
			createNS[name] = true
		}
	}
	for _, key := range order {
		switch plans[key].status {
		case pkgUpgrade:
			sum.Upgraded = append(sum.Upgraded, key)
		case pkgSkip:
			sum.Skipped = append(sum.Skipped, key)
		}
	}

	if s.beforeWriteCommit != nil {
		s.beforeWriteCommit()
	}
	// --- one transaction: recheck the rules on the tx handle, then write ---
	err := s.repo.Transaction(func(tx *repository.Registry) error {
		// the namespace visibility and dependency checks above used reads made before
		// this transaction. Repeat them on the transaction's own connection so a
		// namespace edit or publish that committed in between cannot let private
		// content or a broken dependency in.
		if err := s.recheckImportTx(tx, plans, order, nsVis, localNS, createNS); err != nil {
			return err
		}
		nsIDs := map[string]string{}
		for name, ns := range localNS {
			nsIDs[name] = ns.ID
		}
		for _, name := range nsOrder {
			if !createNS[name] {
				continue
			}
			d := nsDTOs[name]
			row := &database.Namespace{Name: name, Visibility: nsVis[name], Description: d.Description, Color: d.Color}
			if err := tx.CreateNamespace(row); err != nil {
				return uniqueAsConflict(err)
			}
			nsIDs[name] = row.ID
			sum.Namespaces++
		}
		// written holds the tags of the packages this import creates or upgrades. A
		// refused or skipped package writes no tags, so its tags get no color.
		written := map[string]bool{}
		for _, key := range order {
			pl := plans[key]
			if pl.status != pkgNew && pl.status != pkgUpgrade {
				continue
			}
			var newRows []database.PackageVersion
			for _, vv := range pl.versions {
				if vv.existing {
					continue
				}
				newRows = append(newRows, vv.row())
			}
			// set the editable metadata from the bundle so edits survive export
			// and import.
			title, desc, tags := pl.dto.Title, pl.dto.Description, pl.dto.Tags
			for _, t := range model.CleanTags(strings.Split(tags, ",")) {
				written[t] = true
			}
			var pkgID string
			if pl.local == nil {
				row := &database.Package{
					NamespaceID: nsIDs[pl.dto.Namespace], Name: pl.dto.Name, Type: pl.dto.Type,
					Title: title, Description: desc, Tags: tags,
				}
				if err := tx.CreatePackage(row); err != nil {
					return uniqueAsConflict(err)
				}
				pkgID = row.ID
				sum.Packages++
			} else {
				pkgID = pl.local.ID
				if err := tx.UpdatePackageMeta(pkgID, title, desc, tags); err != nil {
					return err
				}
			}
			// an upgrade keeps the local gallery and adds bundle previews only up to the
			// same cap an upload has. A preview already in the gallery is a no op.
			room := MaxPreviewImages - pl.localPreviews
			for _, pv := range pl.dto.Previews {
				if room <= 0 {
					break
				}
				room--
				if err := tx.InsertBlobIfAbsent(pv.Sha, previewSize[pv.Sha], pv.MediaType); err != nil {
					return err
				}
				if err := tx.InsertPackagePreview(pkgID, pv.Sha, pv.MediaType, pv.Position); err != nil {
					return err
				}
			}
			for i := range newRows {
				newRows[i].PackageID = pkgID
				if err := tx.CreateVersion(&newRows[i]); err != nil {
					return uniqueAsConflict(err)
				}
				sha, size := newRows[i].ArchiveBlobSHA256, newRows[i].Size
				if err := tx.InsertBlobIfAbsent(sha, size, "application/gzip"); err != nil {
					return err
				}
				sum.Versions++
			}
		}
		var writtenOrder []string
		for _, name := range tagOrder {
			if written[name] {
				writtenOrder = append(writtenOrder, name)
			}
		}
		return applyTagColors(tx, tagColors, writtenOrder)
	})
	if err != nil {
		return nil, err
	}
	// an upgrade replaces a package's tags, which can leave a tag color row that no
	// package uses.
	s.pruneTags()
	return sum, nil
}

// applyTagColors sets the bundle color on each tag a package uses after the
// import. A tag that already has a color here keeps it, so an import never
// overwrites a local edit.
func applyTagColors(tx *repository.Registry, colors map[string]string, order []string) error {
	if len(order) == 0 {
		return nil
	}
	tags, err := tx.ListTags()
	if err != nil {
		return err
	}
	local := map[string]string{}
	for i := range tags {
		local[tags[i].Name] = tags[i].Color
	}
	for _, name := range order {
		if local[name] != "" {
			continue
		}
		used, err := tx.TagInUse(name)
		if err != nil {
			return err
		}
		if !used {
			continue
		}
		if err := tx.UpsertTagColor(name, colors[name]); err != nil {
			return err
		}
	}
	return nil
}

// uniqueAsConflict turns a unique index failure on an import insert into
// ErrConcurrentChange: the row was created by another writer after the recheck,
// so the operator can run the import again. The database message is not kept,
// since the conflict reason is shown to the operator. Any other error passes
// through.
func uniqueAsConflict(err error) error {
	if repository.IsUniqueViolation(err) {
		return ErrConcurrentChange
	}
	return err
}

// recheckImportTx repeats the import visibility and dependency rules on tx, the
// open import transaction. Namespaces this import creates take the bundle
// visibility; every other lookup reads through tx. Any difference from the plan
// means the registry changed while the import ran, and the import is rolled back
// with ErrConcurrentChange so the operator can run it again.
func (s *RegistryService) recheckImportTx(
	tx *repository.Registry,
	plans map[string]*importPlan,
	order []string,
	nsVis map[string]string,
	localNS map[string]*database.Namespace,
	createNS map[string]bool,
) error {
	for name := range createNS {
		if ns, err := tx.GetNamespace(name); err == nil && ns != nil {
			return fmt.Errorf("%w: namespace %s was created during the import", ErrConcurrentChange, name)
		}
	}
	visibility := func(name string) string {
		if createNS[name] {
			return nsVis[name]
		}
		return repoVisibility(tx)(name)
	}
	depType := func(nsName, name string) (string, bool) {
		if pl := plans[nsName+"/"+name]; pl != nil && (pl.status == pkgNew || pl.status == pkgUpgrade) {
			return pl.dto.Type, true
		}
		return repoDepType(tx)(nsName, name)
	}
	for _, key := range order {
		pl := plans[key]
		if pl.status != pkgNew && pl.status != pkgUpgrade {
			continue
		}
		nsName := pl.dto.Namespace
		if local := localNS[nsName]; local != nil {
			now, err := tx.GetNamespace(nsName)
			if err != nil || now == nil || now.ID != local.ID || now.Visibility != local.Visibility {
				return fmt.Errorf("%w: namespace %s changed during the import", ErrConcurrentChange, nsName)
			}
			// a package the plan creates must still be absent, and a package the plan
			// upgrades must still sit at its address with none of the new versions,
			// or a publish committed in between and the inserts would collide.
			if pl.local == nil {
				exists, eerr := tx.PackageExists(local.ID, pl.dto.Name)
				if eerr != nil {
					return eerr
				}
				if exists {
					return fmt.Errorf("%w: package %s was created during the import", ErrConcurrentChange, key)
				}
			} else {
				nsNow, nameNow, aerr := tx.PackageAddress(pl.local.ID)
				if aerr != nil || nsNow != nsName || nameNow != pl.dto.Name {
					return fmt.Errorf("%w: package %s changed during the import", ErrConcurrentChange, key)
				}
				for _, vv := range pl.versions {
					if vv.existing {
						continue
					}
					exists, eerr := tx.VersionExists(pl.local.ID, vv.m.Version)
					if eerr != nil {
						return eerr
					}
					if exists {
						return fmt.Errorf("%w: %s@%s was published during the import",
							ErrConcurrentChange, key, vv.m.Version)
					}
				}
			}
		}
		for _, vv := range pl.versions {
			if vv.existing {
				continue
			}
			err := s.checkDeps(
				pl.dto.Type, nsName, visibility(nsName), vv.m.Dependencies, visibility, depType)
			if err != nil {
				return fmt.Errorf("%w: %s@%s: %v", ErrConcurrentChange, key, vv.m.Version, err)
			}
			err = s.checkArchiveAssetLists(nsName, vv.m, vv.dto.ArchiveSha, importLatest(tx, plans))
			if err != nil {
				return fmt.Errorf("%w: %s@%s: %v", ErrConcurrentChange, key, vv.m.Version, err)
			}
		}
	}
	over, err := s.importBundleRefusals(tx, plans, order)
	if err != nil {
		return err
	}
	for _, key := range order {
		if why, ok := over[key]; ok {
			return fmt.Errorf("%w: %s %s", ErrConcurrentChange, key, why)
		}
	}
	return nil
}

// importLatest resolves latest as it will be once the import commits: a package
// the import creates or upgrades takes its local versions, read through r, plus
// the new versions from the bundle; every other package reads through r.
func importLatest(r *repository.Registry, plans map[string]*importPlan) latestFunc {
	base := repoLatest(r)
	return func(id string) (*database.PackageVersion, error) {
		pl := plans[id]
		if pl == nil || (pl.status != pkgNew && pl.status != pkgUpgrade) {
			return base(id)
		}
		var all []database.PackageVersion
		if pl.local != nil {
			vs, err := r.ListVersions(pl.local.ID)
			if err != nil {
				return nil, err
			}
			all = append(all, vs...)
		}
		for _, vv := range pl.versions {
			if !vv.existing {
				all = append(all, vv.row())
			}
		}
		return effectiveLatest(all), nil
	}
}

// importBundleRefusals applies the bundle install rules to an import plan,
// reading through r. It returns, keyed by package, why each package the import
// would add versions to must be refused: a bundle version that would unpack to
// more than the cap with the latest version of every reference or whose shared
// pick variables disagree with them, or a package whose new latest version would
// push a local bundle that references it over the cap or make its shared pick
// variables disagree.
func (s *RegistryService) importBundleRefusals(
	r *repository.Registry,
	plans map[string]*importPlan,
	order []string,
) (map[string]string, error) {
	after := importLatest(r, plans)
	out := map[string]string{}
	changed := map[string]bool{}
	for _, key := range order {
		pl := plans[key]
		if pl.status != pkgNew && pl.status != pkgUpgrade {
			continue
		}
		changed[key] = true
		if pl.dto.Type != manifest.TypeBundle {
			continue
		}
		for _, vv := range pl.versions {
			if vv.existing {
				continue
			}
			err := s.checkBundleVersionSize(key, vv.unpacked, vv.m.Dependencies, after)
			if errors.Is(err, ErrBundleTooLarge) {
				out[key] = fmt.Sprintf("not imported because version %s is too large: %v", vv.m.Version, err)
				break
			}
			if err != nil {
				return nil, err
			}
			if err := checkBundleSharedPicks(vv.m, after); err != nil {
				if !IsValidation(err) {
					return nil, err
				}
				out[key] = fmt.Sprintf("not imported because version %s has mismatched shared variables: %v",
					vv.m.Version, err)
				break
			}
		}
	}
	if len(changed) == 0 {
		return out, nil
	}
	bundles, err := latestBundles(r)
	if err != nil {
		return nil, err
	}
	before := repoLatest(r)
	for _, b := range bundles {
		if changed[b.id] || !references(b.m, changed) {
			continue
		}
		why, err := newPickClash(b.m, before, after)
		if err != nil {
			return nil, err
		}
		if why == "" {
			continue
		}
		for _, d := range b.m.Dependencies {
			if _, done := out[d.ID]; changed[d.ID] && !done {
				out[d.ID] = fmt.Sprintf("not imported because its new latest version would stop "+
					"the local bundle %s from installing: %s", b.id, why)
			}
		}
	}
	for _, b := range bundles {
		over, err := s.dependentBundlesOverCap([]bundleRef{b}, changed, before, after)
		if err != nil {
			return nil, err
		}
		if len(over) == 0 {
			continue
		}
		for _, d := range b.m.Dependencies {
			if changed[d.ID] {
				if _, done := out[d.ID]; !done {
					out[d.ID] = fmt.Sprintf("not imported because its new latest version would make "+
						"the local bundle %s unpack to more than the %s Phishing Club installs",
						over[0], utils.FormatMiB(s.bundleCap))
				}
			}
		}
	}
	breaks, err := s.dependentAssetListBreaks(r, changed, before, after)
	if err != nil {
		return nil, err
	}
	for _, b := range breaks {
		for _, id := range b.changed {
			if _, done := out[id]; !done {
				out[id] = fmt.Sprintf("not imported because its new latest version would stop "+
					"%s from installing: %s", b.id, b.why)
			}
		}
	}
	return out, nil
}

// checkStoredPreview runs the preview image checks on a blob that arrived in
// an import bundle, reading at most one byte past the size limit.
func (s *RegistryService) checkStoredPreview(sha string) (string, error) {
	f, err := s.blobs.Open(sha)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxPreviewBytes+1))
	if err != nil {
		return "", err
	}
	return checkPreviewImage(data)
}

// previewReason explains why an imported preview was rejected.
func previewReason(err error, detected, claimed string) string {
	if err != nil {
		return err.Error()
	}
	return fmt.Sprintf("bytes are %s, bundle says %s", detected, claimed)
}

// cleanTagList applies the admin tag rules to a comma separated tag column.
func cleanTagList(tags string) string {
	if strings.TrimSpace(tags) == "" {
		return ""
	}
	return strings.Join(model.CleanTags(strings.Split(tags, ",")), ",")
}

// seedMeta returns the package metadata a manifest seeds, held to the admin caps.
// A manifest is accepted at publish without those caps, so long text is cut to
// fit rather than failing the publish.
func seedMeta(m *manifest.Manifest) (string, string, string) {
	title := utils.TruncateRunes(strings.TrimSpace(m.Title), model.MaxTitleRunes)
	desc := utils.TruncateRunes(strings.TrimSpace(m.Description), model.MaxDescriptionRunes)
	return title, desc, strings.Join(model.CleanTags(m.Tags), ",")
}
