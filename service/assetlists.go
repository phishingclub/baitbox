package service

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"sort"

	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/manifest"
	"github.com/phishingclub/baitbox/repository"
)

// archiveDataDocs reads every content folder data.yaml from a stored archive,
// keyed by archive path. The archive already passed InspectArchiveSize, so each
// file is read up to maxFile bytes and a longer one fails.
func archiveDataDocs(archivePath string, maxFile int64) (map[string][]byte, error) {
	f, err := os.Open(archivePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("tar: %w", err)
		}
		name := path.Clean(hdr.Name)
		if hdr.Typeflag != tar.TypeReg || !isDataYAML(name) {
			continue
		}
		b, err := io.ReadAll(io.LimitReader(tr, maxFile+1))
		if err != nil {
			return nil, err
		}
		if int64(len(b)) > maxFile {
			return nil, fmt.Errorf("archive file %q exceeds size limit", name)
		}
		out[name] = b
	}
}

// blobDataDocs reads the data.yaml docs of the archive stored under sha.
func (s *RegistryService) blobDataDocs(sha string) (map[string][]byte, error) {
	p, err := s.blobs.Path(sha)
	if err != nil {
		return nil, err
	}
	return archiveDataDocs(p, s.limits.withDefaults().MaxFile)
}

// versionLists returns the allow deny lists a stored version declares.
func (s *RegistryService) versionLists(v *database.PackageVersion) (map[string]bool, error) {
	docs, err := s.blobDataDocs(v.ArchiveBlobSHA256)
	if err != nil {
		return nil, err
	}
	return declaredLists(docs)
}

// checkArchiveAssetLists runs checkAssetListRefs on the archive stored under
// sha, the archive of m, filed in nsName.
func (s *RegistryService) checkArchiveAssetLists(
	nsName string, m *manifest.Manifest, sha string, latest latestFunc,
) error {
	if m.Type == manifest.TypeBundle {
		return nil
	}
	docs, err := s.blobDataDocs(sha)
	if err != nil {
		return err
	}
	return checkAssetListRefs(nsName, m, docs, latest, s.versionLists)
}

// listBreak is a package whose asset lists stop resolving after a change: its
// id, why, and the changed packages it depends on.
type listBreak struct {
	id      string
	why     string
	changed []string
}

// kindWord names the kind of a list for a message.
func kindWord(allowed bool) string {
	if allowed {
		return "an allow list"
	}
	return "a deny list"
}

// dependentAssetListBreaks returns every package whose latest version depends
// on a package in changed and would stop resolving its asset lists once latest
// moves from before to after, or would see a list it uses change between allow
// and deny. Only a new break is reported, so a package that was already broken
// never blocks an unrelated change. It reads through r. Each list archive is
// read once per call. A package can only depend on a list package in its own
// namespace, so packages in other namespaces are never read.
func (s *RegistryService) dependentAssetListBreaks(
	r *repository.Registry, changed map[string]bool, before, after latestFunc,
) ([]listBreak, error) {
	breaks, _, err := s.scanAssetListBreaks(r, changed, before, after)
	return breaks, err
}

// changedNamespaces returns the namespaces of the package ids in changed.
func changedNamespaces(changed map[string]bool) map[string]bool {
	out := map[string]bool{}
	for id := range changed {
		if ns, _, ok := splitID(id); ok {
			out[ns] = true
		}
	}
	return out
}

// namespacePackageIDs returns the row ids, sorted, of every package in the
// namespaces, read through r.
func namespacePackageIDs(r *repository.Registry, namespaces map[string]bool) ([]string, error) {
	pkgs, err := r.ListPackages(nil)
	if err != nil {
		return nil, err
	}
	nss, err := r.ListNamespaces(nil)
	if err != nil {
		return nil, err
	}
	nsName := map[string]string{}
	for i := range nss {
		nsName[nss[i].ID] = nss[i].Name
	}
	var out []string
	for i := range pkgs {
		if namespaces[nsName[pkgs[i].NamespaceID]] {
			out = append(out, pkgs[i].ID)
		}
	}
	sort.Strings(out)
	return out, nil
}

// scanAssetListBreaks is dependentAssetListBreaks that also returns the row
// ids, sorted, of the packages it looked at: every package in a namespace of
// changed.
func (s *RegistryService) scanAssetListBreaks(
	r *repository.Registry, changed map[string]bool, before, after latestFunc,
) ([]listBreak, []string, error) {
	pkgs, err := r.ListPackages(nil)
	if err != nil {
		return nil, nil, err
	}
	nss, err := r.ListNamespaces(nil)
	if err != nil {
		return nil, nil, err
	}
	nsName := map[string]string{}
	for i := range nss {
		nsName[nss[i].ID] = nss[i].Name
	}
	namespaces := changedNamespaces(changed)
	listsOf := cachedListsOf(s.versionLists)
	var out []listBreak
	var scanned []string
	for i := range pkgs {
		p := &pkgs[i]
		ns := nsName[p.NamespaceID]
		if !namespaces[ns] {
			continue
		}
		scanned = append(scanned, p.ID)
		if p.Type == manifest.TypeBundle || p.Type == manifest.TypeAllowDeny {
			continue
		}
		id := ns + "/" + p.Name
		if changed[id] {
			continue
		}
		v, err := before(id)
		if err != nil {
			return nil, nil, err
		}
		if v == nil {
			continue
		}
		m, err := manifest.Parse([]byte(v.Manifest))
		if err != nil {
			return nil, nil, fmt.Errorf("stored manifest of %s is unreadable: %w", id, err)
		}
		if !references(m, changed) {
			continue
		}
		docs, err := s.blobDataDocs(v.ArchiveBlobSHA256)
		if err != nil {
			return nil, nil, err
		}
		prev, perr := assetListUses(ns, m, docs, before, listsOf)
		if perr != nil {
			if !IsValidation(perr) {
				return nil, nil, perr
			}
			continue
		}
		next, nerr := assetListUses(ns, m, docs, after, listsOf)
		why := ""
		if nerr != nil {
			if !IsValidation(nerr) {
				return nil, nil, nerr
			}
			why = nerr.Error()
		} else {
			names := make([]string, 0, len(prev))
			for n := range prev {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				if a, ok := next[n]; ok && a != prev[n] {
					why = fmt.Sprintf("the list %q changes from %s to %s", n, kindWord(prev[n]), kindWord(a))
					break
				}
			}
		}
		if why == "" {
			continue
		}
		b := listBreak{id: id, why: why}
		for _, d := range m.Dependencies {
			if changed[d.ID] {
				b.changed = append(b.changed, d.ID)
			}
		}
		out = append(out, b)
	}
	sort.Strings(scanned)
	return out, scanned, nil
}

// assetListWarnings lists the packages whose asset lists stop resolving after
// the versions of package id change to after. It is used for a change that is
// allowed anyway, such as a yank or a version delete, so the operator is told.
// A failure to check is returned as a warning too, since the change already
// happened.
func (s *RegistryService) assetListWarnings(
	id string, before latestFunc, after []database.PackageVersion,
) []string {
	breaks, err := s.dependentAssetListBreaks(s.repo, map[string]bool{id: true}, before, withVersions(id, after, before))
	if err != nil {
		return []string{fmt.Sprintf("could not check the packages that use the lists of %s: %v", id, err)}
	}
	out := make([]string, 0, len(breaks))
	for _, b := range breaks {
		out = append(out, fmt.Sprintf("%s can no longer be installed: %s", b.id, b.why))
	}
	return out
}

// listBreakReads is what a publish of a list version read to find the packages
// it would break, so the write can confirm none of it changed since: the
// version ids of the package, the packages of its namespace and the version
// latest resolved to for each package it looked up.
type listBreakReads struct {
	pkgID    string
	versions []string
	scanned  []string
	latest   map[string]string
}

// versionID is the id of a version, empty for none.
func versionID(v *database.PackageVersion) string {
	if v == nil {
		return ""
	}
	return v.ID
}

// checkListVersionBreaks refuses a new version v of the list package m (row id
// pkgID) that would stop a package that depends on it from installing, see
// dependentAssetListBreaks. It reads outside any transaction, since it reads
// every dependent archive, and returns what it read for verifyListBreakReads
// to confirm inside the transaction that writes the version.
func (s *RegistryService) checkListVersionBreaks(
	m *manifest.Manifest, pkgID string, v *database.PackageVersion,
) (*listBreakReads, error) {
	reads := &listBreakReads{pkgID: pkgID, latest: map[string]string{}}
	ids, err := s.repo.VersionIDs(pkgID)
	if err != nil {
		return nil, err
	}
	reads.versions = ids
	vs, err := s.repo.ListVersions(pkgID)
	if err != nil {
		return nil, err
	}
	base := repoLatest(s.repo)
	before := func(id string) (*database.PackageVersion, error) {
		lv, err := base(id)
		if err == nil {
			reads.latest[id] = versionID(lv)
		}
		return lv, err
	}
	breaks, scanned, err := s.scanAssetListBreaks(
		s.repo, map[string]bool{m.ID: true}, before, withVersions(m.ID, append(vs, *v), before),
	)
	if err != nil {
		return nil, err
	}
	if len(breaks) > 0 {
		return nil, invalidf("this changes the version of %s that Phishing Club installs, "+
			"and then %s cannot be installed: %s", m.ID, breaks[0].id, breaks[0].why)
	}
	reads.scanned = scanned
	return reads, nil
}

// verifyListBreakReads confirms, through the transaction tx, that nothing
// checkListVersionBreaks read changed: the versions of the package, the
// packages of its namespace and every latest version it looked up. Only row
// and version ids are compared, no archive is read. A change is refused with
// ErrConcurrentChange, so the publish can be tried again.
func verifyListBreakReads(tx *repository.Registry, m *manifest.Manifest, reads *listBreakReads) error {
	ids, err := tx.VersionIDs(reads.pkgID)
	if err != nil {
		return err
	}
	if !slices.Equal(ids, reads.versions) {
		return ErrConcurrentChange
	}
	scanned, err := namespacePackageIDs(tx, changedNamespaces(map[string]bool{m.ID: true}))
	if err != nil {
		return err
	}
	if !slices.Equal(scanned, reads.scanned) {
		return ErrConcurrentChange
	}
	latest := repoLatest(tx)
	for id, want := range reads.latest {
		lv, err := latest(id)
		if err != nil {
			return err
		}
		if versionID(lv) != want {
			return ErrConcurrentChange
		}
	}
	return nil
}
