package service

import (
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/manifest"
	"github.com/phishingclub/baitbox/repository"
	"github.com/phishingclub/baitbox/utils"
)

// ErrBundleTooLarge is returned when a bundle and the packages it references
// would unpack to more than MaxBundleInstallBytes, the most Phishing Club
// installs in one go.
var ErrBundleTooLarge = errors.New("bundle install size limit exceeded")

// latestFunc resolves a package id (namespace/name) to the version a "latest"
// request serves, the version Phishing Club installs for a bundle reference. It
// returns nil when the package does not exist or has no version.
type latestFunc func(id string) (*database.PackageVersion, error)

// repoLatest resolves latest through r, so a transaction can pass its own handle.
func repoLatest(r *repository.Registry) latestFunc {
	return func(id string) (*database.PackageVersion, error) {
		nsName, name, ok := splitID(id)
		if !ok {
			return nil, nil
		}
		ns, err := r.GetNamespace(nsName)
		if err != nil || ns == nil {
			return nil, nil
		}
		p, err := r.GetPackage(ns.ID, name)
		if err != nil || p == nil {
			return nil, nil
		}
		vs, err := r.ListVersions(p.ID)
		if err != nil {
			return nil, err
		}
		return effectiveLatest(vs), nil
	}
}

// withVersions resolves latest for one package from the given version list and
// every other package through next. It answers "what would latest be" for a
// change that has not been written yet.
func withVersions(id string, versions []database.PackageVersion, next latestFunc) latestFunc {
	return func(dep string) (*database.PackageVersion, error) {
		if dep == id {
			return effectiveLatest(versions), nil
		}
		return next(dep)
	}
}

// bundleInstallSize returns the unpacked bytes Phishing Club holds to install a
// bundle: selfSize, the bundle's own unpacked size, plus the version latest
// resolves to for each dependency. Phishing Club skips a dependency that is
// already installed, so this is the most a fresh install holds. A dependency
// that does not resolve adds nothing; the dependency rules refuse it.
func (s *RegistryService) bundleInstallSize(
	selfSize int64, deps []manifest.Dependency, latest latestFunc,
) (int64, error) {
	total := selfSize
	for _, d := range deps {
		v, err := latest(d.ID)
		if err != nil {
			return 0, err
		}
		if v != nil {
			total += v.UnpackedSize
		}
	}
	return total, nil
}

// bundleSizeError reports that bundle id would install total bytes.
func bundleSizeError(id string, total, limit int64) error {
	return fmt.Errorf("%w: %s and the packages it references unpack to %s (%d bytes), "+
		"the limit Phishing Club installs is %s",
		ErrBundleTooLarge, id, utils.FormatMiB(total), total, utils.FormatMiB(limit))
}

// checkBundleVersionSize refuses a bundle version whose own unpacked size plus
// the latest version of every reference is over the install cap. The reference
// count cap is enforced by manifest validation, which every stored archive passed.
func (s *RegistryService) checkBundleVersionSize(
	id string, selfSize int64, deps []manifest.Dependency, latest latestFunc,
) error {
	total, err := s.bundleInstallSize(selfSize, deps, latest)
	if err != nil {
		return err
	}
	if total > s.bundleCap {
		return bundleSizeError(id, total, s.bundleCap)
	}
	return nil
}

// bundleRef is the latest version of one bundle package and its parsed manifest.
type bundleRef struct {
	id string
	v  *database.PackageVersion
	m  *manifest.Manifest
}

// latestBundles lists the latest version of every bundle package, read through r.
func latestBundles(r *repository.Registry) ([]bundleRef, error) {
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
	var out []bundleRef
	for i := range pkgs {
		p := &pkgs[i]
		if p.Type != manifest.TypeBundle {
			continue
		}
		vs, err := r.ListVersions(p.ID)
		if err != nil {
			return nil, err
		}
		lv := effectiveLatest(vs)
		if lv == nil {
			continue
		}
		m, err := manifest.Parse([]byte(lv.Manifest))
		if err != nil {
			continue
		}
		out = append(out, bundleRef{id: nsName[p.NamespaceID] + "/" + p.Name, v: lv, m: m})
	}
	return out, nil
}

// references reports whether m names any id in ids.
func references(m *manifest.Manifest, ids map[string]bool) bool {
	for _, d := range m.Dependencies {
		if ids[d.ID] {
			return true
		}
	}
	return false
}

// dependentBundlesOverCap returns the ids of bundles, among bundles, that
// reference a package in changed and would install more than the cap once
// latest resolves through after instead of before. A bundle already over the cap
// is only listed when the change makes it larger, so a change that shrinks or
// keeps the total is never refused.
func (s *RegistryService) dependentBundlesOverCap(
	bundles []bundleRef, changed map[string]bool, before, after latestFunc,
) ([]string, error) {
	var over []string
	for _, b := range bundles {
		if changed[b.id] || !references(b.m, changed) {
			continue
		}
		self := b.v.UnpackedSize
		next, err := s.bundleInstallSize(self, b.m.Dependencies, after)
		if err != nil {
			return nil, err
		}
		if next <= s.bundleCap {
			continue
		}
		prev, err := s.bundleInstallSize(self, b.m.Dependencies, before)
		if err != nil {
			return nil, err
		}
		if next > prev {
			over = append(over, fmt.Sprintf("%s (%s)", b.id, utils.FormatMiB(next)))
		}
	}
	sort.Strings(over)
	return over, nil
}

// checkDependentBundles refuses a change to the versions of package id when a
// bundle that references it would then install more than the cap. after is the
// package's version list once the change is applied. Everything is read through
// r, so a transaction passes its own handle.
func (s *RegistryService) checkDependentBundles(
	r *repository.Registry, id string, after []database.PackageVersion,
) error {
	bundles, err := latestBundles(r)
	if err != nil {
		return err
	}
	before := repoLatest(r)
	over, err := s.dependentBundlesOverCap(bundles, map[string]bool{id: true}, before, withVersions(id, after, before))
	if err != nil {
		return err
	}
	if len(over) > 0 {
		return fmt.Errorf("%w: this changes the version of %s that Phishing Club installs, "+
			"and then %s would unpack to more than %s with the packages it references",
			ErrBundleTooLarge, id, strings.Join(over, ", "), utils.FormatMiB(s.bundleCap))
	}
	return nil
}

// bundleCapWarnings lists the bundles that reference package id and, after a
// change already applied to its versions, unpack to more than the cap and more
// than they did with before, the version list ahead of the change. It is advice
// only, so a read failure is logged and yields no warnings.
func (s *RegistryService) bundleCapWarnings(
	pkg *database.Package, id string, before []database.PackageVersion,
) []string {
	if pkg.Type == manifest.TypeBundle || before == nil {
		return nil
	}
	bundles, err := latestBundles(s.repo)
	if err != nil {
		log.Printf("bundle cap warning for %s: %v", id, err)
		return nil
	}
	now := repoLatest(s.repo)
	over, err := s.dependentBundlesOverCap(bundles, map[string]bool{id: true}, withVersions(id, before, now), now)
	if err != nil {
		log.Printf("bundle cap warning for %s: %v", id, err)
		return nil
	}
	return over
}
