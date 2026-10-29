package service

import (
	"github.com/phishingclub/baitbox/database"
	"github.com/phishingclub/baitbox/manifest"
	"github.com/phishingclub/baitbox/repository"
)

// checkBundleSharedPicks refuses a bundle that shares variables when one name is
// a pick in one package and a plain value or another pick kind in another.
// Phishing Club fills a shared name once, so it refuses such a bundle at install.
// The packages checked are the bundle and the latest version of each reference,
// the versions Phishing Club installs.
func checkBundleSharedPicks(m *manifest.Manifest, latest latestFunc) error {
	if m.ShareVariables != nil && !*m.ShareVariables {
		return nil
	}
	pkgs := []*manifest.Manifest{m}
	for _, d := range m.Dependencies {
		v, err := latest(d.ID)
		if err != nil {
			return err
		}
		if v == nil {
			continue
		}
		dm, err := manifest.Parse([]byte(v.Manifest))
		if err != nil {
			return err
		}
		pkgs = append(pkgs, dm)
	}
	type decl struct{ pick, id string }
	seen := map[string]decl{}
	for _, p := range pkgs {
		for _, v := range p.Variables {
			d, ok := seen[v.Name]
			if !ok {
				seen[v.Name] = decl{pick: v.Pick, id: p.ID}
				continue
			}
			if d.pick != v.Pick {
				return invalidf("the shared variable %q is %s in %s and %s in %s, "+
					"a shared variable must pick the same kind in every package",
					v.Name, pickDesc(d.pick), d.id, pickDesc(v.Pick), p.ID)
			}
		}
	}
	return nil
}

func pickDesc(kind string) string {
	if kind == "" {
		return "a plain value"
	}
	return "a " + kind + " pick"
}

// newPickClash returns why bundle m stops installing when latest moves from
// before to after: its shared picks disagree after and did not before. A clash
// that already existed is not reported, so it never blocks an unrelated change.
// An empty reason means no new clash.
func newPickClash(m *manifest.Manifest, before, after latestFunc) (string, error) {
	clash := checkBundleSharedPicks(m, after)
	if clash == nil {
		return "", nil
	}
	if !IsValidation(clash) {
		return "", clash
	}
	if prev := checkBundleSharedPicks(m, before); prev != nil {
		if !IsValidation(prev) {
			return "", prev
		}
		return "", nil
	}
	return clash.Error(), nil
}

// checkDependentBundlePicks refuses a change to the versions of package id when
// a bundle that references it would then have shared variables whose picks
// disagree. after is the package's version list once the change is applied.
// Everything is read through r, so a transaction passes its own handle.
func checkDependentBundlePicks(r *repository.Registry, id string, after []database.PackageVersion) error {
	bundles, err := latestBundles(r)
	if err != nil {
		return err
	}
	before := repoLatest(r)
	next := withVersions(id, after, before)
	for _, b := range bundles {
		if b.id == id || !references(b.m, map[string]bool{id: true}) {
			continue
		}
		why, err := newPickClash(b.m, before, next)
		if err != nil {
			return err
		}
		if why != "" {
			return invalidf("this changes the version of %s that Phishing Club installs, "+
				"and then the bundle %s cannot be installed: %s", id, b.id, why)
		}
	}
	return nil
}
