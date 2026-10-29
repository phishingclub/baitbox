// Semver ordering for the UI, matching the server's effectiveLatest (which uses
// golang.org/x/mod/semver). Versions are operator authored and validated as semver
// on publish, so they are plain major.minor.patch with an optional prerelease.

// splitVersion returns [major, minor, patch, prerelease]. A leading v is tolerated.
function splitVersion(v) {
	const s = String(v || '').trim().replace(/^v/, '');
	const [core, pre = ''] = s.split('-', 2);
	const [maj, min, pat] = core.split('.');
	return [parseInt(maj, 10) || 0, parseInt(min, 10) || 0, parseInt(pat, 10) || 0, pre];
}

// comparePrerelease orders prerelease strings per semver: no prerelease outranks any
// prerelease; otherwise dot separated identifiers compare, numeric ones numerically.
function comparePrerelease(a, b) {
	if (a === b) return 0;
	if (a === '') return 1; // a is a release, b is a prerelease: a is higher
	if (b === '') return -1;
	const ap = a.split('.');
	const bp = b.split('.');
	for (let i = 0; i < Math.max(ap.length, bp.length); i++) {
		const x = ap[i];
		const y = bp[i];
		if (x === undefined) return -1;
		if (y === undefined) return 1;
		const xn = /^\d+$/.test(x);
		const yn = /^\d+$/.test(y);
		if (xn && yn) {
			const d = parseInt(x, 10) - parseInt(y, 10);
			if (d !== 0) return d < 0 ? -1 : 1;
		} else if (x !== y) {
			return x < y ? -1 : 1;
		}
	}
	return 0;
}

// compareSemver returns -1, 0 or 1 for a < b, a == b, a > b.
export function compareSemver(a, b) {
	const av = splitVersion(a);
	const bv = splitVersion(b);
	for (let i = 0; i < 3; i++) {
		if (av[i] !== bv[i]) return av[i] < bv[i] ? -1 : 1;
	}
	return comparePrerelease(av[3], bv[3]);
}

// highestVersion returns the highest semver version string from a list of version
// objects, skipping yanked ones. Falls back to the highest of all when every one is
// yanked, matching the server. versions use {version, yanked}.
export function highestVersion(versions) {
	if (!versions || versions.length === 0) return '';
	let best = null;
	let bestAny = null;
	for (const v of versions) {
		if (!bestAny || compareSemver(v.version, bestAny.version) > 0) bestAny = v;
		if (v.yanked) continue;
		if (!best || compareSemver(v.version, best.version) > 0) best = v;
	}
	return (best || bestAny).version;
}
