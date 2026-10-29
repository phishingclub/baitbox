import { api } from '$lib/api/api.js';

// The server keeps a tag color only for a tag some package carries, so a color
// chosen for a tag that is not saved yet waits in a pending map (tag name to
// color) until the package is saved. applyPendingTagColors then reads the
// package's saved tags and sets the pending color of each one it carries. A
// pending tag the package did not keep is skipped. It returns the names whose
// color could not be saved.
export async function applyPendingTagColors(ns, name, pending) {
	const names = Object.keys(pending || {});
	if (!names.length) return [];
	const res = await api.packages.detail(ns, name);
	if (!res.ok) return names;
	const saved = new Set((res.data?.tags || []).map((t) => String(t).toLowerCase()));
	const failed = [];
	for (const t of names) {
		if (!saved.has(t.trim().toLowerCase())) continue;
		const r = await api.tags.setColor(t, pending[t]);
		if (!r.ok) failed.push(t);
	}
	return failed;
}
