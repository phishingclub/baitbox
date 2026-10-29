// Shared, stateless helpers for the package authoring pages (new and bundle).
// These close over no page state, so both pages import one copy instead of each
// keeping its own.

import { toast } from '$lib/stores/toast.svelte.js';

// bump the patch number of a semver string, so a loaded package opens as the
// next version. falls back to 1.0.1 when the input is not semver.
export function bumpPatch(v) {
	const m = (v || '1.0.0').match(/^(\d+)\.(\d+)\.(\d+)/);
	return m ? `${m[1]}.${m[2]}.${Number(m[3]) + 1}` : '1.0.1';
}

// decode a base64 string back to text, handling utf-8 bytes. falls back to a
// plain atob when the utf-8 unescape fails.
export const decodeText = (b64) => {
	try {
		return decodeURIComponent(escape(atob(b64)));
	} catch (_) {
		return atob(b64);
	}
};

// the media type for a filename, by extension, for inlining an uploaded image as
// a data url in the preview.
export function mimeFor(name) {
	const e = name.toLowerCase().split('.').pop();
	return (
		{ png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp', svg: 'image/svg+xml' }[e] ||
		'application/octet-stream'
	);
}

// render a string as a safe YAML scalar. a plain scalar breaks on a colon and space,
// a leading indicator, surrounding spaces or a newline, so a subject or title like
// "Action Required: Verify" must be double quoted and escaped, or the generated
// data.yaml is invalid and the package fails to install. values that are safe plain
// scalars are left as is so simple content stays readable.
export function yamlStr(v) {
	const s = String(v ?? '');
	const safe =
		s !== '' &&
		!/^\s|\s$/.test(s) &&
		!/:(\s|$)/.test(s) &&
		!/\s#/.test(s) &&
		!/^[-?:,[\]{}#&*!|>'"%@`]/.test(s) &&
		!/\n/.test(s);
	if (safe) return s;
	return '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\r/g, '').replace(/\n/g, '\\n').replace(/\t/g, '\\t') + '"';
}

// encode text as base64, handling utf-8 bytes, for shipping a file body in the
// publish payload.
export function b64text(s) {
	return btoa(unescape(encodeURIComponent(s)));
}

// a generous per file cap so an accidental huge file (a video, a disk image) is caught
// with a clear message instead of base64 inflating into a payload that hangs or fails
// the publish. legit phishing assets and attachments are well under this.
export const MAX_FILE_BYTES = 25 * 1024 * 1024;

// a default folder for a package's assets, built from its namespace and name, so a
// file like logo.png lands at <namespace>/<name>/logo.png and cannot collide with
// another package's logo.png on the shared asset store. empty until the package is
// named, and only a default: each asset path stays editable.
export function assetFolder(namespace, name) {
	const slug = (s) =>
		String(s || '')
			.trim()
			.toLowerCase()
			.replace(/[^a-z0-9._-]+/g, '-')
			.replace(/^-+|-+$/g, '');
	const ns = slug(namespace);
	const nm = slug(name);
	if (!nm) return '';
	return ns ? `${ns}/${nm}/` : `${nm}/`;
}

// the string an author pastes into HTML for an uploaded asset. the file ships in the
// archive under assets/<file>, but phishingclub serves it per sending domain, so the
// reference is {{.BaseURL}}/<file> (BaseURL resolves to the domain at send time). a
// stored dependency path (assets/<file>) is converted to the same reference form.
export function assetRef(path) {
	return `{{.BaseURL}}/${String(path).replace(/^assets\//, '')}`;
}

// normalize an operator edited asset path: strip a leading slash and any .. segment
// so it cannot escape assets/, and drop characters that are not safe in a path.
export function sanitizeAssetPath(p) {
	return String(p || '')
		.replace(/\\/g, '/')
		.replace(/[^A-Za-z0-9._/-]+/g, '-')
		.replace(/\.\.+/g, '.')
		.replace(/\/{2,}/g, '/')
		.replace(/^\/+/, '');
}

// copy an asset's reference so the operator can paste it straight into their HTML
// instead of retyping it.
export function copyRef(path) {
	navigator.clipboard?.writeText(path).then(
		() => toast('Reference copied', 'success'),
		() => toast('Could not copy', 'error')
	);
}
