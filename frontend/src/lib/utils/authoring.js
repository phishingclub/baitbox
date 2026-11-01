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
// scalars are left as is so simple content stays readable. a C1 control, the line
// breaks U+0085, U+2028 and U+2029, and the byte order mark are escaped too, since
// the Go YAML parser Phishing Club uses reads the line breaks as a new line and
// refuses the others as plain or quoted text.
export function yamlStr(v) {
	const s = String(v ?? '');
	const safe =
		s !== '' &&
		!/^\s|\s$/.test(s) &&
		!/:(\s|$)/.test(s) &&
		!/\s#/.test(s) &&
		!/^[-?:,[\]{}#&*!|>'"%@`]/.test(s) &&
		!/\n/.test(s) &&
		// a plain null, bool or number would load as that type, and a null loads as
		// an empty string, so quote anything that reads as one.
		!/^(?:~|null|true|false|yes|no|on|off|y|n)$/i.test(s) &&
		!/^[-+]?\.?\d/.test(s) &&
		// a control character cannot appear in a plain scalar.
		// eslint-disable-next-line no-control-regex
		!/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u2028\u2029\ufeff]/.test(s);
	if (safe) return s;
	return (
		'"' +
		s
			.replace(/\\/g, '\\\\')
			.replace(/"/g, '\\"')
			.replace(/\r/g, '')
			.replace(/\n/g, '\\n')
			.replace(/\t/g, '\\t')
			.replace(/\u0085/g, '\\N')
			.replace(/\u2028/g, '\\L')
			.replace(/\u2029/g, '\\P')
			// eslint-disable-next-line no-control-regex
			.replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, (c) => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0'))
			.replace(/[\u0080-\u009f\ufeff]/g, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')) +
		'"'
	);
}

// undo yamlStr for one scalar as written: a double quoted scalar has its quotes
// and escapes removed, anything else is returned as is.
export function unquoteYamlStr(s) {
	if (s.length >= 2 && s[0] === '"' && s[s.length - 1] === '"') {
		const named = { n: '\n', t: '\t', N: '\u0085', L: '\u2028', P: '\u2029', 0: '\u0000' };
		return s
			.slice(1, -1)
			.replace(/\\(x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|.)/g, (_, c) =>
				c.length > 1 ? String.fromCharCode(parseInt(c.slice(1), 16)) : c in named ? named[c] : c
			);
	}
	return s;
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
