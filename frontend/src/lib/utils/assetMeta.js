// Per asset settings (name, description, content type, response headers and
// allow deny list names). They ship in a content folder data.yaml as an assets
// block. A list name is a list of an allow / deny package in the same namespace
// that the package depends on, or an installer pick variable. The checks here
// mirror the Bait Box server and Phishing Club, so an author sees a problem
// before publishing.

import jsyaml from '$lib/components/yaml/index.js';
import { yamlStr } from '$lib/utils/authoring.js';

// common file extensions and the media type Phishing Club serves them with when
// an asset has no content type of its own. Only a hint in the editor.
const EXT_TYPES = {
	html: 'text/html; charset=utf-8',
	htm: 'text/html; charset=utf-8',
	css: 'text/css; charset=utf-8',
	js: 'text/javascript; charset=utf-8',
	mjs: 'text/javascript; charset=utf-8',
	json: 'application/json',
	xml: 'text/xml; charset=utf-8',
	txt: 'text/plain; charset=utf-8',
	csv: 'text/csv; charset=utf-8',
	svg: 'image/svg+xml',
	png: 'image/png',
	jpg: 'image/jpeg',
	jpeg: 'image/jpeg',
	gif: 'image/gif',
	webp: 'image/webp',
	avif: 'image/avif',
	ico: 'image/x-icon',
	bmp: 'image/bmp',
	pdf: 'application/pdf',
	zip: 'application/zip',
	wasm: 'application/wasm',
	woff: 'font/woff',
	woff2: 'font/woff2',
	ttf: 'font/ttf',
	otf: 'font/otf',
	mp4: 'video/mp4',
	webm: 'video/webm',
	mp3: 'audio/mpeg',
	wav: 'audio/wav'
};

// the type a file is served with by its extension, or empty when unknown.
export function typeFromExtension(path) {
	const base = String(path || '').split('/').pop();
	if (!base.includes('.')) return '';
	return EXT_TYPES[base.split('.').pop().toLowerCase()] || '';
}

// a new empty settings set for an asset.
export function emptyAssetMeta() {
	return { name: '', description: '', contentType: '', headers: [], allowDeny: [] };
}

// the installer pick variable the editor adds when the installer chooses the
// asset's one list at install, and the pick kind it declares.
export const DEFAULT_LIST_PICK = 'ALLOW_DENY_LIST';
export const LIST_PICK_KIND = 'allowDeny';

// whether a pick kind picks an allow / deny list.
export const isListPick = (kind) => kind === LIST_PICK_KIND;

// every list name the known list packages in namespace declare, mapped to its
// kind and package. pkgs are { id, namespace, lists: [{ name, allowed }] }; a
// package that could not be read has no lists and an error.
export function listKinds(pkgs, namespace) {
	const out = new Map();
	for (const p of pkgs || []) {
		if (p.namespace !== namespace) continue;
		for (const l of p.lists || []) out.set(l.name, { allowed: !!l.allowed, pkg: p });
	}
	return out;
}

// the list packages the assets use, which the package must depend on so
// Phishing Club installs them with it.
export function usedListPackages(assets, pkgs, namespace) {
	const used = new Set((assets || []).flatMap((a) => a.allowDeny || []));
	return (pkgs || []).filter((p) => p.namespace === namespace && (p.lists || []).some((l) => used.has(l.name)));
}

// read the lists of the allow / deny package id from its latest version. It
// returns { id, namespace, name, title, lists } or, when the package cannot be
// read, the same with an error message and no lists.
export async function fetchListPackage(api, id) {
	const [namespace, name] = String(id || '').split('/');
	const base = { id, namespace, name, title: name };
	const res = await api.packages.source(namespace, name, 'latest');
	if (!res.ok) return { ...base, error: res.status === 404 ? `${id} no longer exists` : `Could not read ${id}` };
	if (res.data.type !== 'allowdeny') return { ...base, error: `${id} is not an allow / deny package` };
	const lists = (res.data.lists || []).map((l) => ({ name: l.name, allowed: !!l.allowed }));
	return { ...base, title: res.data.title || name, lists };
}

// header rows that carry anything; a fully blank row is ignored like the other
// header editors.
const usedHeaders = (a) => (a.headers || []).filter((h) => String(h.key).trim() || String(h.value) !== '');

// whether an asset has any setting, so only those are written to the block.
export function hasAssetMeta(a) {
	return !!(
		String(a.name || '').trim() ||
		String(a.description || '').trim() ||
		String(a.contentType || '').trim() ||
		usedHeaders(a).length ||
		(a.allowDeny || []).length
	);
}

// a valid HTTP token: header names and media type parts.
const TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
// response headers an asset cannot set, matched in lower case.
const BLOCKED = new Set([
	'content-length',
	'transfer-encoding',
	'connection',
	'keep-alive',
	'upgrade',
	'te',
	'trailer',
	'proxy-connection',
	'content-type'
]);
// a control character other than tab, which no header value may hold.
// eslint-disable-next-line no-control-regex
const CTL = /[\u0000-\u0008\u000a-\u001f\u007f]/;

// the most response headers one asset can have, as Phishing Club allows.
export const MAX_ASSET_HEADERS = 50;

// the length of a string in UTF-8 bytes, which is what Phishing Club counts.
export const byteLength = (s) => new TextEncoder().encode(String(s ?? '')).length;

// trim the white space Go's strings.TrimSpace trims, which Phishing Club applies
// before it checks a value. It differs from String.trim on U+0085 and U+FEFF.
const GO_SPACE = '[\\t\\n\\v\\f\\r \\u0085\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]';
const GO_TRIM = new RegExp(`^${GO_SPACE}+|${GO_SPACE}+$`, 'g');
export const goTrim = (s) => String(s ?? '').replace(GO_TRIM, '');

// the problem with a Cache-Control value on an asset with lists, or empty. Such
// an asset is sent with "private, no-store" unless it sets its own, so the value
// must hold no-store or private and must not hold public or s-maxage.
export function filteredCacheControlError(value) {
	let keeps = false;
	let opens = false;
	for (const part of String(value || '').split(',')) {
		const name = goTrim(part.split('=')[0]).toLowerCase();
		if (name === 'no-store' || name === 'private') keeps = true;
		if (name === 'public' || name === 's-maxage') opens = true;
	}
	return !keeps || opens ? 'With allow or deny lists, Cache-Control must hold no-store or private and not public or s-maxage.' : '';
}

// the YAML 1.1 spellings the Go YAML parser takes for a bool field besides
// true and false, quoted or not.
const YES = new Set(['y', 'Y', 'yes', 'Yes', 'YES', 'on', 'On', 'ON']);
const NO = new Set(['n', 'N', 'no', 'No', 'NO', 'off', 'Off', 'OFF']);

// read an allowed value the way Phishing Club does when it decodes it into a Go
// bool. v is the value as js-yaml loads it with its default schema, which reads
// a plain true, True or TRUE (and the false forms) as a bool and anything quoted
// as text, the same as the Go parser. Returns null for a value Phishing Club
// refuses.
export function yamlBool(v) {
	if (v === null || v === undefined) return false;
	if (typeof v === 'boolean') return v;
	if (typeof v === 'string') {
		if (YES.has(v)) return true;
		if (NO.has(v)) return false;
	}
	return null;
}

// read one scalar as written in a data.yaml, such as the text after allowed:,
// as a bool the way yamlBool does. Returns null for a value Phishing Club refuses.
export function scalarBool(raw) {
	try {
		return yamlBool(jsyaml.load(String(raw ?? '')));
	} catch (_) {
		return null;
	}
}

// the problem with a content type, or empty when it is fine.
export function contentTypeError(ct) {
	const s = String(ct || '');
	if (!s) return '';
	if (byteLength(s) > 255) return 'At most 255 bytes.';
	if (CTL.test(s)) return 'Contains invalid characters.';
	const [mt, ...params] = s.split(';');
	const parts = mt.trim().split('/');
	if (parts.length !== 2 || !parts[0] || !parts[1] || !TOKEN.test(parts[0]) || !TOKEN.test(parts[1]))
		return 'Use a type and subtype, such as text/html.';
	for (const p of params) {
		const t = p.trim();
		if (!t && params.length === 1) continue;
		const m = t.match(/^([^=\s]+)=(.+)$/);
		if (!m || !TOKEN.test(m[1]) || !(TOKEN.test(m[2]) || /^"([^"\\]|\\.)*"$/.test(m[2])))
			return 'A parameter must look like charset=utf-8.';
	}
	return '';
}

// the problem with one header row, as { key, value } messages.
export function headerErrors(h) {
	const key = goTrim(h.key);
	const value = goTrim(h.value);
	const out = { key: '', value: '' };
	if (!key) out.key = 'Enter a header name.';
	else if (byteLength(key) > 127) out.key = 'At most 127 bytes.';
	else if (!TOKEN.test(key)) out.key = 'Not a valid header name.';
	else if (key.toLowerCase() === 'content-type') out.key = 'Set the content type field instead.';
	else if (BLOCKED.has(key.toLowerCase())) out.key = `${key} cannot be set on an asset.`;
	if (value === '') out.value = 'Enter a value.';
	else if (byteLength(value) > 2048) out.value = 'At most 2048 bytes.';
	else if (CTL.test(value)) out.value = 'Contains invalid characters.';
	return out;
}

// every problem with one asset's settings. known maps each list name that
// resolves to its kind, as listKinds returns it. picks maps each installer pick
// variable name to its pick kind, and plainVars holds the
// variables the content uses as plain values, which a pick may not share.
export function assetMetaErrors(a, known = new Map(), picks = {}, plainVars = new Set()) {
	const out = { name: '', description: '', contentType: '', headers: [], headerList: '', allowDeny: '' };
	if (byteLength(goTrim(a.name)) > 127) out.name = 'At most 127 bytes.';
	if (byteLength(goTrim(a.description)) > 255) out.description = 'At most 255 bytes.';
	out.contentType = contentTypeError(goTrim(a.contentType));
	const names = (a.allowDeny || []).map((n) => goTrim(n));
	out.headers = (a.headers || []).map((h) => {
		if (!(String(h.key).trim() || String(h.value) !== '')) return { key: '', value: '' };
		const e = headerErrors(h);
		if (!e.key && !e.value && names.length && goTrim(h.key).toLowerCase() === 'cache-control')
			e.value = filteredCacheControlError(goTrim(h.value));
		return e;
	});
	if (usedHeaders(a).length > MAX_ASSET_HEADERS) out.headerList = `At most ${MAX_ASSET_HEADERS} headers.`;
	const pickNames = names.map(pickVarName).filter(Boolean);
	const missing = names.filter((n) => !pickVarName(n) && !known.has(n));
	const badPick = pickNames.find((v) => !isListPick(picks[v]));
	const sharedPick = pickNames.find((v) => plainVars.has(v));
	const kinds = new Set(names.filter((n) => known.has(n)).map((n) => known.get(n).allowed));
	if (new Set(names).size !== names.length) out.allowDeny = 'A list is named twice.';
	else if (pickNames.length && names.length > 1) out.allowDeny = 'A list chosen at install must be the only list.';
	else if (missing.length) out.allowDeny = `${missing.join(', ')} is not a list of an allow / deny package in this namespace. Remove it.`;
	else if (badPick) out.allowDeny = `@@${badPick}@@ is not a variable that lets the installer pick a list. Remove it.`;
	else if (sharedPick) out.allowDeny = `@@${sharedPick}@@ is also used as a variable in the content. Rename it there or remove the installer pick.`;
	else if (kinds.size > 1) out.allowDeny = 'Use only allow lists or only deny lists on one asset.';
	return out;
}

// whether an error set from assetMetaErrors holds any problem.
export function hasErrors(e) {
	return !!(e.name || e.description || e.contentType || e.headerList || e.allowDeny || e.headers.some((h) => h.key || h.value));
}

// the installer pick variable an allowDeny entry names, or empty for a list name.
export function pickVarName(entry) {
	const m = String(entry || '').match(/^@@([A-Z_][A-Z0-9_]{0,63})@@$/);
	return m ? m[1] : '';
}

// a character a block scalar cannot hold as written: a line break other than
// a newline, which the Go YAML parser would start a new line at, a control
// character or the byte order mark.
// eslint-disable-next-line no-control-regex
const BLOCK_UNSAFE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u2028\u2029\ufeff]/;

// the one list of an allow / deny package, as an allowDenies block entry at the
// list item indent.
// A multi line value is written as a block scalar, or as a double quoted scalar
// with escapes when it holds a character a block scalar cannot.
export function listYaml(name, l) {
	const blk = (key, val) => {
		const text = String(val || '')
			.trim()
			.split('\n')
			.map((x) => x.trim())
			.join('\n');
		if (!text) return '';
		if (BLOCK_UNSAFE.test(text)) return `    ${key}: ${yamlStr(text)}\n`;
		return `    ${key}: |\n` + text.split('\n').map((x) => `      ${x}`).join('\n') + '\n';
	};
	const rules = (l.headerRules || []).filter((h) => h.keyRegex.trim() || h.valueRegex.trim());
	const headerBlk = rules.length
		? `    headers:\n` +
			rules.map((h) => `      - keyRegex: ${yamlStr(h.keyRegex)}\n        valueRegex: ${yamlStr(h.valueRegex)}`).join('\n') +
			'\n'
		: '';
	return (
		`  - name: ${yamlStr(name)}\n    allowed: ${!!l.allowed}\n` +
		blk('cidrs', l.cidrs) +
		blk('countryCodes', l.countryCodes) +
		blk('asns', l.asns) +
		headerBlk +
		blk('ja4', l.ja4)
	);
}

// the assets block for every asset with a setting. path is the asset path under
// assets/. every scalar goes through yamlStr so a colon or a leading @ cannot
// break the YAML.
export function assetsYaml(assets) {
	const items = assets.filter(hasAssetMeta);
	if (!items.length) return '';
	let y = 'assets:\n';
	for (const a of items) {
		y += `  - path: ${yamlStr(a.filename)}\n`;
		if (a.name.trim()) y += `    name: ${yamlStr(a.name.trim())}\n`;
		if (a.description.trim()) y += `    description: ${yamlStr(a.description.trim())}\n`;
		if (a.contentType.trim()) y += `    contentType: ${yamlStr(a.contentType.trim())}\n`;
		const hs = usedHeaders(a);
		if (hs.length)
			y += '    headers:\n' + hs.map((h) => `      - key: ${yamlStr(String(h.key).trim())}\n        value: ${yamlStr(h.value)}\n`).join('');
		if (a.allowDeny.length) y += '    allowDeny:\n' + a.allowDeny.map((n) => `      - ${yamlStr(n)}\n`).join('');
	}
	return y;
}

// read the assets block back from a data.yaml. The failsafe schema keeps every
// scalar as the text it was written as, so a value such as 0123 or true loads
// back unchanged. A data.yaml that does not parse gives nothing rather than half
// the settings.
export function parseAssetMeta(text) {
	let doc;
	try {
		doc = jsyaml.load(String(text || ''), { schema: jsyaml.FAILSAFE_SCHEMA });
	} catch (_) {
		return { assets: [] };
	}
	if (!doc || typeof doc !== 'object') return { assets: [] };
	const str = (v) => (typeof v === 'string' ? v : '');
	const arr = (v) => (Array.isArray(v) ? v : []);
	const assets = arr(doc.assets)
		.filter((a) => a && typeof a === 'object' && str(a.path))
		.map((a) => ({
			path: str(a.path),
			name: str(a.name),
			description: str(a.description),
			contentType: str(a.contentType),
			headers: arr(a.headers)
				.filter((h) => h && typeof h === 'object')
				.map((h) => ({ key: str(h.key), value: str(h.value) })),
			allowDeny: arr(a.allowDeny).filter((n) => typeof n === 'string')
		}));
	return { assets };
}
