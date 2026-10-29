import { get, post, patch, del } from './client.js';

// Only keys with a value are sent, so the server applies its defaults for the
// rest. sort must be an allowlisted column or the server answers 400.
function listQuery(opts = {}) {
	const p = new URLSearchParams();
	if (opts.page) p.set('page', opts.page);
	if (opts.perPage) p.set('perPage', opts.perPage);
	if (opts.sort) p.set('sort', opts.sort);
	if (opts.dir) p.set('dir', opts.dir);
	if (opts.q != null && String(opts.q).trim() !== '') p.set('q', String(opts.q).trim());
	if (opts.type) p.set('type', opts.type);
	if (opts.namespace) p.set('namespace', opts.namespace);
	if (opts.tag) p.set('tag', opts.tag);
	const qs = p.toString();
	return qs ? `?${qs}` : '';
}

export const api = {
	login: (username, password, code) => post('/login', { username, password, code }),
	passkeyLoginBegin: (username, password) => post('/login/passkey/begin', { username, password }),
	passkeyLoginFinish: (cred) => post('/login/passkey/finish', cred),
	logout: () => post('/logout'),
	me: () => get('/me'),
	instance: () => get('/admin/instance'),
	disableAdmin: (password) => post('/admin/instance/disable-admin', { password }),
	changePassword: (current, next, username) => post('/admin/change-password', { current, next, username }),
	mfa: {
		status: () => get('/admin/mfa'),
		begin: () => post('/admin/mfa/begin'),
		confirm: (code) => post('/admin/mfa/confirm', { code }),
		disable: (code) => post('/admin/mfa/disable', { code })
	},
	// step up: a fresh proof of identity (TOTP code, passkey, or the password when
	// no second factor exists) that lets this session make one second factor change.
	stepUp: {
		status: () => get('/admin/stepup'),
		verify: (body) => post('/admin/stepup', body),
		passkeyBegin: () => post('/admin/stepup/passkey/begin'),
		passkeyFinish: (cred) => post('/admin/stepup/passkey/finish', cred)
	},
	passkeys: {
		list: () => get('/admin/passkeys'),
		registerBegin: () => post('/admin/passkeys/register/begin'),
		registerFinish: (name, cred) => post(`/admin/passkeys/register/finish?name=${encodeURIComponent(name)}`, cred),
		remove: (id) => del('/admin/passkeys/' + id)
	},
	stats: () => get('/admin/stats'),
	// software update: status reads the stored result, check asks GitHub now,
	// run installs the latest signed release and restarts the service.
	update: {
		status: () => get('/admin/update'),
		check: () => post('/admin/update/check'),
		run: () => post('/admin/update/run')
	},
	operators: {
		list: () => get('/admin/operators'),
		create: (username, password) => post('/admin/operators', { username, password }),
		remove: (id) => del('/admin/operators/' + id)
	},

	namespaces: {
		list: (opts) => get('/admin/namespaces' + listQuery(opts)),
		create: (d) => post('/admin/namespaces', d),
		update: (id, d) => patch('/admin/namespaces/' + id, d),
		renameImpact: (id) => get('/admin/namespaces/' + id + '/rename-impact'),
		rename: (id, newName) => post('/admin/namespaces/' + id + '/rename', { newName }),
		remove: (id) => del('/admin/namespaces/' + id)
	},

	tokens: {
		list: () => get('/admin/tokens'),
		create: (d) => post('/admin/tokens', d),
		update: (id, d) => patch('/admin/tokens/' + id, d),
		revoke: (id) => post('/admin/tokens/' + id + '/revoke'),
		remove: (id) => del('/admin/tokens/' + id)
	},

	packages: {
		list: (opts) => get('/admin/packages' + listQuery(opts)),
		detail: (ns, name) => get(`/admin/packages/${ns}/${name}`),
		dependents: (ns, name) => get(`/admin/packages/${ns}/${name}/dependents`),
		source: (ns, name, version) => get(`/admin/packages/${ns}/${name}/versions/${version}/source`),
		author: (d) => post('/admin/packages', d),
		move: (ns, name, toNamespace, newName) => post(`/admin/packages/${ns}/${name}/move`, { toNamespace, newName }),
		updateMeta: (ns, name, meta) => patch(`/admin/packages/${ns}/${name}/meta`, meta),
		remove: (ns, name) => del(`/admin/packages/${ns}/${name}`),
		yank: (ns, name, version, yanked) =>
			post(`/admin/packages/${ns}/${name}/versions/${version}/yank`, { yanked }),
		removeVersion: (ns, name, version) =>
			del(`/admin/packages/${ns}/${name}/versions/${version}`),
		// package meta preview images (not shipped content assets)
		addPreview: (ns, name, content) => post(`/admin/packages/${ns}/${name}/previews`, { content }),
		removePreview: (ns, name, sha) => del(`/admin/packages/${ns}/${name}/previews/${sha}`),
		reorderPreviews: (ns, name, order) =>
			patch(`/admin/packages/${ns}/${name}/previews/order`, { order })
	},

	drafts: {
		list: () => get('/admin/drafts'),
		save: (d) => post('/admin/drafts', d),
		get: (ns, name) => get(`/admin/drafts/${ns}/${name}`),
		remove: (ns, name) => del(`/admin/drafts/${ns}/${name}`)
	},

	tags: {
		list: () => get('/admin/tags'),
		setColor: (name, color) => post('/admin/tags', { name, color })
	}
};
