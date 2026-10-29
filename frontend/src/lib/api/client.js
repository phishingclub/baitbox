// In dev vite proxies the API to baitbox; in prod the Go backend serves both the
// SPA and the API.
import { goto } from '$app/navigation';
import { browser } from '$app/environment';
import { auth } from '../stores/auth.svelte.js';
import { toast } from '../stores/toast.svelte.js';

// debounce the network error toast so a burst of failed calls (a page loading
// several endpoints while the server restarts) shows one message.
let lastNetErrAt = 0;

async function request(method, path, body) {
	const opts = { method, headers: {}, credentials: 'same-origin' };
	if (body !== undefined) {
		opts.headers['Content-Type'] = 'application/json';
		opts.body = JSON.stringify(body);
	}
	let res;
	try {
		res = await fetch('/api/v1' + path, opts);
	} catch (e) {
		// the server is unreachable: tell the operator rather than let the page
		// look like an empty registry.
		if (browser && Date.now() - lastNetErrAt > 3000) {
			lastNetErrAt = Date.now();
			toast('Could not reach the server. Check your connection.', 'error');
		}
		return { ok: false, status: 0, data: null, error: 'network error' };
	}
	// session expired or missing: send the operator to login rather than leave
	// them on a page that looks broken or empty. The login call itself returns
	// 401 on wrong credentials and is handled locally, so it is excluded.
	if (res.status === 401 && path !== '/login' && browser) {
		auth.clear();
		goto('/login');
	}
	let data = null;
	try {
		data = await res.json();
	} catch (_) {
		/* not json */
	}
	// the operator still has an issued password: the server allows nothing but
	// the change, so send them to the setup page.
	if (res.status === 403 && data?.passwordChangeRequired && browser) {
		goto('/setup');
	}
	// a throttled attempt (429) says how many seconds to wait before the next one.
	const retryAfter = res.status === 429 ? parseInt(res.headers.get('Retry-After') || '', 10) || 0 : 0;
	return {
		ok: res.ok,
		status: res.status,
		data,
		retryAfter,
		error: (data && data.error) || (!res.ok ? res.statusText : '')
	};
}

export const get = (p) => request('GET', p);
export const post = (p, b) => request('POST', p, b ?? {});
export const patch = (p, b) => request('PATCH', p, b ?? {});
export const del = (p) => request('DELETE', p);
