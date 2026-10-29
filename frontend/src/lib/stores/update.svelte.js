// The last known software update status, shared so the sidebar notice and the
// settings Updates tab agree. The layout loads it once after sign in and the
// Updates tab replaces it after each check.
import { api } from '$lib/api/api.js';

let s = $state({ status: null });

export const updateState = s;

export function setUpdateStatus(status) {
	s.status = status ?? null;
}

// load the stored status without contacting GitHub. errors are ignored on
// purpose: the notice is a hint and must never get in the way.
export async function loadUpdateStatus() {
	try {
		const res = await api.update.status();
		if (res.ok && res.data) s.status = res.data;
	} catch (_) {
		/* ignore */
	}
}
