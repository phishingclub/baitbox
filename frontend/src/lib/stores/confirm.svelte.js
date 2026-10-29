// A styled, promise based confirm to replace the native confirm() dialog for
// destructive actions. A caller does:
//   if (!(await askConfirm({ title, body, confirmLabel }))) return;
// The single ConfirmDialog mounted in the layout renders this state and settles
// the promise with the operator's choice.

let s = $state({ open: false, title: 'Are you sure?', body: '', confirmLabel: 'Confirm' });
let resolver = null;

export const confirmState = s;

export function askConfirm(opts = {}) {
	// if a previous prompt is somehow still open, cancel it first
	if (resolver) {
		const r = resolver;
		resolver = null;
		r(false);
	}
	s.title = opts.title ?? 'Are you sure?';
	s.body = opts.body ?? '';
	s.confirmLabel = opts.confirmLabel ?? 'Confirm';
	s.open = true;
	return new Promise((res) => {
		resolver = res;
	});
}

export function settleConfirm(result) {
	if (!s.open) return;
	s.open = false;
	const r = resolver;
	resolver = null;
	if (r) r(result);
}
