// Shared vim keybinding preference. The toggle buttons in the editor toolbars and
// the global Ctrl+Alt+V shortcut all drive this one value, so every open editor
// switches together. The choice persists per browser.
function createVimPref() {
	let enabled = $state(false);
	try {
		enabled = localStorage.getItem('bs-vim') === '1';
	} catch (_) {
		/* ignore */
	}
	function persist() {
		try {
			localStorage.setItem('bs-vim', enabled ? '1' : '0');
		} catch (_) {
			/* ignore */
		}
	}
	return {
		get enabled() {
			return enabled;
		},
		set(v) {
			enabled = !!v;
			persist();
		},
		toggle() {
			enabled = !enabled;
			persist();
		}
	};
}

export const vimPref = createVimPref();
