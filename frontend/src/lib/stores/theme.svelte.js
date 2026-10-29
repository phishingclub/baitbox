// Theme preference: 'light', 'dark', or 'system'. The resolved dark state
// drives the `dark` class on the document, matched by Tailwind's class strategy.
// An early script in app.html applies the same rule before hydration.
function createTheme() {
	let mode = $state('system');

	function systemDark() {
		try {
			return window.matchMedia('(prefers-color-scheme: dark)').matches;
		} catch (_) {
			return false;
		}
	}
	function resolvedDark() {
		return mode === 'dark' || (mode === 'system' && systemDark());
	}
	function apply() {
		try {
			document.documentElement.classList.toggle('dark', resolvedDark());
		} catch (_) {
			/* no document */
		}
	}
	return {
		get mode() {
			return mode;
		},
		get isDark() {
			return resolvedDark();
		},
		init() {
			try {
				const saved = localStorage.getItem('theme');
				if (saved === 'light' || saved === 'dark' || saved === 'system') mode = saved;
			} catch (_) {
				/* storage blocked */
			}
			apply();
		},
		set(m) {
			mode = m;
			try {
				localStorage.setItem('theme', m);
			} catch (_) {
				/* storage blocked */
			}
			apply();
		},
		toggle() {
			this.set(resolvedDark() ? 'light' : 'dark');
		}
	};
}

export const theme = createTheme();
