// apply the saved theme before first paint so there is no flash. a stored choice
// wins; otherwise follow the system preference. served from the app origin so it
// passes script-src 'self'; a classic blocking script so it runs before paint.
try {
	var m = localStorage.getItem('theme');
	var dark = m === 'dark' || ((m === 'system' || !m) && window.matchMedia('(prefers-color-scheme: dark)').matches);
	document.documentElement.classList.toggle('dark', dark);
} catch (e) {}
