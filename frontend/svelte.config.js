import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
export default {
	preprocess: vitePreprocess(),
	kit: {
		adapter: adapter({ assets: 'build', fallback: 'index.html', precompress: false, strict: true }),
		alias: { $lib: './src/lib' },
		// hash mode lets SvelteKit hash its own inline bootstrap script, so the app
		// boots under script-src 'self' with no unsafe-inline. SvelteKit bakes the
		// policy and the matching hash into a meta tag in index.html; the Go server
		// lifts that into a response header. style-src keeps unsafe-inline because
		// Monaco and Svelte inject styles at runtime that cannot be hashed. blob: is
		// allowed only for workers, never for script. frame-ancestors and form-action
		// cannot be set from a meta tag, so the Go security headers add them.
		csp: {
			mode: 'hash',
			directives: {
				'default-src': ['self'],
				'script-src': ['self'],
				'style-src': ['self', 'unsafe-inline'],
				'img-src': ['self', 'data:'],
				'font-src': ['self', 'data:'],
				'connect-src': ['self'],
				'worker-src': ['self', 'blob:'],
				'frame-src': ['self'],
				'object-src': ['none'],
				'base-uri': ['self']
			}
		}
	}
};
