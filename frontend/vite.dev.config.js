import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';
import basicSsl from '@vitejs/plugin-basic-ssl';

export default defineConfig({
	plugins: [sveltekit(), basicSsl()],
	server: {
		https: true,
		host: '0.0.0.0',
		port: 8113,
		proxy: {
			// the registry protocol goes to the registry listener (8112), as a consumer
			// reads it in production. The admin listener serves it only to a signed in
			// operator.
			'^/api/v1/(info|index|packages|previews)(/|$|\\?)': {
				target: 'https://registry.baitbox.test:8112',
				secure: false
			},
			// target the admin listener (8114) on the aliased hostname baitbox has a
			// cert for (certmagic only issues for the allowlisted registry/admin
			// hosts, not the bare service name); secure:false skips the dev
			// self signed pebble cert. The registry listener on 8112 has no admin routes.
			'/api/': { target: 'https://admin.baitbox.test:8114', secure: false, ws: true },
			// the export and import bundle routes live at the root, outside the API.
			'/admin/': { target: 'https://admin.baitbox.test:8114', secure: false },
			// the live preview echo endpoint, also at the root.
			'/preview': { target: 'https://admin.baitbox.test:8114', secure: false },
			// the package preview file server. match only the rawfile subpath so the
			// SPA keeps owning the package list and detail pages.
			'^/packages/[^/]+/[^/]+/[^/]+/rawfile/': {
				target: 'https://admin.baitbox.test:8114',
				secure: false
			}
		}
	}
});
