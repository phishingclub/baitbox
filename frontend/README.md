# Bait Box admin (SPA)

SvelteKit + Svelte 5 + Tailwind single page app, served by the Go backend in
production (embedded) and by vite in dev. Talks to the backend JSON API under
`/api`. In dev the vite server runs on 8113 and proxies `/api` to the baitbox
admin listener on 8114 (the registry listener on 8112 has no admin routes).
