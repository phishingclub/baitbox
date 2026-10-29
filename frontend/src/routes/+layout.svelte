<script>
	import '../app.css';
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { api } from '$lib/api/api.js';
	import { auth } from '$lib/stores/auth.svelte.js';
	import { theme } from '$lib/stores/theme.svelte.js';
	import { vimPref } from '$lib/stores/vim.svelte.js';
	import Toasts from '$lib/components/Toasts.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import BrandMark from '$lib/components/BrandMark.svelte';
	import { updateState, loadUpdateStatus, setUpdateStatus } from '$lib/stores/update.svelte.js';

	let { children } = $props();
	let ready = $state(false);
	let sidebarOpen = $state(false); // off canvas drawer on small screens

	// the rail is grouped: resource navigation (Content) is kept apart from account
	// and instance administration (Admin), with Packages first as the primary object.
	const navGroups = [
		{ label: '', items: [{ href: '/', label: 'Dashboard' }] },
		{
			label: 'Content',
			items: [
				{ href: '/packages', label: 'Packages' },
				{ href: '/namespaces', label: 'Namespaces' },
				{ href: '/tokens', label: 'Tokens' }
			]
		},
		{
			label: 'Admin',
			items: [{ href: '/settings', label: 'Settings' }]
		}
	];

	const isLogin = $derived($page.url.pathname === '/login');
	// first login setup runs full screen like login, without the navigation
	const isSetup = $derived($page.url.pathname === '/setup');

	// a per page browser tab title so multiple tabs and bookmarks are distinguishable. the
	// dynamic package detail page sets its own (ns/name) title, which overrides this one
	// since the last <title> in the head wins.
	const pageTitle = $derived.by(() => {
		const p = $page.url.pathname;
		const map = {
			'/login': 'Sign in',
			'/setup': 'Secure your account',
			'/': 'Dashboard',
			'/namespaces': 'Namespaces',
			'/tokens': 'Tokens',
			'/settings': 'Settings',
			'/packages': 'Packages',
			'/packages/new': 'New package',
			'/packages/bundle': 'New bundle'
		};
		const name = map[p] || (p.startsWith('/packages/') ? 'Package' : '');
		return name ? `${name} · Bait Box` : 'Bait Box';
	});
	// the current section name alone, for the mobile top bar: on a phone the sidebar is
	// off canvas, so showing the section (not a static wordmark) tells the operator where
	// they are. brand identity stays in the drawer header and the browser tab title.
	const sectionName = $derived(pageTitle === 'Bait Box' ? 'Bait Box' : pageTitle.replace(' · Bait Box', ''));

	// Escape closes the mobile nav drawer, matching the overlay click and the Escape
	// handling on the dialog and preview, so a keyboard user can dismiss it too.
	$effect(() => {
		if (!sidebarOpen) return;
		const onKey = (e) => {
			if (e.key === 'Escape') sidebarOpen = false;
		};
		window.addEventListener('keydown', onKey);
		return () => window.removeEventListener('keydown', onKey);
	});

	// Ctrl+Alt+V (Cmd+Alt+V on macOS) toggles vim keybindings in every editor at
	// once. Uses e.code so it works on any keyboard layout, and the capture phase so
	// an editor with vim active does not swallow it first.
	$effect(() => {
		const onKey = (e) => {
			if ((e.ctrlKey || e.metaKey) && e.altKey && e.code === 'KeyV') {
				e.preventDefault();
				vimPref.toggle();
			}
		};
		window.addEventListener('keydown', onKey, true);
		return () => window.removeEventListener('keydown', onKey, true);
	});

	// load the update status once per signed in operator, both on a fresh page
	// load and after signing in. not awaited, so it never holds up the page, and
	// cleared on sign out so the next operator does not see a stale notice.
	let updateLoadedFor = null;
	$effect(() => {
		const op = auth.operator;
		const key = op && !op.passwordChangeRequired ? op.username ?? '' : null;
		if (key === null) {
			updateLoadedFor = null;
			setUpdateStatus(null);
		} else if (key !== updateLoadedFor) {
			updateLoadedFor = key;
			loadUpdateStatus();
		}
	});

	onMount(async () => {
		theme.init();
		const res = await api.me();
		if (res.ok && res.data) {
			auth.set(res.data);
			if (res.data.passwordChangeRequired) {
				if (!isSetup) goto('/setup');
			} else if (isLogin) goto('/');
		} else {
			auth.clear();
			if (!isLogin) goto('/login');
		}
		ready = true;
	});

	async function logout() {
		await api.logout();
		auth.clear();
		goto('/login');
	}
</script>

<svelte:head><title>{pageTitle}</title></svelte:head>

<Toasts />
<ConfirmDialog />

{#if !ready}
	<div class="min-h-screen bg-gray-50 dark:bg-gray-900"></div>
{:else if isLogin || isSetup}
	{@render children()}
{:else}
	<div class="min-h-screen bg-gray-50 dark:bg-gray-900 text-gray-800 dark:text-gray-100">
		{#if sidebarOpen}
			<button
				class="fixed inset-0 z-30 bg-black/40 lg:hidden"
				aria-label="Close menu"
				onclick={() => (sidebarOpen = false)}
			></button>
		{/if}
		<div class="flex h-screen overflow-hidden">
			<aside
				id="nav-drawer"
				class="fixed inset-y-0 left-0 z-40 w-56 shrink-0 bg-gradient-to-b from-pc-darkblue to-active-blue text-blue-100 flex flex-col transform transition-transform lg:static lg:translate-x-0 {sidebarOpen
					? 'translate-x-0'
					: '-translate-x-full'}"
			>
				<div class="flex items-center gap-2 px-5 py-5 text-white">
					<BrandMark class="h-6 w-6 shrink-0" />
					<div class="font-phudu text-xl font-bold tracking-tight">Bait Box</div>
				</div>
				<nav class="flex-1 overflow-y-auto px-3">
					{#each navGroups as group}
						<div class="mt-4 first:mt-0">
							{#if group.label}
								<div class="px-3 pb-1 text-[11px] font-semibold uppercase tracking-wider text-blue-300/80">{group.label}</div>
							{/if}
							<div class="space-y-1">
								{#each group.items as item}
									<a
										href={item.href}
										onclick={() => (sidebarOpen = false)}
										class="relative block rounded-md px-3 py-2 text-sm font-medium transition-colors {$page.url.pathname === item.href
											? 'bg-white/15 text-white font-semibold'
											: 'text-blue-100 hover:bg-white/10 hover:text-white'}"
									>
										{#if $page.url.pathname === item.href}
											<span class="absolute left-0 top-1.5 bottom-1.5 w-1 rounded-full bg-white"></span>
										{/if}
										{item.label}
									</a>
								{/each}
							</div>
						</div>
					{/each}
				</nav>
				<div class="px-4 py-3 border-t border-white/10 text-xs text-blue-50">
					{#if updateState.status?.updateAvailable}
						<a
							href="/settings#updates"
							onclick={() => (sidebarOpen = false)}
							class="mb-3 flex items-center gap-2 rounded-md bg-white/10 px-2.5 py-1.5 font-medium text-white hover:bg-white/15"
						>
							<span class="h-1.5 w-1.5 shrink-0 rounded-full bg-emerald-400" aria-hidden="true"></span>
							<span class="truncate">Update available{updateState.status.latestVersion ? `: ${updateState.status.latestVersion}` : ''}</span>
						</a>
					{/if}
					<div class="mb-2 truncate font-medium text-blue-100">{auth.operator?.username ?? ''}</div>
					<div class="flex items-center justify-between gap-2">
						<button
							onclick={logout}
							class="rounded-md border border-white/20 px-2.5 py-1 font-medium text-white hover:bg-white/10"
							>Log out</button
						>
						<button
							onclick={() => theme.toggle()}
							aria-label="Toggle dark mode"
							title={theme.isDark ? 'Switch to light mode' : 'Switch to dark mode'}
							class="rounded-md border border-white/20 px-2 py-1 text-sm text-white hover:bg-white/10"
						>
							{theme.isDark ? '☀' : '☾'}
						</button>
					</div>
				</div>
			</aside>
			<div class="flex min-h-0 min-w-0 flex-1 flex-col">
				<header class="flex items-center gap-3 border-b border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-950 px-4 py-3 lg:hidden">
					<button
						onclick={() => (sidebarOpen = !sidebarOpen)}
						aria-label={sidebarOpen ? 'Close menu' : 'Open menu'}
						aria-expanded={sidebarOpen}
						aria-controls="nav-drawer"
						class="relative rounded-md border border-gray-200 dark:border-gray-700 px-2 py-1 text-lg leading-none hover:bg-gray-100 dark:hover:bg-gray-800"
					>
						☰
						{#if updateState.status?.updateAvailable}
							<!-- the sidebar is hidden on a phone, so a dot on the menu button hints at the update notice inside it -->
							<span class="absolute -right-1 -top-1 h-2.5 w-2.5 rounded-full bg-emerald-500 ring-2 ring-white dark:ring-gray-950" title="Update available"></span>
						{/if}
					</button>
					<span class="text-base font-bold tracking-tight">{sectionName}</span>
				</header>
				<main class="min-h-0 flex-1 overflow-auto">
					<div class="mx-auto max-w-7xl px-4 py-8 sm:px-6">
						{@render children()}
					</div>
				</main>
			</div>
		</div>
	</div>
{/if}
