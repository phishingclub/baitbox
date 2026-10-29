<script>
	import { onMount } from 'svelte';
	import { api } from '$lib/api/api.js';
	import { typeLabel } from '$lib/utils/packageType.js';
	import { nsDotClass, nsDotStyle } from '$lib/utils/nsColor.js';
	import Help from '$lib/components/Help.svelte';
	import StatusPill from '$lib/components/StatusPill.svelte';
	import Button from '$lib/components/Button.svelte';
	import Card from '$lib/components/Card.svelte';
	import StatTile from '$lib/components/StatTile.svelte';
	import ErrorCard from '$lib/components/ErrorCard.svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';

	let stats = $state(null);
	let loaded = $state(false);
	let packages = $state([]);
	let loadError = $state('');
	let registryPublic = $state(false);
	// a failed load must not look like a fresh, empty registry (all zeros + "Get
	// started"), which would alarm an operator who actually has content. the stats
	// call drives those counts, so treat its failure as the dashboard load error.
	async function load() {
		loadError = '';
		// the dashboard derives its "recent" and "most installed" lists in the browser,
		// so it needs the whole registry, not one server page. ask for the max page.
		const [s, p, inst] = await Promise.all([
			api.stats(),
			api.packages.list({ perPage: 200 }),
			api.instance()
		]);
		if (s.ok) stats = s.data;
		if (inst.ok) registryPublic = !!inst.data?.registryPublic;
		else loadError = s.error || 'Could not load the dashboard';
		if (p.ok) packages = p.data.packages;
		loaded = true;
	}
	onMount(load);

	// the five most recently touched packages, newest first, for a quick glance
	// at registry activity. packages without a timestamp sort to the bottom.
	const recent = $derived(
		packages
			.slice()
			.sort((a, b) => new Date(b.updatedAt || 0) - new Date(a.updatedAt || 0))
			.slice(0, 5)
	);

	// the most installed packages, for an at a glance sense of what content is
	// actually used. only shown when something has been installed.
	const mostInstalled = $derived(
		packages
			.filter((p) => (p.downloadCount ?? 0) > 0)
			.sort((a, b) => (b.downloadCount ?? 0) - (a.downloadCount ?? 0))
			.slice(0, 5)
	);

	function fmtDate(s) {
		if (!s) return '';
		const d = new Date(s);
		if (isNaN(d)) return '';
		return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
	}

	const cards = $derived([
		{ label: 'Namespaces', n: stats?.Namespaces ?? 0 },
		{ label: 'Packages', n: stats?.Packages ?? 0 },
		{ label: 'Versions', n: stats?.Versions ?? 0 },
		{ label: 'Downloads', n: stats?.Downloads ?? 0 }
	]);

	const hasNamespace = $derived((stats?.Namespaces ?? 0) > 0);
	const hasPackage = $derived((stats?.Packages ?? 0) > 0);
	const hasToken = $derived((stats?.Tokens ?? 0) > 0);
	const setUp = $derived(hasNamespace && hasPackage);

	// the onboarding checklist is dismissable and stays dismissed (per browser). an
	// operator past setup does not want it reappearing every visit.
	let dismissed = $state(false);
	onMount(() => {
		try {
			dismissed = localStorage.getItem('bs-onboarding-dismissed') === '1';
		} catch (_) {
			/* ignore */
		}
	});
	function dismiss() {
		dismissed = true;
		try {
			localStorage.setItem('bs-onboarding-dismissed', '1');
		} catch (_) {
			/* ignore */
		}
	}

	// a short, state aware path for a new operator. the first two steps flip to
	// done from the live counts; the last two are always available actions.
	const steps = $derived([
		{
			title: 'Create a namespace',
			href: '/namespaces',
			cta: 'Create namespace',
			done: hasNamespace
		},
		{
			title: 'Publish your first package',
			href: '/packages/new',
			cta: 'New package',
			done: hasPackage
		},
		{
			title: 'Create a read token',
			href: '/tokens',
			cta: 'Manage tokens',
			done: hasToken
		},
		{
			title: 'Connect from Phishing Club',
			href: '/settings#registry',
			cta: 'Open registry settings',
			done: false
		}
	]);
</script>

<PageHeader title="Dashboard">
	{#snippet help()}
		<Help title="About Bait Box">
			<p>Bait Box is a content registry. You author packages here and publish versions; Phishing Club connects to the registry and installs them.</p>
			<p><strong>Namespaces</strong> are the owner or scope of packages, like <code>acme-corp</code>. A package is addressed as <code>namespace/name</code>.{#if registryPublic} Public namespaces install without a token; private ones need a read token.{/if}</p>
			<p><strong>Packages</strong> are versioned content: emails, landing pages, assets, scripts, report templates, AiTM proxy configs, remote browser automations, attachments and allow or deny lists.</p>
			<p><strong>Tokens</strong> are read tokens: a connected Phishing Club needs one to read the registry{#if registryPublic}, except for public namespaces{/if}. The web UI uses your operator login, not a token. Authoring and publishing happen here in the admin area.</p>
			<p>To install from Phishing Club, open the <strong>Library</strong> page, add this registry with <strong>Add Bait Box</strong>, then browse and install.</p>
		</Help>
	{/snippet}
</PageHeader>

{#if loaded && loadError}
	<ErrorCard message={loadError} onretry={load} class="mt-6" />
{/if}

{#if !loadError}
	<div class="mt-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
		{#each cards as c}
			<StatTile value={c.n.toLocaleString()} label={c.label} />
		{/each}
	</div>
{/if}

{#if loaded && !loadError && !dismissed}
	<Card padding="lg" class="mt-8">
		<div class="flex items-center justify-between gap-3">
			<h2 class="text-lg font-semibold">{setUp ? 'You are set up' : 'Get started'}</h2>
			<div class="flex items-center gap-2">
				{#if setUp}
					<StatusPill tone="active">registry ready</StatusPill>
				{/if}
				<button type="button" onclick={dismiss} title="Dismiss" aria-label="Dismiss getting started" class="rounded-md border border-gray-300 px-2 py-1 text-xs font-medium text-gray-700 hover:bg-gray-50 dark:border-gray-700 dark:text-gray-200 dark:hover:bg-gray-900">Dismiss</button>
			</div>
		</div>
		{#if setUp}
			<p class="mt-2 text-sm text-gray-700 dark:text-gray-200">
				Your registry has content. Keep publishing packages, or connect it to Phishing Club to install from it.
			</p>
		{/if}
		<ol class="mt-4 space-y-3">
			{#each steps as s, i}
				<li class="flex items-start gap-3">
					<span
						class="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-xs font-semibold {s.done
							? 'bg-emerald-500 text-white'
							: 'bg-gray-100 text-gray-700 dark:bg-gray-800 dark:text-gray-200'}"
					>
						{s.done ? '✓' : i + 1}
					</span>
					<div class="min-w-0 flex-1">
						<div class="flex flex-wrap items-center gap-2">
							<span class="text-sm font-medium {s.done ? 'text-gray-700 dark:text-gray-200' : ''}">{s.title}</span>
						</div>
					</div>
					{#if !s.done}
						<Button href={s.href} variant="primary" class="shrink-0">{s.cta}</Button>
					{/if}
				</li>
			{/each}
		</ol>
	</Card>
{/if}

{#if loaded && !loadError && recent.length > 0}
	<Card padding="none" class="mt-6 overflow-hidden">
		<div class="flex items-center justify-between border-b border-gray-100 dark:border-gray-800 p-4">
			<h2 class="text-lg font-semibold">Recently updated</h2>
			<a href="/packages" class="text-sm font-medium text-cta-blue hover:text-active-blue">All packages</a>
		</div>
		<ul class="divide-y divide-gray-200 dark:divide-gray-800">
			{#each recent as p (p.namespace + '/' + p.name)}
				<li>
					<a
						href="/packages/{p.namespace}/{p.name}"
						class="flex items-center gap-3 px-4 py-2.5 hover:bg-gray-50 dark:hover:bg-gray-900"
					>
						<span class="flex min-w-0 flex-1 items-center gap-2 truncate">
							<span class="h-2 w-2 shrink-0 rounded-full {nsDotClass(p.namespaceColor)}" style={nsDotStyle(p.namespaceColor)}></span>
							<span class="truncate"><span class="text-gray-700 dark:text-gray-200">{p.namespace}/</span><span class="font-medium">{p.name}</span></span>
						</span>
						<span class="shrink-0 inline-flex items-center rounded px-2 py-0.5 text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-100">{typeLabel(p.type)}</span>
						<span class="shrink-0 whitespace-nowrap text-xs text-gray-500 dark:text-gray-400">{fmtDate(p.updatedAt)}</span>
					</a>
				</li>
			{/each}
		</ul>
	</Card>
{/if}

{#if loaded && !loadError && mostInstalled.length > 0}
	<Card padding="none" class="mt-6 overflow-hidden">
		<div class="flex items-center justify-between border-b border-gray-100 dark:border-gray-800 p-4">
			<h2 class="text-lg font-semibold">Most installed</h2>
			<a href="/packages" class="text-sm font-medium text-cta-blue hover:text-active-blue">All packages</a>
		</div>
		<ul class="divide-y divide-gray-200 dark:divide-gray-800">
			{#each mostInstalled as p (p.namespace + '/' + p.name)}
				<li>
					<a
						href="/packages/{p.namespace}/{p.name}"
						class="flex items-center gap-3 px-4 py-2.5 hover:bg-gray-50 dark:hover:bg-gray-900"
					>
						<span class="flex min-w-0 flex-1 items-center gap-2 truncate">
							<span class="h-2 w-2 shrink-0 rounded-full {nsDotClass(p.namespaceColor)}" style={nsDotStyle(p.namespaceColor)}></span>
							<span class="truncate"><span class="text-gray-700 dark:text-gray-200">{p.namespace}/</span><span class="font-medium">{p.name}</span></span>
						</span>
						<span class="shrink-0 inline-flex items-center rounded px-2 py-0.5 text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-100">{typeLabel(p.type)}</span>
						<span class="shrink-0 whitespace-nowrap text-xs tabular-nums text-gray-500 dark:text-gray-400">{(p.downloadCount ?? 0).toLocaleString()} {p.downloadCount === 1 ? 'install' : 'installs'}</span>
					</a>
				</li>
			{/each}
		</ul>
	</Card>
{/if}
