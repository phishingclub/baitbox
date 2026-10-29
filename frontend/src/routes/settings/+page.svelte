<script>
	import { onMount, tick } from 'svelte';
	import Help from '$lib/components/Help.svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import Account from './panels/Account.svelte';
	import Users from './panels/Users.svelte';
	import Registry from './panels/Registry.svelte';
	import Updates from './panels/Updates.svelte';

	const tabs = [
		{ id: 'account', label: 'Account & security', component: Account },
		{ id: 'users', label: 'Users', component: Users },
		{ id: 'registry', label: 'Registry', component: Registry },
		{ id: 'updates', label: 'Updates', component: Updates }
	];

	let active = $state('account');
	let tabNav;
	const ActiveComponent = $derived((tabs.find((t) => t.id === active) || tabs[0]).component);

	function selectTab(id) {
		active = id;
		// switching tabs replaces the hash rather than pushing, so the back button
		// leaves settings instead of walking back through each visited tab.
		if (typeof history !== 'undefined') history.replaceState(history.state, '', `#${id}`);
	}

	function syncFromHash() {
		const hash = (typeof location !== 'undefined' ? location.hash : '').replace(/^#/, '');
		if (tabs.some((t) => t.id === hash)) {
			active = hash;
			// on a narrow screen the tab row scrolls, so bring the chosen tab into view
			tick().then(() => tabNav?.querySelector('[aria-current="page"]')?.scrollIntoView({ block: 'nearest', inline: 'nearest' }));
		}
	}

	onMount(() => {
		syncFromHash();
		window.addEventListener('hashchange', syncFromHash);
		return () => window.removeEventListener('hashchange', syncFromHash);
	});
</script>

<svelte:head><title>Settings · Bait Box</title></svelte:head>

<PageHeader title="Settings">
	{#snippet help()}
		<Help title="Settings">
			<p>Your operator account, the other operators who can sign in, registry operations (export, import, and connecting to Phishing Club), and <strong>Updates</strong> for installing new Bait Box releases, each on its own tab.</p>
		</Help>
	{/snippet}
</PageHeader>

<div class="mt-6 border-b border-gray-200 dark:border-gray-800">
	<nav bind:this={tabNav} class="-mb-px flex gap-1 overflow-x-auto" aria-label="Settings sections">
		{#each tabs as tab}
			<button
				type="button"
				onclick={() => selectTab(tab.id)}
				aria-current={active === tab.id ? 'page' : undefined}
				class="whitespace-nowrap border-b-2 px-4 py-2 text-sm font-semibold transition-colors {active === tab.id
					? 'border-cta-blue text-cta-blue dark:border-highlight-blue dark:text-highlight-blue'
					: 'border-transparent text-gray-700 hover:border-gray-300 hover:text-gray-900 dark:text-gray-200 dark:hover:border-gray-600 dark:hover:text-white'}"
			>
				{tab.label}
			</button>
		{/each}
	</nav>
</div>

<div class="mt-6">
	{#key active}
		<ActiveComponent />
	{/key}
</div>
