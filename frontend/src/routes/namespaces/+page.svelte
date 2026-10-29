<script>
	import { onMount } from 'svelte';
	import { api } from '$lib/api/api.js';
	import { toast } from '$lib/stores/toast.svelte.js';
	import { askConfirm } from '$lib/stores/confirm.svelte.js';
	import Skeleton from '$lib/components/Skeleton.svelte';
	import ColorPicker from '$lib/components/ColorPicker.svelte';
	import Help from '$lib/components/Help.svelte';
	import StatusPill from '$lib/components/StatusPill.svelte';
	import SortHeader from '$lib/components/SortHeader.svelte';
	import Pagination from '$lib/components/Pagination.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import RowMenu from '$lib/components/RowMenu.svelte';
	import Button from '$lib/components/Button.svelte';
	import Card from '$lib/components/Card.svelte';
	import ErrorCard from '$lib/components/ErrorCard.svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import Alert from '$lib/components/Alert.svelte';
	import { nsDotClass, nsDotStyle } from '$lib/utils/nsColor.js';

	let namespaces = $state([]);
	let total = $state(0);
	let loaded = $state(false);
	let refreshing = $state(false);
	let query = $state('');
	let form = $state({ name: '', description: '', visibility: 'private', color: '' });
	// a namespace name is a lowercase slug (a package is addressed as namespace/name)
	const nameValid = $derived(/^[a-z0-9][a-z0-9-]*$/.test(form.name));
	// warn before submit when a name on the current page is already taken, so the
	// operator fixes it inline. the server enforces uniqueness across the whole
	// registry and rejects a duplicate with a 409 regardless.
	const nameExists = $derived(
		!!form.name && nameValid && namespaces.some((n) => n.name.toLowerCase() === form.name.toLowerCase())
	);

	// server side paging, sort and search. only name is a server allowlisted sort
	// column; visibility, package count and download count are derived and not
	// server sortable, so their headers are plain. default: no sort, server order.
	const perPage = 50;
	let pageNum = $state(1);
	let sortKey = $state('');
	let sortDir = $state('asc');
	function sortBy(key) {
		if (sortKey === key) sortDir = sortDir === 'asc' ? 'desc' : 'asc';
		else {
			sortKey = key;
			sortDir = 'asc';
		}
		pageNum = 1;
		load();
	}

	// a new search resets to the first page and refetches, debounced so it does not
	// fire on every keystroke.
	let debounce;
	function onSearchInput() {
		clearTimeout(debounce);
		debounce = setTimeout(() => {
			pageNum = 1;
			load();
		}, 300);
	}
	function clearSearch() {
		query = '';
		pageNum = 1;
		load();
	}
	function gotoPage(n) {
		pageNum = n;
		load();
	}

	let editing = $state(null); // id being edited
	let edit = $state({ description: '', visibility: 'private', color: '' });

	// rename flow. renameImpact holds the fetched counts, or null while they load.
	let renameOpen = $state(false);
	let renameNs = $state(null);
	let renameName = $state('');
	let renameImpact = $state(null);
	let renameBusy = $state(false);
	// the new name follows the same slug rule as the create form.
	const renameValid = $derived(/^[a-z0-9][a-z0-9-]*$/.test(renameName));
	// another namespace already holds this name (case insensitive), so the server would
	// reject it with a 409. renameNs itself is excluded.
	const renameTaken = $derived(
		!!renameName && renameValid && namespaces.some((n) => n.id !== renameNs?.id && n.name.toLowerCase() === renameName.toLowerCase())
	);
	// typing back the current name is a no op.
	const renameUnchanged = $derived(renameName.toLowerCase() === (renameNs?.name.toLowerCase() ?? ''));
	const renameCanConfirm = $derived(renameValid && !renameTaken && !renameUnchanged && !renameBusy);

	let loadError = $state('');
	async function load() {
		if (loaded) refreshing = true;
		loadError = '';
		const res = await api.namespaces.list({ page: pageNum, perPage, sort: sortKey, dir: sortDir, q: query });
		if (res.ok) {
			namespaces = res.data.namespaces || [];
			total = res.data.total || 0;
		} else {
			loadError = res.error || 'Could not load namespaces';
		}
		loaded = true;
		refreshing = false;
	}
	onMount(load);

	// public namespaces exist only when registry.public is on in the config.
	// until the flag loads the public option stays hidden.
	let registryPublic = $state(false);
	let registryInfoLoaded = $state(false);
	onMount(async () => {
		const r = await api.instance();
		if (r.ok) registryPublic = !!r.data?.registryPublic;
		registryInfoLoaded = true;
	});

	async function create() {
		if (!form.name) {
			toast('Name is required', 'error');
			return;
		}
		if (!nameValid) {
			toast('Name must be a lowercase slug (a-z, 0-9, dashes)', 'error');
			return;
		}
		if (nameExists) {
			toast(`A namespace named ${form.name} already exists`, 'error');
			return;
		}
		const res = await api.namespaces.create(form);
		if (res.ok) {
			toast('Namespace created', 'success');
			form = { name: '', description: '', visibility: 'private', color: '' };
			await load();
		} else {
			toast(res.error || 'Failed to create', 'error');
		}
	}

	function startEdit(ns) {
		editing = ns.id;
		edit = {
			description: ns.description,
			visibility: registryPublic ? ns.visibility : 'private',
			color: ns.color ?? ''
		};
	}
	async function saveEdit(ns) {
		const res = await api.namespaces.update(ns.id, edit);
		if (res.ok) {
			toast('Saved', 'success');
			editing = null;
			await load();
		} else {
			toast(res.error || 'Failed to save', 'error');
		}
	}
	async function remove(ns) {
		if (!(await askConfirm({ title: 'Delete namespace', body: `Delete namespace "${ns.name}"? This cannot be undone.`, confirmLabel: 'Delete' }))) return;
		const res = await api.namespaces.remove(ns.id);
		if (res.ok) {
			toast('Namespace deleted', 'success');
			await load();
		} else {
			toast(res.error || 'Failed to delete', 'error');
		}
	}

	async function openRename(ns) {
		renameNs = ns;
		renameName = '';
		renameImpact = null;
		renameOpen = true;
		const res = await api.namespaces.renameImpact(ns.id);
		if (res.ok) renameImpact = res.data;
	}
	async function confirmRename() {
		renameBusy = true;
		const res = await api.namespaces.rename(renameNs.id, renameName.trim());
		if (res.ok) {
			toast('Namespace renamed', 'success');
			renameOpen = false;
			await load();
		} else {
			toast(res.error || 'Could not rename', 'error');
		}
		renameBusy = false;
	}
</script>

<PageHeader title="Namespaces">
	{#snippet help()}
		<Help title="Namespaces">
			<p>A namespace is the owner or scope of packages, like <code>acme-corp</code>. Packages are addressed as <code>namespace/name</code>.</p>
			{#if registryPublic}
				<p>Public namespaces can be installed by anyone; private ones require a read token.</p>
			{:else}
				<p>This registry is private, so every namespace needs a read token. Set <code>registry.public</code> in the config to allow public namespaces.</p>
			{/if}
		</Help>
	{/snippet}
</PageHeader>

{#if registryInfoLoaded && !registryPublic}
	<Alert variant="info" title="Private registry." class="mt-6">
		Every request to the registry needs a read token, so namespaces cannot be public. Set
		<code>registry.public</code> in the config to allow anonymous reads of public namespaces.
	</Alert>
{/if}

<Card class="mt-6">
	<h2 class="pc-card-title mb-3">New namespace</h2>
	<form onsubmit={(e) => { e.preventDefault(); create(); }} class="flex flex-wrap items-end gap-3">
		<label class="relative text-sm">
			<span class="pc-label">Name</span>
			<input bind:value={form.name} placeholder="acme-corp" class="pc-control mt-1 block {(form.name && !nameValid) || nameExists ? 'border-red-400 dark:border-red-700' : ''}" />
			{#if form.name && !nameValid}
				<span class="absolute left-0 top-full mt-1 block text-xs text-red-600 dark:text-red-400">Lowercase letters, numbers and dashes only.</span>
			{:else if nameExists}
				<span class="absolute left-0 top-full mt-1 block whitespace-nowrap text-xs text-red-600 dark:text-red-400">A namespace named {form.name} already exists.</span>
			{/if}
		</label>
		<label class="text-sm flex-1 min-w-48">
			<span class="pc-label">Description</span>
			<input bind:value={form.description} class="mt-1 block w-full rounded-md pc-control px-3 py-2" />
		</label>
		{#if registryPublic}
			<label class="text-sm">
				<span class="pc-label">Visibility</span>
				<select bind:value={form.visibility} class="mt-1 block rounded-md pc-control px-3 py-2">
					<option value="private">private</option>
					<option value="public">public</option>
				</select>
			</label>
		{/if}
		<div class="text-sm">
				<span class="pc-label">Color</span>
				<ColorPicker bind:value={form.color} />
			</div>
			<Button variant="primary" type="submit" disabled={!nameValid || nameExists}>Create</Button>
	</form>
</Card>

<Card padding="none" class="mt-6 overflow-hidden">
	{#if !loaded}
		<Skeleton rows={4} />
	{:else if loadError}
		<ErrorCard bare message={loadError} onretry={load} />
	{:else if total === 0 && !query.trim()}
		<EmptyState message="No namespaces yet. Create one above to start publishing packages." />
	{:else}
		<div class="border-b border-gray-100 dark:border-gray-800 p-3">
			<input
				bind:value={query}
				oninput={onSearchInput}
				aria-label="Search namespaces"
				placeholder="Search by name or description"
				class="w-full rounded-md pc-control px-3 py-2 text-sm"
			/>
		</div>
		{#if namespaces.length === 0}
			<EmptyState message={`No namespaces match "${query.trim()}".`}>
				<Button variant="neutral" size="xs" onclick={clearSearch}>Clear search</Button>
			</EmptyState>
		{:else}
		<div class="overflow-x-auto transition-opacity {refreshing ? 'opacity-50' : ''}"><table class="w-full text-sm">
			<thead class="bg-gray-50 dark:bg-gray-900 text-gray-700 dark:text-gray-200">
				<tr>
					<SortHeader label="Name" column="name" {sortKey} {sortDir} onsort={sortBy} />
					<th class="text-left px-4 py-2 font-medium">Visibility</th>
					<th class="text-left px-4 py-2 font-medium">Packages</th>
					<th class="text-left px-4 py-2 font-medium">Downloads</th>
					<th class="text-left px-4 py-2 font-medium">Description</th>
					<th class="px-4 py-2"></th>
				</tr>
			</thead>
			<tbody>
				{#each namespaces as ns (ns.id)}
					<tr class="border-t border-gray-100 dark:border-gray-800">
						<td class="px-4 py-3 font-medium">
							<span class="inline-flex items-center gap-2">
								<span class="h-2.5 w-2.5 shrink-0 rounded-full {nsDotClass(ns.color)}" style={nsDotStyle(ns.color)}></span>
								{ns.name}
							</span>
						</td>
						{#if editing === ns.id}
							<td class="px-4 py-3">
								{#if registryPublic}
									<select bind:value={edit.visibility} class="rounded-md pc-control px-2 py-1">
										<option value="private">private</option>
										<option value="public">public</option>
									</select>
								{:else}
									<StatusPill tone="private">private</StatusPill>
								{/if}
							</td>
							<td class="px-4 py-3 text-gray-800 dark:text-gray-100">{ns.packageCount ?? 0}</td>
							<td class="px-4 py-3 text-gray-800 dark:text-gray-100">{(ns.downloadCount ?? 0).toLocaleString()}</td>
							<td class="px-4 py-3">
								<input bind:value={edit.description} class="w-full rounded-md pc-control px-2 py-1" />
								<ColorPicker bind:value={edit.color} />
							</td>
							<td class="px-4 py-3 text-right whitespace-nowrap">
								<Button variant="blue" size="xs" onclick={() => saveEdit(ns)}>Save</Button>
								<Button variant="neutral" size="xs" onclick={() => (editing = null)} class="ml-3">Cancel</Button>
							</td>
						{:else}
							<td class="px-4 py-3">
								<StatusPill tone={ns.visibility === 'public' ? 'public' : 'private'}>{ns.visibility}</StatusPill>
							</td>
							<td class="px-4 py-3 text-gray-800 dark:text-gray-100">
								{#if ns.packageCount > 0}
									<a href={`/packages?namespace=${encodeURIComponent(ns.name)}`} class="hover:underline" title={`View packages in ${ns.name}`}>{ns.packageCount}</a>
								{:else}
									{ns.packageCount ?? 0}
								{/if}
							</td>
							<td class="px-4 py-3 text-gray-800 dark:text-gray-100">{(ns.downloadCount ?? 0).toLocaleString()}</td>
							<td class="px-4 py-3 text-gray-800 dark:text-gray-100">{ns.description}</td>
							<td class="px-4 py-3 text-right whitespace-nowrap">
								<RowMenu id={`ns-${ns.id}`} label={`Actions for ${ns.name}`}>
									<button type="button" onclick={() => openRename(ns)} class="pc-menu-item">Rename</button>
										<button type="button" onclick={() => startEdit(ns)} class="pc-menu-item">Edit</button>
									{#if ns.packageCount > 0}
										<button type="button" disabled class="pc-menu-item" title="Delete its packages first">Delete</button>
									{:else}
										<button type="button" onclick={() => remove(ns)} class="pc-menu-item-danger">Delete</button>
									{/if}
								</RowMenu>
							</td>
						{/if}
					</tr>
				{/each}
			</tbody>
		</table></div>
		<Pagination {pageNum} pageSize={perPage} {total} onchange={gotoPage} />
		{/if}
	{/if}
</Card>

<Modal bind:open={renameOpen} title="Rename namespace" size="md">
	<p class="text-sm text-gray-700 dark:text-gray-200">
		Renaming <span class="font-mono">{renameNs?.name}</span> changes the address of every package it owns.
	</p>
	<label class="relative mt-4 block text-sm">
		<span class="pc-label">New name</span>
		<input
			bind:value={renameName}
			placeholder={renameNs?.name}
			class="pc-control mt-1 block w-full {(renameName && !renameValid) || renameTaken ? 'border-red-400 dark:border-red-700' : ''}"
		/>
		{#if renameName && !renameValid}
			<span class="absolute left-0 top-full mt-1 block text-xs text-red-600 dark:text-red-400">Lowercase letters, numbers and dashes only.</span>
		{:else if renameTaken}
			<span class="absolute left-0 top-full mt-1 block whitespace-nowrap text-xs text-red-600 dark:text-red-400">A namespace named {renameName} already exists.</span>
		{/if}
	</label>
	<p class="mt-5 font-mono text-xs text-gray-500 dark:text-gray-400">
		{renameNs?.name}/… becomes {renameName || 'new-name'}/…
	</p>
	{#if renameImpact}
		<Alert variant="warning" class="mt-4">
			Old installs stop working. The {renameImpact.packages} package(s) here must be reinstalled from the new name.
			{#if renameImpact.externalDependents.length > 0}
				<span class="mt-2 block">
					These packages break until republished:
					<span class="mt-1 flex flex-wrap gap-1">
						{#each renameImpact.externalDependents as dep}
							<span class="rounded bg-gray-100 px-1.5 py-0.5 font-mono text-xs text-gray-700 dark:bg-gray-800 dark:text-gray-200">{dep}</span>
						{/each}
					</span>
				</span>
			{/if}
		</Alert>
	{/if}
	{#snippet footer()}
		<Button variant="neutral" onclick={() => (renameOpen = false)}>Cancel</Button>
		<Button variant="primary" onclick={confirmRename} disabled={!renameCanConfirm}>Rename</Button>
	{/snippet}
</Modal>
