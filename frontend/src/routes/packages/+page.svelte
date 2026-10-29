<script>
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { api } from '$lib/api/api.js';
	import { toast } from '$lib/stores/toast.svelte.js';
	import { askConfirm } from '$lib/stores/confirm.svelte.js';
	import ImportResult from '$lib/components/ImportResult.svelte';
	import { importSummary, importNeedsDetail } from '$lib/utils/importSummary.js';
	import Skeleton from '$lib/components/Skeleton.svelte';
	import Help from '$lib/components/Help.svelte';
	import StatusPill from '$lib/components/StatusPill.svelte';
	import SortHeader from '$lib/components/SortHeader.svelte';
	import Pagination from '$lib/components/Pagination.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import Button from '$lib/components/Button.svelte';
	import Card from '$lib/components/Card.svelte';
	import ErrorCard from '$lib/components/ErrorCard.svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import Select from '$lib/components/Select.svelte';
	import { typeLabel } from '$lib/utils/packageType.js';
	import { nsDotClass, nsDotStyle, tagChipClass, tagChipStyle } from '$lib/utils/nsColor.js';

	let packages = $state([]);
	let total = $state(0);
	let drafts = $state([]);
	let loaded = $state(false);
	let refreshing = $state(false);
	let loadError = $state('');
	let query = $state('');

	// server backed filters, combined with the search and pagination. each is an exact
	// match the server applies: type, namespace name and a whole tag. selecting or
	// clearing any one resets to the first page and refetches.
	let typeFilter = $state('');
	let nsFilter = $state('');
	let tagFilter = $state('');
	// namespaces and tags fill the filter controls. namespaces are fetched small (the
	// select stays usable); tags are every tag a package carries, with its color if set.
	let namespaceOptions = $state([{ value: '', label: 'All namespaces' }]);
	let tags = $state([]); // {name, color}
	const hasActiveFilters = $derived(!!typeFilter || !!nsFilter || !!tagFilter);

	// the known package types, shown in the type filter with their friendly labels.
	const typeOptions = [
		{ value: '', label: 'All types' },
		...['page', 'email', 'domain', 'script', 'proxy', 'remotebrowser', 'allowdeny', 'smtp', 'webhook', 'oauthprovider', 'apisender', 'asset', 'attachment', 'reporttemplate', 'bundle', 'template'].map((t) => ({ value: t, label: typeLabel(t) }))
	];

	// server side paging, sort and search: the registry can grow large, so a page
	// change, sort or search is a fresh query rather than a client slice. only the
	// columns the server allowlists may be sent as sort; namespace and visibility
	// are derived from the namespace join and are not server sortable.
	const perPage = 50;
	let pageNum = $state(1);
	// default to most recently updated first, the most useful view for managing.
	let sortKey = $state('updated_at');
	let sortDir = $state('desc');

	// a failed load must not look like an empty registry, or an operator whose session
	// dropped would think their packages vanished. track the error and offer a retry.
	async function load() {
		if (loaded) refreshing = true;
		loadError = '';
		syncURL();
		const res = await api.packages.list({ page: pageNum, perPage, sort: sortKey, dir: sortDir, q: query, type: typeFilter, namespace: nsFilter, tag: tagFilter });
		if (res.ok) {
			packages = res.data.packages || [];
			total = res.data.total || 0;
		} else {
			loadError = res.error || 'Could not load packages';
		}
		loaded = true;
		refreshing = false;
	}

	// reflect the current filters, search, sort and page in the URL so the view is
	// shareable and a namespace drill down link lands already filtered. replaceState keeps
	// it out of the back history; the page does not refetch off the URL, so no loop.
	function syncURL() {
		const p = new URLSearchParams();
		if (query.trim()) p.set('q', query.trim());
		if (typeFilter) p.set('type', typeFilter);
		if (nsFilter) p.set('namespace', nsFilter);
		if (tagFilter) p.set('tag', tagFilter);
		if (pageNum > 1) p.set('page', pageNum);
		const qs = p.toString();
		goto(qs ? `?${qs}` : $page.url.pathname, { replaceState: true, keepFocus: true, noScroll: true });
	}

	// a filter change always starts over at the first page.
	function onTypeFilter(v) {
		typeFilter = v;
		pageNum = 1;
		load();
	}
	function onNamespaceFilter(v) {
		nsFilter = v;
		pageNum = 1;
		load();
	}
	// clicking a tag chip sets the tag filter; clicking the active one clears it.
	function toggleTag(name) {
		tagFilter = tagFilter === name ? '' : name;
		pageNum = 1;
		load();
	}
	function clearFilters() {
		typeFilter = '';
		nsFilter = '';
		tagFilter = '';
		query = '';
		pageNum = 1;
		load();
	}
	async function loadDrafts() {
		const res = await api.drafts.list();
		if (res.ok) drafts = res.data.drafts || [];
	}
	async function discardDraft(d) {
		const res = await api.drafts.remove(d.namespace, d.name);
		if (res.ok) drafts = drafts.filter((x) => !(x.namespace === d.namespace && x.name === d.name));
	}

	// a new search resets to the first page and refetches; debounced so it does not
	// fire on every keystroke.
	let debounce;
	function onSearchInput() {
		clearTimeout(debounce);
		debounce = setTimeout(() => {
			pageNum = 1;
			load();
		}, 300);
	}
	// a click anywhere on a row opens the package. clicks on a link inside the row are
	// left to the link so the router handles it once (and ctrl or middle click still
	// open a new tab).
	function openRow(e, p) {
		if (e.target instanceof Element && e.target.closest('a')) return;
		goto(`/packages/${p.namespace}/${p.name}`);
	}

	function gotoPage(n) {
		pageNum = n;
		load();
	}
	// clicking a header sorts by its server column and toggles direction; a new
	// column resets to the first page.
	function sortBy(key) {
		if (sortKey === key) sortDir = sortDir === 'asc' ? 'desc' : 'asc';
		else {
			sortKey = key;
			// numeric and date columns default descending, text columns ascending.
			sortDir = key === 'download_count' || key === 'updated_at' ? 'desc' : 'asc';
		}
		pageNum = 1;
		load();
	}

	// import a single package bundle exported from another Bait Box. It runs the same
	// restore path as the whole registry import: existing rows are kept, new ones are
	// added, and every version's archive integrity is reverified before it is stored.
	let importing = $state(false);
	// the import result: a toast for a plain add, and the detail dialog when the
	// import upgraded, skipped or refused existing packages.
	let importResult = $state(null);
	let importResultOpen = $state(false);
	function showImportResult(data) {
		toast(importSummary(data), data?.refused?.length ? 'error' : 'success');
		if (importNeedsDetail(data)) {
			importResult = data;
			importResultOpen = true;
		}
	}
	let importInput;
	async function doImportPackage(e) {
		const file = e.target.files?.[0];
		if (!file) return;
		const ok = await askConfirm({
			title: 'Import package bundle',
			body: `Import "${file.name}" into this registry? An existing package, version or namespace with the same name is kept; new rows and blobs are added.`,
			confirmLabel: 'Import'
		});
		if (!ok) {
			importInput.value = '';
			return;
		}
		importing = true;
		try {
			const res = await fetch('/admin/import-package', {
				method: 'POST',
				credentials: 'same-origin',
				headers: { 'Content-Type': 'application/gzip' },
				body: file
			});
			let data = null;
			try {
				data = await res.json();
			} catch (_) {
				/* not json */
			}
			if (res.ok) {
				showImportResult(data);
				await load();
			} else {
				toast((data && data.error) || 'Import failed', 'error');
			}
		} catch (_) {
			toast('Import failed', 'error');
		} finally {
			importing = false;
			importInput.value = '';
		}
	}


	// fill the filter selects. namespaces drive the namespace filter; the tags in use,
	// colored where a color is set, become the browse by tag chips. a failure just leaves a control empty, which
	// the main list error handling already covers.
	async function loadFilterSources() {
		const nsRes = await api.namespaces.list({ perPage: 200 });
		if (nsRes.ok) namespaceOptions = [{ value: '', label: 'All namespaces' }, ...(nsRes.data.namespaces || []).map((n) => ({ value: n.name, label: n.name }))];
		const tagRes = await api.tags.list();
		if (tagRes.ok) tags = tagRes.data.tags || [];
	}

	onMount(() => {
		// seed the filters, search and page from the URL so a deep link (for example a
		// namespace drill down) opens already filtered.
		const sp = $page.url.searchParams;
		query = sp.get('q') || '';
		typeFilter = sp.get('type') || '';
		nsFilter = sp.get('namespace') || '';
		tagFilter = sp.get('tag') || '';
		const pg = parseInt(sp.get('page') || '1', 10);
		if (pg > 1) pageNum = pg;
		loadFilterSources();
		load();
		loadDrafts();
	});

	// short local date for the Updated column; blank if the timestamp is missing.
	function fmtDate(s) {
		if (!s) return '';
		const d = new Date(s);
		if (isNaN(d)) return '';
		return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
	}
</script>

<PageHeader title="Packages">
	{#snippet help()}
		<Help title="Packages">
			<p>A package is versioned content (an email, landing page, asset bundle or AiTM config) addressed as <code>namespace/name</code>.</p>
			<p>Create one with <strong>New package</strong>: write the content, add images, declare <code>@@VARIABLES@@</code>, and publish. Each version is installable from Phishing Club.</p>
		</Help>
	{/snippet}
	{#snippet actions()}
		<Button variant="secondary" disabled={importing} onclick={() => importInput.click()}>
			{importing ? 'Importing…' : 'Import package'}
		</Button>
		<input bind:this={importInput} type="file" accept=".gz,.tar.gz,application/gzip" class="hidden" onchange={doImportPackage} />
		<Button href="/packages/bundle" variant="secondary">New bundle</Button>
		<Button href="/packages/new" variant="primary">New package</Button>
	{/snippet}
</PageHeader>

{#if drafts.length}
	<Card padding="sm" class="mt-4">
		<div class="mb-2 flex items-center gap-2">
			<h2 class="pc-card-title">Drafts</h2>
			<span class="inline-flex items-center rounded-full bg-gray-100 px-2 py-0.5 text-xs font-medium text-gray-700 dark:bg-gray-800 dark:text-gray-200">{drafts.length}</span>
			<span class="text-sm text-gray-700 dark:text-gray-200">unpublished work, saved but not released</span>
		</div>
		<ul class="divide-y divide-gray-100 dark:divide-gray-800">
			{#each drafts as d}
				<li class="flex items-center justify-between gap-3 py-2">
					<a href={`/packages/new?draft=${d.namespace}/${d.name}`} class="min-w-0 flex-1">
						<span class="font-medium text-gray-900 dark:text-white">{d.title || d.name}</span>
						<span class="ml-2 font-mono text-xs text-gray-600 dark:text-gray-300">{d.namespace}/{d.name}</span>
						<span class="ml-2 text-xs text-gray-600 dark:text-gray-300">{typeLabel(d.type)} · v{d.version}</span>
					</a>
					<div class="flex items-center gap-2">
						<Button href={`/packages/new?draft=${d.namespace}/${d.name}`} variant="neutral" size="xs" class="border-gray-300 text-gray-700 hover:bg-gray-50 dark:border-gray-700 dark:text-gray-200 dark:hover:bg-gray-800">Open</Button>
						<Button variant="neutral" size="xs" onclick={() => discardDraft(d)} class="border-red-300 text-red-600 hover:bg-red-50 dark:border-red-500/40 dark:text-red-400 dark:hover:bg-red-900/20">Discard</Button>
					</div>
				</li>
			{/each}
		</ul>
	</Card>
{/if}

<Card padding="none" class="mt-6 overflow-hidden">
	{#if !loaded}
		<Skeleton rows={4} />
	{:else if loadError}
		<ErrorCard bare message={loadError} onretry={load} />
	{:else if total === 0 && !query.trim() && !hasActiveFilters}
		<div class="p-8 text-center">
			<p class="text-sm text-gray-700 dark:text-gray-200">No packages yet.</p>
			<Button href="/packages/new" variant="primary" class="mt-3 inline-block">Author your first package</Button>
		</div>
	{:else}
		<div class="space-y-3 border-b border-gray-200 dark:border-gray-800 p-3">
			<div class="flex flex-wrap items-end gap-3">
				<div class="min-w-[12rem] flex-1">
					<input
						bind:value={query}
						oninput={onSearchInput}
						aria-label="Search packages"
						placeholder="Search by name or description"
						class="pc-control w-full"
					/>
				</div>
				<div class="w-44">
					<span class="pc-label">Type</span>
					<Select value={typeFilter} onchange={onTypeFilter} options={typeOptions} ariaLabel="Filter by type" class="mt-1" />
				</div>
				<div class="w-44">
					<span class="pc-label">Namespace</span>
					<Select value={nsFilter} onchange={onNamespaceFilter} options={namespaceOptions} ariaLabel="Filter by namespace" class="mt-1" />
				</div>
				{#if hasActiveFilters || query.trim()}
					<Button variant="neutral" onclick={clearFilters}>Clear all</Button>
				{/if}
			</div>
			{#if tags.length}
				<div class="flex flex-wrap items-center gap-1.5">
					<span class="mr-1 text-xs font-medium pc-muted">Browse by tag:</span>
					{#each tags as t (t.name)}
						<button
							type="button"
							onclick={() => toggleTag(t.name)}
							aria-pressed={tagFilter === t.name}
							class="inline-flex items-center rounded px-1.5 py-0.5 text-xs transition {tagChipClass(t.color)} {tagFilter === t.name ? 'ring-2 ring-active-blue/60' : 'opacity-80 hover:opacity-100'}"
							style={tagChipStyle(t.color)}
						>{t.name}</button>
					{/each}
				</div>
			{/if}
			{#if hasActiveFilters}
				<p class="text-xs pc-muted">
					Filtering by{typeFilter ? ` type ${typeLabel(typeFilter)}` : ''}{nsFilter ? ` namespace ${nsFilter}` : ''}{tagFilter ? ` tag ${tagFilter}` : ''}.
				</p>
			{/if}
		</div>
		{#if packages.length === 0}
			<EmptyState message={query.trim() ? `No packages match "${query.trim()}"${hasActiveFilters ? ' with these filters' : ''}.` : 'No packages match these filters.'}>
				<Button variant="neutral" size="xs" onclick={clearFilters}>Clear all</Button>
			</EmptyState>
		{:else}
			<div class="overflow-x-auto transition-opacity {refreshing ? 'opacity-50' : ''}">
				<table class="w-full text-sm">
					<thead class="bg-gray-50 dark:bg-gray-900 text-gray-700 dark:text-gray-200">
						<tr>
							<th class="px-4 py-2 text-left font-medium">Namespace</th>
							<SortHeader label="Name" column="name" {sortKey} {sortDir} onsort={sortBy} />
							<SortHeader label="Type" column="type" {sortKey} {sortDir} onsort={sortBy} />
							<th class="px-4 py-2 text-left font-medium">Visibility</th>
							<SortHeader label="Downloads" column="download_count" {sortKey} {sortDir} onsort={sortBy} align="right" />
							<SortHeader label="Updated" column="updated_at" {sortKey} {sortDir} onsort={sortBy} />
							<th class="px-4 py-2"></th>
						</tr>
					</thead>
					<tbody>
						{#each packages as p (p.namespace + '/' + p.name)}
							<tr class="border-t border-gray-200 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-900 cursor-pointer" onclick={(e) => openRow(e, p)}>
								<td class="px-4 py-3 align-top text-gray-800 dark:text-gray-100">
									<span class="inline-flex items-center gap-2">
										<span class="h-2.5 w-2.5 shrink-0 rounded-full {nsDotClass(p.namespaceColor)}" style={nsDotStyle(p.namespaceColor)}></span>
										{p.namespace}
									</span>
								</td>
								<td class="px-4 py-3 align-top">
									<div class="min-w-0">
										<a
											href="/packages/{p.namespace}/{p.name}"
											title={p.name}
											class="font-medium hover:underline">{p.title || p.name}</a
										>
										{#if p.description}
											<div class="mt-0.5 max-w-xs truncate text-xs text-gray-500 dark:text-gray-400">{p.description}</div>
										{/if}
									</div>
								</td>
								<td class="px-4 py-3 align-top">
									<span class="inline-flex items-center rounded px-2 py-0.5 text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-100">{typeLabel(p.type)}</span>
								</td>
								<td class="px-4 py-3 align-top">
									<StatusPill tone={p.visibility === 'public' ? 'public' : 'private'}>{p.visibility}</StatusPill>
								</td>
								<td class="px-4 py-3 align-top text-right tabular-nums">{(p.downloadCount ?? 0).toLocaleString()}</td>
								<td class="px-4 py-3 align-top text-gray-700 dark:text-gray-200 whitespace-nowrap">{fmtDate(p.updatedAt)}</td>
								<td class="px-4 py-3 align-top text-right text-gray-400 dark:text-gray-500" aria-hidden="true">›</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
			<Pagination {pageNum} pageSize={perPage} {total} onchange={gotoPage} />
		{/if}
	{/if}
</Card>

<ImportResult bind:open={importResultOpen} result={importResult} />
