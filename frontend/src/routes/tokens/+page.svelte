<script>
	import { onMount } from 'svelte';
	import { api } from '$lib/api/api.js';
	import { toast } from '$lib/stores/toast.svelte.js';
	import { askConfirm } from '$lib/stores/confirm.svelte.js';
	import Skeleton from '$lib/components/Skeleton.svelte';
	import Help from '$lib/components/Help.svelte';
	import StatusPill from '$lib/components/StatusPill.svelte';
	import SortHeader from '$lib/components/SortHeader.svelte';
	import Pagination from '$lib/components/Pagination.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import RowMenu from '$lib/components/RowMenu.svelte';
	import Button from '$lib/components/Button.svelte';
	import Card from '$lib/components/Card.svelte';
	import ErrorCard from '$lib/components/ErrorCard.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import PageHeader from '$lib/components/PageHeader.svelte';
	import StepUpDialog from '$lib/components/StepUpDialog.svelte';

	let tokens = $state([]);
	let loaded = $state(false);
	let form = $state({ name: '', namespaces: '', allowedCidrs: '', expiresInDays: 0 });
	let fresh = $state(''); // the clear token shown once after create
	let query = $state('');
	let nsList = $state([]); // available namespaces, for clickable scope chips
	let stepUp = $state(null);

	// add a namespace to the comma separated scope input, avoiding duplicates.
	function addScope(name) {
		const parts = form.namespaces
			.split(/[\s,]+/)
			.map((x) => x.trim())
			.filter(Boolean);
		if (!parts.includes(name)) parts.push(name);
		form.namespaces = parts.join(', ');
	}

	function scopeList(s) {
		try {
			return (JSON.parse(s) || []).join(', ');
		} catch (_) {
			return '';
		}
	}

	// short local date for the token's last use, or "never" if it has not been used
	// yet, so an operator can spot stale tokens to revoke.
	function lastUsed(s) {
		if (!s) return 'never';
		const d = new Date(s);
		if (isNaN(d)) return 'never';
		return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
	}
	function fmtDate(s) {
		if (!s) return '';
		const d = new Date(s);
		return isNaN(d) ? '' : d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
	}
	// a token past its expiry is rejected by the server even though it is not
	// revoked, so the UI shows it as expired rather than active.
	function isExpired(s) {
		if (!s) return false;
		const d = new Date(s);
		return !isNaN(d) && d.getTime() < Date.now();
	}

	let sortKey = $state(''); // '' keeps the backend order; else name/lastUsedAt/status
	let sortDir = $state('asc');
	function sortBy(key) {
		if (sortKey === key) sortDir = sortDir === 'asc' ? 'desc' : 'asc';
		else {
			sortKey = key;
			sortDir = 'asc';
		}
	}
	// client side pagination, matching the packages list. it has no effect until the
	// filtered token set exceeds a page; tokens accumulate over the life of a registry.
	const pageSize = 25;
	let pageNum = $state(1);
	function statusOf(t) {
		return t.revoked ? 'revoked' : isExpired(t.expiresAt) ? 'expired' : 'active';
	}

	const filtered = $derived.by(() => {
		const q = query.trim().toLowerCase();
		let rows = q
			? tokens.filter((t) =>
					`${t.name} ${t.prefix} ${scopeList(t.entitlements)}`.toLowerCase().includes(q)
				)
			: tokens.slice();
		if (sortKey) {
			const dir = sortDir === 'asc' ? 1 : -1;
			const ts = (s) => (s ? new Date(s).getTime() : 0); // never used sorts oldest
			rows.sort((a, b) => {
				if (sortKey === 'lastUsedAt') return (ts(a.lastUsedAt) - ts(b.lastUsedAt)) * dir;
				if (sortKey === 'status') return statusOf(a).localeCompare(statusOf(b)) * dir;
				return String(a[sortKey] ?? '').localeCompare(String(b[sortKey] ?? '')) * dir;
			});
		}
		return rows;
	});

	const paged = $derived(filtered.slice((pageNum - 1) * pageSize, pageNum * pageSize));
	$effect(() => {
		const _ = query;
		pageNum = 1;
	});

	let loadError = $state('');
	async function load() {
		loadError = '';
		const res = await api.tokens.list();
		if (res.ok) tokens = res.data.tokens;
		else loadError = res.error || 'Could not load tokens';
		loaded = true;
	}
	onMount(async () => {
		await load();
		const res = await api.namespaces.list({ perPage: 200 });
		nsList = res.ok ? res.data.namespaces.map((n) => n.name) : [];
	});

	// scope entries the operator typed that are neither * nor an existing namespace, so
	// the form can warn before minting a token that would not grant access to anything.
	const unknownScopes = $derived(
		form.namespaces
			.split(/[\s,]+/)
			.map((x) => x.trim())
			.filter(Boolean)
			.filter((n) => n !== '*' && nsList.length > 0 && !nsList.includes(n))
	);

	async function create() {
		if (!form.name) {
			toast('Name is required', 'error');
			return;
		}
		const namespaces = form.namespaces
			.split(/[\s,]+/)
			.map((x) => x.trim())
			.filter(Boolean);
		const allowedCidrs = form.allowedCidrs
			.split(/[\s,]+/)
			.map((x) => x.trim())
			.filter(Boolean);
		// minting a token creates a credential, so the server asks for a fresh proof
		// of identity first. null means the operator cancelled that prompt.
		const res = await stepUp.withStepUp(() =>
			api.tokens.create({
				name: form.name,
				namespaces,
				allowedCidrs,
				expiresInDays: Number(form.expiresInDays) || 0
			})
		);
		if (!res) return;
		if (res.ok) {
			fresh = res.data.token;
			form = { name: '', namespaces: '', allowedCidrs: '', expiresInDays: 0 };
			await load();
		} else {
			toast(res.error || 'Failed to create token', 'error');
		}
	}

	async function copy() {
		try {
			await navigator.clipboard.writeText(fresh);
			toast('Copied to clipboard', 'success');
		} catch (_) {
			toast('Copy failed; select it manually', 'error');
		}
	}

	async function revoke(t) {
		// revoking is immediate and permanent: anything using the token stops working and
		// it cannot be unrevoked, so confirm like a delete.
		if (
			!(await askConfirm({
				title: 'Revoke token',
				body: `Revoke token "${t.name}"? Anything using it (the CLI, CI, or a Phishing Club connection) stops working immediately. This cannot be undone.`,
				confirmLabel: 'Revoke'
			}))
		)
			return;
		const res = await api.tokens.revoke(t.id);
		if (res.ok) {
			toast('Token revoked', 'success');
			await load();
		} else toast(res.error || 'Failed', 'error');
	}
	async function remove(t) {
		if (!(await askConfirm({ title: 'Delete token', body: `Delete token "${t.name}"? This cannot be undone.`, confirmLabel: 'Delete' }))) return;
		const res = await api.tokens.remove(t.id);
		if (res.ok) {
			toast('Token deleted', 'success');
			await load();
		} else toast(res.error || 'Failed', 'error');
	}

	// edit the source IP allowlist on an existing token. blank clears the restriction.
	let editTok = $state(null);
	let editOpen = $state(false);
	let editCidrs = $state('');
	let editSaving = $state(false);
	function openEditIps(t) {
		editTok = t;
		editCidrs = scopeList(t.allowedCidrs);
		editOpen = true;
	}
	function closeEditIps() {
		editOpen = false;
		editTok = null;
	}
	async function saveEditIps() {
		const allowedCidrs = editCidrs
			.split(/[\s,]+/)
			.map((x) => x.trim())
			.filter(Boolean);
		editSaving = true;
		const id = editTok.id;
		const res = await stepUp.withStepUp(() => api.tokens.update(id, { allowedCidrs }));
		editSaving = false;
		if (!res) return;
		if (res.ok) {
			toast('Allowed IPs updated', 'success');
			closeEditIps();
			await load();
		} else toast(res.error || 'Failed to update', 'error');
	}
</script>

<PageHeader title="Tokens">
	{#snippet help()}
		<Help title="Tokens">
			<p>Tokens let the Phishing Club registry client read and install packages. The web UI itself uses your operator login, not a token.</p>
			<p>A token is read only: it can install packages from the namespaces it is given, or <code>*</code> for all. Publishing is done by an operator in the admin UI.</p>
		</Help>
	{/snippet}
</PageHeader>

{#if fresh}
	<div class="mt-4 rounded-xl border border-pc-dusty-light-blue bg-grayblue-light dark:bg-pc-darkblue/40 p-4">
		<div class="text-sm font-semibold text-active-blue dark:text-highlight-blue">New token, shown once</div>
		<div class="mt-2 flex items-center gap-2">
			<code class="flex-1 break-all rounded bg-pc-lightblue/70 dark:bg-gray-900/60 border border-highlight-blue dark:border-active-blue px-3 py-2 text-sm">{fresh}</code>
			<Button variant="primary" onclick={copy}>Copy</Button>
			<Button variant="neutral" size="xs" onclick={() => (fresh = '')}>Dismiss</Button>
		</div>
		<p class="mt-2 text-xs text-cta-blue dark:text-highlight-blue">Only the hash is stored. Copy it now; you cannot see it again.</p>
	</div>
{/if}

<Card class="mt-6">
	<h2 class="pc-card-title mb-3">New token</h2>
	<form onsubmit={(e) => { e.preventDefault(); create(); }} class="flex flex-wrap items-end gap-3">
		<label class="text-sm">
			<span class="pc-label">Name</span>
			<input bind:value={form.name} placeholder="phishing-club" class="mt-1 block rounded-md pc-control px-3 py-2" />
		</label>
		<label class="text-sm flex-1 min-w-48">
			<span class="pc-label">Namespaces (comma separated, or *)</span>
			<input bind:value={form.namespaces} placeholder="acme-corp, *" class="mt-1 block w-full rounded-md pc-control px-3 py-2" />
		</label>
		<label class="text-sm flex-1 min-w-48">
			<span class="pc-label">Allowed IPs (comma separated, blank = any)</span>
			<input bind:value={form.allowedCidrs} placeholder="203.0.113.5, 10.0.0.0/8" class="mt-1 block w-full rounded-md pc-control px-3 py-2" />
		</label>
		<label class="text-sm">
			<span class="pc-label">Expires</span>
			<select bind:value={form.expiresInDays} class="mt-1 block rounded-md pc-control px-3 py-2">
				<option value={0}>No expiry</option>
				<option value={30}>30 days</option>
				<option value={90}>90 days</option>
				<option value={365}>1 year</option>
			</select>
		</label>
		<Button variant="primary" type="submit">Create token</Button>
	</form>
	{#if nsList.length}
		<div class="mt-3 flex flex-wrap items-center gap-1.5">
			<span class="text-xs text-gray-700 dark:text-gray-200">Add namespace:</span>
			{#each nsList as n}
				<button type="button" onclick={() => addScope(n)} class="rounded bg-gray-100 px-2 py-0.5 text-xs text-gray-800 hover:bg-gray-200 dark:bg-gray-800 dark:text-gray-100 dark:hover:bg-gray-700">{n}</button>
			{/each}
			<button type="button" onclick={() => addScope('*')} class="rounded bg-gray-100 px-2 py-0.5 text-xs text-gray-800 hover:bg-gray-200 dark:bg-gray-800 dark:text-gray-100 dark:hover:bg-gray-700">* (all)</button>
		</div>
	{/if}
	{#if unknownScopes.length}
		<p class="mt-2 text-xs text-amber-700 dark:text-amber-300">
			Not an existing namespace: {unknownScopes.join(', ')}. The token will grant no access until a matching namespace exists.
		</p>
	{/if}
</Card>

{#if loaded && loadError}
	<ErrorCard class="mt-6" message={loadError} onretry={load} />
{:else}
<Card padding="none" class="mt-6 overflow-hidden">
	{#if !loaded}
		<Skeleton rows={4} />
	{:else if tokens.length === 0}
		<EmptyState message="No tokens yet. Create one above for the CLI or the Phishing Club registry client." />
	{:else}
		<div class="border-b border-gray-100 dark:border-gray-800 p-3">
			<input
				bind:value={query}
				aria-label="Search tokens"
				placeholder="Search by name, namespace or prefix"
				class="w-full rounded-md pc-control px-3 py-2 text-sm"
			/>
		</div>
		{#if filtered.length === 0}
			<EmptyState message={`No tokens match "${query}".`} />
		{:else}
		<div class="overflow-x-auto"><table class="w-full text-sm">
			<thead class="bg-gray-50 dark:bg-gray-900 text-gray-700 dark:text-gray-200">
				<tr>
					<th class="text-left px-4 py-2 font-medium">Prefix</th>
					<SortHeader label="Name" column="name" {sortKey} {sortDir} onsort={sortBy} />
					<th class="text-left px-4 py-2 font-medium">Namespaces</th>
					<th class="text-left px-4 py-2 font-medium">Allowed IPs</th>
					<th class="text-left px-4 py-2 font-medium">Created by</th>
					<SortHeader label="Last used" column="lastUsedAt" {sortKey} {sortDir} onsort={sortBy} />
					<SortHeader label="Status" column="status" {sortKey} {sortDir} onsort={sortBy} />
					<th class="px-4 py-2"></th>
				</tr>
			</thead>
			<tbody>
				{#each paged as t (t.id)}
					<tr class="border-t border-gray-100 dark:border-gray-800">
						<td class="px-4 py-3"><code class="text-xs">{t.prefix}…</code></td>
						<td class="px-4 py-3 font-medium">{t.name}</td>
						<td class="px-4 py-3 text-gray-800 dark:text-gray-100">{scopeList(t.entitlements)}</td>
						<td class="px-4 py-3 text-gray-700 dark:text-gray-200">{scopeList(t.allowedCidrs) || 'any'}</td>
						<td class="px-4 py-3 text-gray-700 dark:text-gray-200">{t.createdBy || '-'}</td>
						<td class="px-4 py-3 whitespace-nowrap {t.lastUsedAt ? 'text-gray-700 dark:text-gray-200' : 'text-gray-600 dark:text-gray-300'}">{lastUsed(t.lastUsedAt)}</td>
						<td class="px-4 py-3">
							{#if t.revoked}
								<StatusPill tone="revoked">revoked</StatusPill>
							{:else if isExpired(t.expiresAt)}
								<StatusPill tone="expired">expired</StatusPill>
							{:else}
								<StatusPill tone="active">active</StatusPill>
								{#if t.expiresAt}
									<div class="mt-0.5 text-xs text-gray-700 dark:text-gray-200">expires {fmtDate(t.expiresAt)}</div>
								{/if}
							{/if}
						</td>
						<td class="px-4 py-3 text-right whitespace-nowrap">
							<RowMenu id={`tok-${t.id}`} label={`Actions for ${t.name}`}>
								<button type="button" onclick={() => openEditIps(t)} class="pc-menu-item">Edit allowed IPs</button>
								{#if !t.revoked}
									<button type="button" onclick={() => revoke(t)} class="pc-menu-item">Revoke</button>
								{/if}
								<button type="button" onclick={() => remove(t)} class="pc-menu-item-danger">Delete</button>
							</RowMenu>
						</td>
					</tr>
				{/each}
			</tbody>
		</table></div>
		<Pagination {pageNum} {pageSize} total={filtered.length} onchange={(n) => (pageNum = n)} />
		{/if}
	{/if}
</Card>
{/if}

<Modal bind:open={editOpen} title="Allowed IPs" onclose={closeEditIps}>
	{#if editTok}
		<p class="mt-1 pc-desc">Restrict token <strong>{editTok.name}</strong> to these IPs or CIDRs. Leave blank to allow any.</p>
	{/if}
	<input bind:value={editCidrs} placeholder="203.0.113.5, 10.0.0.0/8" class="mt-3 block w-full rounded-md pc-control px-3 py-2" />
	{#snippet footer()}
		<Button variant="secondary" onclick={closeEditIps}>Cancel</Button>
		<Button variant="primary" onclick={saveEditIps} disabled={editSaving} class="disabled:opacity-50">{editSaving ? 'Saving…' : 'Save'}</Button>
	{/snippet}
</Modal>

<StepUpDialog bind:this={stepUp} />
