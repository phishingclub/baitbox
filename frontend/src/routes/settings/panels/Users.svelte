<script>
	import { onMount } from 'svelte';
	import { api } from '$lib/api/api.js';
	import { toast } from '$lib/stores/toast.svelte.js';
	import { askConfirm } from '$lib/stores/confirm.svelte.js';
	import Help from '$lib/components/Help.svelte';
	import Skeleton from '$lib/components/Skeleton.svelte';
	import SortHeader from '$lib/components/SortHeader.svelte';
	import Pagination from '$lib/components/Pagination.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import StatusPill from '$lib/components/StatusPill.svelte';
	import RowMenu from '$lib/components/RowMenu.svelte';
	import Button from '$lib/components/Button.svelte';
	import Card from '$lib/components/Card.svelte';
	import ErrorCard from '$lib/components/ErrorCard.svelte';
	import Field from '$lib/components/Field.svelte';
	import StepUpDialog from '$lib/components/StepUpDialog.svelte';

	let operators = $state([]);
	let loaded = $state(false);
	let loadError = $state('');
	let form = $state({ username: '', password: '', confirm: '' });
	let busy = $state(false);
	let query = $state('');
	let stepUp = $state(null);

	const passwordsMatch = $derived(form.confirm.length > 0 && form.password === form.confirm);
	const canCreate = $derived(form.username.trim().length >= 3 && form.password.length >= 12 && passwordsMatch && !busy);

	let sortKey = $state('');
	let sortDir = $state('asc');
	function sortBy(key) {
		if (sortKey === key) sortDir = sortDir === 'asc' ? 'desc' : 'asc';
		else {
			sortKey = key;
			sortDir = key === 'createdAt' ? 'desc' : 'asc';
		}
	}

	const filtered = $derived.by(() => {
		const q = query.trim().toLowerCase();
		let rows = q ? operators.filter((o) => o.username.toLowerCase().includes(q)) : operators.slice();
		if (sortKey) {
			const dir = sortDir === 'asc' ? 1 : -1;
			rows.sort((a, b) => {
				if (sortKey === 'createdAt') return (new Date(a.createdAt) - new Date(b.createdAt)) * dir;
				return String(a[sortKey] ?? '').localeCompare(String(b[sortKey] ?? '')) * dir;
			});
		}
		return rows;
	});

	const pageSize = 25;
	let pageNum = $state(1);
	const paged = $derived(filtered.slice((pageNum - 1) * pageSize, pageNum * pageSize));
	$effect(() => {
		const _ = `${query}|${sortKey}|${sortDir}`;
		pageNum = 1;
	});

	async function load() {
		loadError = '';
		const res = await api.operators.list();
		if (res.ok) operators = res.data.operators || [];
		else loadError = res.error || 'Could not load operators';
		loaded = true;
	}
	onMount(load);

	async function create() {
		if (!canCreate) {
			if (form.username.trim().length < 3) toast('Username must be at least 3 characters', 'error');
			else if (form.password.length < 12) toast('Password must be at least 12 characters', 'error');
			else toast('Passwords do not match', 'error');
			return;
		}
		busy = true;
		// adding an operator creates a new login, so the server asks for a fresh
		// proof of identity first. null means the operator cancelled that prompt.
		const res = await stepUp.withStepUp(() => api.operators.create(form.username.trim(), form.password));
		busy = false;
		if (!res) return;
		if (res.ok) {
			toast('Operator created', 'success');
			form = { username: '', password: '', confirm: '' };
			await load();
		} else {
			toast(res.error || 'Could not create operator', 'error');
		}
	}

	async function remove(op) {
		if (!(await askConfirm({ title: 'Delete operator', body: `Delete operator "${op.username}"? This signs them out and cannot be undone.`, confirmLabel: 'Delete' }))) return;
		const res = await stepUp.withStepUp(() => api.operators.remove(op.id));
		if (!res) return;
		if (res.ok) {
			toast('Operator deleted', 'success');
			await load();
		} else {
			toast(res.error || 'Could not delete operator', 'error');
		}
	}

	function fmt(ts) {
		try {
			return new Date(ts).toLocaleDateString();
		} catch (_) {
			return ts;
		}
	}
</script>

<Card padding="lg">
	<form onsubmit={(e) => { e.preventDefault(); create(); }}>
		<div class="flex items-center gap-2">
			<h3 class="pc-card-title">Add an operator</h3>
			<Help title="Operator users">
				<p>Operator accounts that sign in to this admin UI. Each has its own username and password and its own sessions.</p>
				<p>A new operator must set their own password the first time they sign in.</p>
				<p>Add a colleague as a separate operator rather than sharing one login, so actions are logged per person. The last operator cannot be deleted, so the instance is never locked out.</p>
			</Help>
		</div>
		<div class="mt-3 grid gap-3 sm:grid-cols-[1fr_1fr_1fr_auto] sm:items-end">
			<Field label="Username">
				<input bind:value={form.username} autocomplete="off" class="pc-control" placeholder="jane" />
			</Field>
			<Field label="Password">
				<input bind:value={form.password} type="password" autocomplete="new-password" class="pc-control" placeholder="at least 12 characters" />
			</Field>
			<Field label="Confirm password">
				<input bind:value={form.confirm} type="password" autocomplete="new-password" class="pc-control" placeholder="repeat password" />
				{#if form.confirm.length > 0 && !passwordsMatch}
					<span class="mt-1 block text-xs text-red-600 dark:text-red-400">Passwords do not match.</span>
				{/if}
			</Field>
			<Button variant="primary" type="submit" disabled={!canCreate}>Create operator</Button>
		</div>
	</form>
</Card>

{#if loaded && loadError}
	<ErrorCard class="mt-6" message={loadError} onretry={load} />
{:else}
<Card padding="none" class="mt-6 overflow-hidden">
	{#if !loaded}
		<Skeleton rows={4} />
	{:else if operators.length === 0}
		<EmptyState message="No operators yet. Add one above." />
	{:else}
		<div class="border-b border-gray-100 p-3 dark:border-gray-800">
			<input bind:value={query} aria-label="Search operators" placeholder="Search by username" class="pc-control text-sm" />
		</div>
		{#if filtered.length === 0}
			<EmptyState message={`No operators match "${query}".`} />
		{:else}
			<div class="overflow-x-auto">
				<table class="w-full text-sm">
					<thead class="bg-gray-50 text-gray-700 dark:bg-gray-900 dark:text-gray-200">
						<tr>
							<SortHeader label="Username" column="username" {sortKey} {sortDir} onsort={sortBy} />
							<SortHeader label="Created" column="createdAt" {sortKey} {sortDir} onsort={sortBy} />
							<th class="px-4 py-2"></th>
						</tr>
					</thead>
					<tbody>
						{#each paged as op (op.id)}
							<tr class="border-t border-gray-100 text-gray-800 dark:border-gray-800 dark:text-gray-100">
								<td class="px-4 py-3 font-medium">
									{op.username}
									{#if op.self}<span class="ml-2"><StatusPill tone="info">you</StatusPill></span>{/if}
								</td>
								<td class="px-4 py-3">{fmt(op.createdAt)}</td>
								<td class="px-4 py-3 text-right whitespace-nowrap">
									{#if operators.length > 1}
										<RowMenu id={`op-${op.id}`} label={`Actions for ${op.username}`}>
											<button type="button" onclick={() => remove(op)} class="pc-menu-item-danger">Delete operator</button>
										</RowMenu>
									{/if}
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
			<Pagination {pageNum} {pageSize} total={filtered.length} onchange={(n) => (pageNum = n)} />
		{/if}
	{/if}
</Card>
{/if}

<StepUpDialog bind:this={stepUp} />
