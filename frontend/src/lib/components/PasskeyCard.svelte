<script>
	// The passkeys (WebAuthn) card. It lists the operator's passkeys, adds a new one
	// with an optional name and, when allowRemove is on, removes one after a confirm.
	// Adding and removing both ask the operator to confirm it is them first.
	// passkeys and loading are bindable so a parent can summarize the account state.
	import { onMount } from 'svelte';
	import { api } from '$lib/api/api.js';
	import { toast } from '$lib/stores/toast.svelte.js';
	import { askConfirm } from '$lib/stores/confirm.svelte.js';
	import { createCredential, supported } from '$lib/webauthn.js';
	import Button from '$lib/components/Button.svelte';
	import Card from '$lib/components/Card.svelte';
	import Field from '$lib/components/Field.svelte';
	import Help from '$lib/components/Help.svelte';
	import StatusPill from '$lib/components/StatusPill.svelte';
	import StepUpDialog from '$lib/components/StepUpDialog.svelte';

	// matches the server limit on a passkey name
	const NAME_MAX = 64;

	let {
		passkeys = $bindable([]),
		loading = $bindable(true),
		allowRemove = true,
		class: cls = ''
	} = $props();

	let name = $state('');
	let busy = $state(false);
	let stepUp = $state(null);

	async function load() {
		const r = await api.passkeys.list();
		if (r.ok) passkeys = r.data.passkeys || [];
		loading = false;
	}
	async function add() {
		if (!supported()) {
			toast('This browser does not support passkeys', 'error');
			return;
		}
		busy = true;
		try {
			const begin = await stepUp.withStepUp(() => api.passkeys.registerBegin());
			if (!begin) return;
			if (!begin.ok) {
				toast(begin.error || 'Could not start enrollment', 'error');
				return;
			}
			const att = await createCredential(begin.data);
			const fin = await api.passkeys.registerFinish(name.trim() || 'Passkey', att);
			if (fin.ok) {
				toast('Passkey added', 'success');
				name = '';
				await load();
			} else {
				toast(fin.error || 'Could not add passkey', 'error');
			}
		} catch (err) {
			toast('Passkey enrollment was cancelled or failed', 'error');
		} finally {
			busy = false;
		}
	}
	async function remove(pk) {
		if (!(await askConfirm({ title: 'Remove passkey', body: `Remove "${pk.name}"? You can no longer sign in with it.`, confirmLabel: 'Remove' }))) return;
		const r = await stepUp.withStepUp(() => api.passkeys.remove(pk.id));
		if (!r) return;
		if (r.ok) {
			toast('Passkey removed', 'success');
			await load();
		} else toast(r.error || 'Could not remove passkey', 'error');
	}
	function fmtDate(ts) {
		try {
			return new Date(ts).toLocaleDateString();
		} catch (_) {
			return ts;
		}
	}

	onMount(load);
</script>

<Card padding="lg" class={cls}>
	<div class="flex items-center gap-2">
		<h3 class="pc-card-title">Passkeys</h3>
		{#if !loading}
			<StatusPill tone={passkeys.length ? 'on' : 'off'}>{passkeys.length ? 'on' : 'off'}</StatusPill>
		{/if}
		<Help title="Passkeys">
			<p>A passkey (WebAuthn) is a second factor bound to this site and your device, phone or security key. After your password, you approve the login with the passkey instead of typing a code.</p>
			<p>Add one per device you sign in from. If you have a passkey or an authenticator code enabled, every login requires it.</p>
		</Help>
	</div>
	<form class="mt-4 flex flex-wrap items-end gap-2" onsubmit={(e) => { e.preventDefault(); add(); }}>
		<div class="min-w-0 flex-1 basis-48">
			<Field label="Name this passkey" optional>
				<input bind:value={name} maxlength={NAME_MAX} placeholder="e.g. YubiKey, MacBook Touch ID" class="pc-control" />
			</Field>
		</div>
		<Button variant="primary" type="submit" disabled={busy}>{busy ? 'Waiting…' : 'Add a passkey'}</Button>
	</form>
	{#if loading}
		<p class="mt-3 pc-desc">Loading…</p>
	{:else if passkeys.length}
		<ul class="mt-4 divide-y divide-gray-100 dark:divide-gray-800">
			{#each passkeys as pk (pk.id)}
				<li class="flex items-center justify-between gap-3 py-2 text-sm">
					<div class="min-w-0">
						<div class="truncate font-medium text-gray-900 dark:text-white">{pk.name}</div>
						<div class="pc-desc">Added {fmtDate(pk.createdAt)}{#if pk.lastUsedAt} · last used {fmtDate(pk.lastUsedAt)}{/if}</div>
					</div>
					{#if allowRemove}
						<Button variant="danger" size="xs" onclick={() => remove(pk)}>Remove</Button>
					{:else}
						<svg class="h-4 w-4 shrink-0 text-emerald-600 dark:text-emerald-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-label="Added"><path d="M20 6 9 17l-5-5" /></svg>
					{/if}
				</li>
			{/each}
		</ul>
	{:else}
		<p class="mt-3 pc-desc">No passkeys yet.</p>
	{/if}
</Card>

<StepUpDialog bind:this={stepUp} />
