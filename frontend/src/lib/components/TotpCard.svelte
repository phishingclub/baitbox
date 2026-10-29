<script>
	// The authenticator app (TOTP) card. It loads the current state, walks the
	// operator through enrollment (confirm it is them, show the secret, confirm a 6
	// digit code) and, when allowDisable is on, lets them turn it off again with a
	// current code. The secret stays on the server between the two enrollment steps.
	// enabled and loading are bindable so a parent can summarize the account state.
	import { onMount } from 'svelte';
	import { api } from '$lib/api/api.js';
	import { toast } from '$lib/stores/toast.svelte.js';
	import Button from '$lib/components/Button.svelte';
	import Card from '$lib/components/Card.svelte';
	import Field from '$lib/components/Field.svelte';
	import Help from '$lib/components/Help.svelte';
	import StatusPill from '$lib/components/StatusPill.svelte';
	import StepUpDialog from '$lib/components/StepUpDialog.svelte';
	import { goto } from '$app/navigation';
	import { auth } from '$lib/stores/auth.svelte.js';

	let {
		enabled = $bindable(false),
		loading = $bindable(true),
		allowDisable = true,
		title = 'Two factor authentication',
		class: cls = ''
	} = $props();

	let enrolling = $state(false);
	let secret = $state('');
	let code = $state('');
	let disableCode = $state('');
	let busy = $state(false);
	let stepUp = $state(null);

	async function load() {
		const r = await api.mfa.status();
		if (r.ok) enabled = r.data.enabled;
		loading = false;
	}
	async function startEnroll() {
		busy = true;
		const r = await stepUp.withStepUp(() => api.mfa.begin());
		busy = false;
		if (!r) return;
		if (r.ok) {
			secret = r.data.secret;
			code = '';
			enrolling = true;
		} else toast(r.error || 'Could not start enrollment', 'error');
	}
	async function confirmEnroll() {
		busy = true;
		const r = await api.mfa.confirm(code.trim());
		busy = false;
		if (r.ok && r.data?.signedOut) {
			toast('Two factor authentication enabled. Please sign in again.', 'success');
			auth.clear();
			goto('/login');
		} else if (r.ok) {
			enabled = true;
			enrolling = false;
			secret = '';
			code = '';
			toast('Two factor authentication enabled. Other sessions were signed out.', 'success');
		} else toast(r.error || 'That code did not match', 'error');
	}
	async function disable() {
		busy = true;
		const r = await api.mfa.disable(disableCode.trim());
		busy = false;
		if (r.ok) {
			enabled = false;
			disableCode = '';
			toast('Two factor authentication disabled', 'success');
		} else toast(r.error || 'That code did not match', 'error');
	}
	function copySecret() {
		navigator.clipboard?.writeText(secret).then(
			() => toast('Secret copied', 'success'),
			() => toast('Could not copy', 'error')
		);
	}

	onMount(load);
</script>

<Card padding="lg" class={cls}>
	<div class="flex items-center gap-2">
		<h3 class="pc-card-title">{title}</h3>
		{#if !loading && !enrolling}
			<StatusPill tone={enabled ? 'on' : 'off'}>{enabled ? 'on' : 'off'}</StatusPill>
		{/if}
		<Help title="Two factor authentication">
			<p>Adds a second step to your login: after your password, an authenticator app (Google Authenticator, 1Password, Aegis, etc.) supplies a 6 digit code.</p>
			<p>Enable it, add the secret to your app, then confirm a code. From then on every login asks for the current code.</p>
		</Help>
	</div>
	{#if loading}
		<p class="mt-2 pc-desc">Loading…</p>
	{:else if enabled && allowDisable}
		<p class="mt-1 pc-desc">Your account is protected by an authenticator app.</p>
		<form class="mt-4 space-y-3" onsubmit={(e) => { e.preventDefault(); disable(); }}>
			<Field label="Enter a current code to turn it off">
				<input bind:value={disableCode} inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" class="pc-control font-mono tracking-[0.2em]" />
			</Field>
			<Button variant="danger" type="submit" disabled={busy || disableCode.trim().length < 6}>Disable two factor</Button>
		</form>
	{:else if enabled}
		<p class="mt-2 flex items-center gap-2 text-sm font-medium text-emerald-700 dark:text-emerald-400">
			<svg class="h-4 w-4 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 6 9 17l-5-5" /></svg>
			Authenticator app added. Every login now asks for a code.
		</p>
	{:else if enrolling}
		<p class="mt-2 pc-desc">Add this secret to your authenticator app, then enter a code to confirm.</p>
		<div class="mt-3 rounded-lg border border-gray-200 bg-gray-50 p-3 dark:border-gray-800 dark:bg-gray-900">
			<div class="text-sm font-medium text-gray-800 dark:text-gray-100">Secret</div>
			<div class="mt-1 flex items-center gap-2">
				<code class="break-all font-mono text-sm text-gray-900 dark:text-gray-100">{secret}</code>
				<Button variant="neutral" size="xs" onclick={copySecret}>Copy</Button>
			</div>
		</div>
		<form class="mt-3 space-y-3" onsubmit={(e) => { e.preventDefault(); confirmEnroll(); }}>
			<Field label="Code from your app">
				<input bind:value={code} inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="123456" class="pc-control font-mono tracking-[0.2em]" />
			</Field>
			<div class="flex flex-wrap gap-2">
				<Button variant="primary" type="submit" disabled={busy || code.trim().length < 6}>Confirm and enable</Button>
				<Button variant="secondary" onclick={() => { enrolling = false; }}>Cancel</Button>
			</div>
		</form>
	{:else}
		<p class="mt-1 pc-desc">Protect your login with an authenticator app.</p>
		<Button variant="primary" onclick={startEnroll} disabled={busy} class="mt-4">Enable two factor</Button>
	{/if}
</Card>

<StepUpDialog bind:this={stepUp} />
