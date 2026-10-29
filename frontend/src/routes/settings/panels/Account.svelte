<script>
	import { goto } from '$app/navigation';
	import { api } from '$lib/api/api.js';
	import Button from '$lib/components/Button.svelte';
	import Card from '$lib/components/Card.svelte';
	import Field from '$lib/components/Field.svelte';
	import Alert from '$lib/components/Alert.svelte';
	import { auth } from '$lib/stores/auth.svelte.js';
	import { toast } from '$lib/stores/toast.svelte.js';
	import TotpCard from '$lib/components/TotpCard.svelte';
	import PasskeyCard from '$lib/components/PasskeyCard.svelte';

	let current = $state('');
	let next = $state('');
	let confirmPw = $state('');
	let saving = $state(false);

	// second factor state, filled in by the TOTP and passkey cards
	let mfaEnabled = $state(false);
	let mfaLoading = $state(true);
	let passkeys = $state([]);
	let passkeysLoading = $state(true);

	// a one line summary of what is protecting the account beyond the password, so
	// the state is readable at a glance rather than inferred from two separate cards.
	const factorCount = $derived((mfaEnabled ? 1 : 0) + (passkeys.length ? 1 : 0));
	const protection = $derived.by(() => {
		if (mfaLoading || passkeysLoading) return '';
		const parts = [];
		if (mfaEnabled) parts.push('an authenticator app');
		if (passkeys.length) parts.push(`${passkeys.length} passkey${passkeys.length === 1 ? '' : 's'}`);
		return parts.length ? `Protected by ${parts.join(' and ')}.` : 'No second factor. Your account is protected by a password only.';
	});

	const pwValid = $derived(current.length > 0 && next.length >= 12 && next === confirmPw);
	async function changePassword(e) {
		e.preventDefault();
		if (!pwValid || saving) return;
		saving = true;
		const res = await api.changePassword(current, next);
		saving = false;
		if (res.ok && res.data?.signedOut) {
			toast('Password changed. Please sign in again.', 'success');
			auth.clear();
			goto('/login');
		} else if (res.ok) {
			current = '';
			next = '';
			confirmPw = '';
			toast('Password changed. Other sessions were signed out.', 'success');
		} else {
			toast(res.error || 'Could not change password', 'error');
		}
	}
</script>

{#if !mfaLoading && !passkeysLoading}
	{#if factorCount}
		<Alert variant="success">{protection}</Alert>
	{:else}
		<Alert variant="warning" title="Security warning:">your account has no second factor. Add an authenticator app or a passkey below to protect it.</Alert>
	{/if}
{/if}

<div class="mt-6 grid items-start gap-6 lg:grid-cols-2">
	<!-- Change password -->
	<Card padding="lg">
		<h3 class="pc-card-title">Change password</h3>
		<p class="mt-1 pc-desc">
			Signed in as <span class="font-semibold">{auth.operator?.username ?? ''}</span>. Changing your
			password signs you out everywhere else.
		</p>
		<form class="mt-4 space-y-3" onsubmit={changePassword}>
			<Field label="Current password">
				<input type="password" bind:value={current} autocomplete="current-password" class="w-full rounded-md pc-control px-3 py-2 text-sm" />
			</Field>
			<Field label="New password">
				<input type="password" bind:value={next} autocomplete="new-password" class="w-full rounded-md pc-control px-3 py-2 text-sm" />
				<p class="mt-1 text-sm {next.length > 0 && next.length < 12 ? 'text-red-600 dark:text-red-400' : 'text-gray-800 dark:text-gray-200'}">At least 12 characters.</p>
			</Field>
			<Field label="Confirm new password">
				<input type="password" bind:value={confirmPw} autocomplete="new-password" class="w-full rounded-md pc-control px-3 py-2 text-sm" />
				{#if confirmPw.length > 0 && confirmPw !== next}
					<p class="mt-1 text-sm text-red-600 dark:text-red-400">Passwords do not match.</p>
				{/if}
			</Field>
			<Button variant="primary" type="submit" disabled={!pwValid || saving}>
				{saving ? 'Saving...' : 'Change password'}
			</Button>
		</form>
	</Card>

	<TotpCard bind:enabled={mfaEnabled} bind:loading={mfaLoading} />
	<PasskeyCard bind:passkeys bind:loading={passkeysLoading} />
</div>
