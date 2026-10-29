<script>
	// First login setup. Step 1 replaces an issued password with one the operator
	// chose; the server blocks every other admin route until that is done, so there
	// is no way past it except logging out. Step 2 offers an authenticator app and
	// a passkey, both optional, using the same cards as Settings.
	import { goto } from '$app/navigation';
	import { api } from '$lib/api/api.js';
	import { auth } from '$lib/stores/auth.svelte.js';
	import { toast } from '$lib/stores/toast.svelte.js';
	import BrandMark from '$lib/components/BrandMark.svelte';
	import Button from '$lib/components/Button.svelte';
	import Card from '$lib/components/Card.svelte';
	import Field from '$lib/components/Field.svelte';
	import TotpCard from '$lib/components/TotpCard.svelte';
	import PasskeyCard from '$lib/components/PasskeyCard.svelte';
	import PasswordInput from '$lib/components/PasswordInput.svelte';
	import { takeLoginPassword } from '$lib/stores/firstLogin.js';

	let step = $state(1);

	// the seeded account must also replace the default username every install shares
	const mustRename = (auth.operator?.username ?? '').toLowerCase() === 'admin';
	let username = $state('');
	// the password typed at login; the field is only asked for when it is gone
	let current = $state(takeLoginPassword());
	const askCurrent = current === '';
	let next = $state('');
	let confirmPw = $state('');
	let saving = $state(false);

	let mfaEnabled = $state(false);
	let mfaLoading = $state(true);
	let passkeys = $state([]);
	let passkeysLoading = $state(true);
	const hasFactor = $derived(mfaEnabled || passkeys.length > 0);

	const tooShort = $derived(next.length > 0 && next.length < 12);
	const mismatch = $derived(confirmPw.length > 0 && confirmPw !== next);
	const nameTrim = $derived(username.trim());
	const nameReserved = $derived(nameTrim.toLowerCase() === 'admin');
	const nameBad = $derived(nameTrim.length > 0 && (nameTrim.length < 3 || nameTrim.length > 64 || nameReserved));
	const nameValid = $derived(!mustRename || (nameTrim.length >= 3 && nameTrim.length <= 64 && !nameReserved));
	const pwValid = $derived(nameValid && current.length > 0 && next.length >= 12 && next === confirmPw);

	async function changePassword(e) {
		e.preventDefault();
		if (!pwValid || saving) return;
		saving = true;
		const res = await api.changePassword(current, next, mustRename ? nameTrim : '');
		saving = false;
		if (res.ok && res.data?.signedOut) {
			toast('Password changed. Please sign in again.', 'success');
			auth.clear();
			goto('/login');
			return;
		}
		if (!res.ok) {
			toast(res.error || 'Could not change password', 'error');
			return;
		}
		current = '';
		next = '';
		confirmPw = '';
		if (auth.operator) auth.set({ ...auth.operator, username: res.data?.username || auth.operator.username, passwordChangeRequired: false });
		toast('Password changed', 'success');
		step = 2;
	}

	async function logout() {
		await api.logout();
		auth.clear();
		goto('/login');
	}
</script>

<div class="min-h-screen bg-gray-50 px-4 py-10 text-gray-800 dark:bg-gray-900 dark:text-gray-100 sm:py-16">
	<div class="mx-auto w-full {step === 1 ? 'max-w-md' : 'max-w-3xl'}">
		<div class="mb-6 flex items-center justify-between gap-3">
			<div class="flex items-center gap-2.5">
				<span class="flex h-9 w-9 items-center justify-center rounded-lg bg-cta-blue text-white">
					<BrandMark class="h-5 w-5" />
				</span>
				<span class="font-phudu text-xl font-bold tracking-tight">Bait Box</span>
			</div>
			<button type="button" onclick={logout} class="text-sm font-medium text-gray-700 underline-offset-4 hover:text-gray-900 hover:underline dark:text-gray-200 dark:hover:text-white">Log out</button>
		</div>

		<!-- progress -->
		<ol class="mb-6 flex items-center gap-3 text-sm" aria-label="Setup progress">
			{#each [{ n: 1, label: 'Password' }, { n: 2, label: 'Second factor' }] as s, i}
				{#if i > 0}<li aria-hidden="true" class="h-px w-8 bg-gray-300 dark:bg-gray-700 sm:w-12"></li>{/if}
				<li class="flex items-center gap-2" aria-current={step === s.n ? 'step' : undefined}>
					<span
						class="flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-xs font-semibold {step > s.n
							? 'bg-emerald-600 text-white'
							: step === s.n
								? 'bg-cta-blue text-white'
								: 'border border-gray-300 text-gray-700 dark:border-gray-600 dark:text-gray-200'}"
					>
						{#if step > s.n}
							<svg class="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 6 9 17l-5-5" /></svg>
						{:else}{s.n}{/if}
					</span>
					<span class={step === s.n ? 'font-semibold text-gray-900 dark:text-white' : 'text-gray-700 dark:text-gray-200'}>{s.label}</span>
				</li>
			{/each}
			<li class="ml-auto text-gray-700 dark:text-gray-200">Step {step} of 2</li>
		</ol>

		{#if step === 1}
			<Card padding="xl" class="shadow-sm">
				<h1 class="pc-card-title">{mustRename ? 'Set your own login' : 'Set your own password'}</h1>
				<p class="mt-2 pc-desc">{mustRename ? 'Choose a new username and password.' : 'Choose a new password.'}</p>
				<form class="mt-6 space-y-4" onsubmit={changePassword}>
					{#if mustRename}
						<Field label="New username" hint={nameReserved ? 'Choose a name other than admin.' : '3 to 64 characters. You sign in with this from now on.'} hintClass={nameBad ? 'text-red-600 dark:text-red-400' : ''}>
							<!-- svelte-ignore a11y_autofocus -->
							<input bind:value={username} autocomplete="username" autofocus class="pc-control" />
						</Field>
					{/if}
					{#if askCurrent}
						<Field label="Current password" hint="The password you just signed in with.">
							<PasswordInput bind:value={current} autocomplete="current-password" autofocus={!mustRename} />
						</Field>
					{/if}
					<Field label="New password" hint="At least 12 characters." hintClass={tooShort ? 'text-red-600 dark:text-red-400' : ''}>
						<PasswordInput bind:value={next} autocomplete="new-password" autofocus={!mustRename && !askCurrent} />
					</Field>
					<Field label="Confirm new password" hint={mismatch ? 'Passwords do not match.' : ''} hintClass="text-red-600 dark:text-red-400">
						<PasswordInput bind:value={confirmPw} autocomplete="new-password" />
					</Field>
					<Button variant="primary" type="submit" disabled={!pwValid || saving} class="w-full">
						{saving ? 'Saving…' : 'Set password and continue'}
					</Button>
				</form>
			</Card>
		{:else}
			<div class="mb-5">
				<h1 class="text-2xl font-semibold text-gray-900 dark:text-white">Add a second factor</h1>
				<p class="mt-2 pc-desc">
					Optional. You can also do this later in Settings.
				</p>
			</div>
			<div class="grid items-start gap-6 md:grid-cols-2">
				<TotpCard title="Authenticator app" allowDisable={false} bind:enabled={mfaEnabled} bind:loading={mfaLoading} />
				<PasskeyCard allowRemove={false} bind:passkeys bind:loading={passkeysLoading} />
			</div>
			<div class="mt-6 flex flex-col-reverse gap-3 sm:flex-row sm:items-center sm:justify-end">
				{#if hasFactor}
					<Button variant="primary" onclick={() => goto('/')}>Continue to dashboard</Button>
				{:else}
					<Button variant="secondary" onclick={() => goto('/')}>Skip for now</Button>
				{/if}
			</div>
		{/if}
	</div>
</div>
