<script>
	import { goto } from '$app/navigation';
	import { api } from '$lib/api/api.js';
	import { auth } from '$lib/stores/auth.svelte.js';
	import { toast } from '$lib/stores/toast.svelte.js';
	import BrandMark from '$lib/components/BrandMark.svelte';
	import BetaTag from '$lib/components/BetaTag.svelte';
	import Button from '$lib/components/Button.svelte';
	import Card from '$lib/components/Card.svelte';
	import { getCredential, supported } from '$lib/webauthn.js';
	import { holdLoginPassword } from '$lib/stores/firstLogin.js';

	let username = $state('');
	let password = $state('');
	let code = $state('');
	let mfaStep = $state(false);
	let totpAvailable = $state(false);
	let passkeyAvailable = $state(false);
	let busy = $state(false);

	// throttledMessage turns a 429 reply into a message with the wait from
	// Retry-After, or returns '' for any other reply.
	function throttledMessage(res) {
		if (res.status !== 429) return '';
		const secs = res.retryAfter || res.data?.retryAfter || 0;
		if (secs <= 0) return 'Too many attempts, try again shortly';
		return `Too many attempts, try again in ${secs} ${secs === 1 ? 'second' : 'seconds'}`;
	}

	async function submit(e) {
		e.preventDefault();
		busy = true;
		const res = await api.login(username, password, mfaStep ? code.trim() : '');
		busy = false;
		if (res.ok) {
			auth.set(res.data);
			if (res.data?.passwordChangeRequired) holdLoginPassword(password);
			goto(res.data?.passwordChangeRequired ? '/setup' : '/');
			return;
		}
		const throttled = throttledMessage(res);
		if (throttled) {
			// keep the form as it is, so the operator can retry once the wait passes.
			toast(throttled, 'error');
			return;
		}
		if (res.data?.mfaRequired) {
			mfaStep = true;
			totpAvailable = !!res.data.totpAvailable;
			passkeyAvailable = !!res.data.passkeyAvailable;
			if (code) toast('That code did not match; try again', 'error');
			return;
		}
		mfaStep = false;
		code = '';
		toast(res.error || 'Invalid username or password', 'error');
	}

	async function usePasskey() {
		if (!supported()) {
			toast('This browser does not support passkeys', 'error');
			return;
		}
		busy = true;
		try {
			const begin = await api.passkeyLoginBegin(username, password);
			if (!begin.ok) {
				toast(throttledMessage(begin) || begin.error || 'Could not start passkey login', 'error');
				return;
			}
			const assertion = await getCredential(begin.data);
			const fin = await api.passkeyLoginFinish(assertion);
			if (fin.ok) {
				auth.set(fin.data);
				if (fin.data?.passwordChangeRequired) holdLoginPassword(password);
				goto(fin.data?.passwordChangeRequired ? '/setup' : '/');
			} else {
				toast(throttledMessage(fin) || fin.error || 'Passkey verification failed', 'error');
			}
		} catch (err) {
			toast('Passkey was cancelled or failed', 'error');
		} finally {
			busy = false;
		}
	}
</script>

<div class="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900 text-gray-800 dark:text-gray-100">
	<Card padding="xl" class="w-full max-w-sm shadow-sm">
		<form onsubmit={submit}>
			<div class="mb-6 flex items-center gap-2.5">
				<span class="flex h-9 w-9 items-center justify-center rounded-lg bg-cta-blue text-white">
					<BrandMark class="h-5 w-5" />
				</span>
				<h1 class="font-phudu text-xl font-bold tracking-tight">Bait Box</h1>
				<BetaTag />
			</div>
			{#if !mfaStep}
				<label class="block text-sm mb-3">
					<span class="text-gray-800 dark:text-gray-100">Username</span>
					<input bind:value={username} autocomplete="username" class="pc-control mt-1" />
				</label>
				<label class="block text-sm mb-6">
					<span class="text-gray-800 dark:text-gray-100">Password</span>
					<input bind:value={password} type="password" autocomplete="current-password" class="pc-control mt-1" />
				</label>
				<Button type="submit" variant="primary" disabled={busy} class="w-full">
					{busy ? 'Signing in…' : 'Sign in'}
				</Button>
			{:else}
				{#if passkeyAvailable && totpAvailable}
					<p class="mb-4 text-sm text-gray-700 dark:text-gray-200">Finish signing in with your passkey, or enter a code from your authenticator app. Either one works.</p>
				{/if}
				{#if passkeyAvailable}
					<Button variant="primary" onclick={usePasskey} disabled={busy} class="w-full">
						{busy ? 'Waiting for passkey…' : 'Use a passkey'}
					</Button>
					{#if totpAvailable}
						<div class="my-4 flex items-center gap-3 text-xs text-gray-700 dark:text-gray-200">
							<span class="h-px flex-1 bg-gray-200 dark:bg-gray-800"></span>or<span class="h-px flex-1 bg-gray-200 dark:bg-gray-800"></span>
						</div>
					{/if}
				{/if}
				{#if totpAvailable}
					<label class="block text-sm mb-3">
						<span class="text-gray-800 dark:text-gray-100">Authenticator code</span>
						<!-- svelte-ignore a11y_autofocus -->
						<input bind:value={code} autocomplete="one-time-code" inputmode="numeric" maxlength="6" placeholder="123456" autofocus class="pc-control mt-1 text-center font-mono tracking-[0.3em]" />
					</label>
					<Button type="submit" variant="primary" disabled={busy || code.trim().length < 6} class="w-full">
						{busy ? 'Verifying…' : 'Verify'}
					</Button>
				{/if}
				<Button variant="secondary" onclick={() => { mfaStep = false; code = ''; }} class="mt-2 w-full">Back</Button>
			{/if}
		</form>
	</Card>
</div>
