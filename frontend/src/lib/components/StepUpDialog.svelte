<script>
	// Asks the operator to prove it is them before a second factor change. The
	// server says which proofs fit: a code from the authenticator app when two
	// factor is on, a passkey when one is registered, and the current password only
	// when no second factor exists. run() opens the dialog and resolves true once
	// the server granted the step up, false when the operator cancelled.
	// withStepUp(call) runs an API call and, when the server answers that a step up
	// is needed, asks for it and runs the call once more. It resolves null when the
	// operator cancelled, so the caller stops without showing an error.
	import { tick } from 'svelte';
	import { api } from '$lib/api/api.js';
	import { toast } from '$lib/stores/toast.svelte.js';
	import { getCredential, supported } from '$lib/webauthn.js';
	import Alert from '$lib/components/Alert.svelte';
	import Button from '$lib/components/Button.svelte';
	import Field from '$lib/components/Field.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import PasswordInput from '$lib/components/PasswordInput.svelte';

	const formId = `stepup-${Math.random().toString(36).slice(2, 8)}`;

	let open = $state(false);
	let methods = $state({ totp: false, passkey: false, password: false });
	let code = $state('');
	let password = $state('');
	let busy = $state(false);
	let error = $state('');
	let codeEl = $state(null);
	let resolver = null;

	function settle(result) {
		const r = resolver;
		resolver = null;
		open = false;
		code = '';
		password = '';
		error = '';
		busy = false;
		r?.(result);
	}

	export async function run() {
		if (resolver) settle(false);
		const r = await api.stepUp.status();
		if (!r.ok) {
			toast(r.error || 'Could not check how to confirm it is you', 'error');
			return false;
		}
		methods = { totp: !!r.data?.totp, passkey: !!r.data?.passkey, password: !!r.data?.password };
		if (!methods.totp && !methods.passkey && !methods.password) {
			toast('There is no way to confirm it is you on this account', 'error');
			return false;
		}
		code = '';
		password = '';
		error = '';
		busy = false;
		open = true;
		return new Promise((res) => {
			resolver = res;
		});
	}

	export async function withStepUp(call) {
		let r = await call();
		if (r.status === 403 && r.data?.stepUpRequired) {
			if (!(await run())) return null;
			r = await call();
		}
		return r;
	}

	const canSubmit = $derived(methods.totp ? code.length === 6 : methods.password && password.length > 0);

	// keep only digits so a pasted code with spaces still fits the 6 digit limit
	function onCodeInput(e) {
		code = e.currentTarget.value.replace(/\D/g, '').slice(0, 6);
	}

	async function submit(e) {
		e.preventDefault();
		if (busy || !canSubmit) return;
		const pending = resolver;
		busy = true;
		error = '';
		const r = await api.stepUp.verify(methods.totp ? { code } : { password });
		// the operator cancelled while the check ran
		if (!pending || pending !== resolver) return;
		busy = false;
		if (r.ok) {
			settle(true);
			return;
		}
		error = r.error || 'That did not match';
		if (methods.totp) {
			code = '';
			await tick();
			codeEl?.focus();
		}
	}

	async function usePasskey() {
		if (busy) return;
		if (!supported()) {
			error = 'This browser does not support passkeys';
			return;
		}
		const pending = resolver;
		const cancelled = () => !pending || pending !== resolver;
		busy = true;
		error = '';
		try {
			const begin = await api.stepUp.passkeyBegin();
			if (cancelled()) return;
			if (!begin.ok) {
				error = begin.error || 'Could not start the passkey check';
				return;
			}
			const cred = await getCredential(begin.data);
			// no grant is asked for once the operator cancelled
			if (cancelled()) return;
			const fin = await api.stepUp.passkeyFinish(cred);
			if (cancelled()) return;
			if (fin.ok) {
				settle(true);
				return;
			}
			error = fin.error || 'Passkey verification failed';
		} catch (_) {
			if (!cancelled()) error = 'The passkey check was cancelled or failed';
		} finally {
			if (!cancelled()) busy = false;
		}
	}
</script>

<Modal bind:open title="Confirm it is you" size="sm" onclose={() => settle(false)}>
	<form id={formId} class="space-y-4" onsubmit={submit}>
		{#if methods.totp}
			<p class="pc-desc">Enter a current code from your authenticator app.</p>
			<Field label="Code">
				<!-- svelte-ignore a11y_autofocus -->
				<input
					bind:this={codeEl}
					value={code}
					oninput={onCodeInput}
					inputmode="numeric"
					autocomplete="one-time-code"
					maxlength="6"
					placeholder="123456"
					autofocus
					aria-invalid={error ? 'true' : undefined}
					class="pc-control font-mono tracking-[0.2em]"
				/>
			</Field>
			{#if methods.passkey}
				<div class="flex items-center gap-3">
					<span class="pc-desc">Or</span>
					<Button variant="secondary" size="xs" onclick={usePasskey} disabled={busy}>Use a passkey instead</Button>
				</div>
			{/if}
		{:else if methods.passkey}
			<p class="pc-desc">Use one of your passkeys to continue.</p>
		{:else}
			<p class="pc-desc">Enter your current password to continue.</p>
			<Field label="Current password">
				<PasswordInput bind:value={password} autocomplete="current-password" autofocus aria-invalid={error ? 'true' : undefined} />
			</Field>
		{/if}
		{#if error}
			<div role="alert">
				<Alert variant="danger">{error}</Alert>
			</div>
		{/if}
	</form>
	{#snippet footer()}
		<Button variant="secondary" onclick={() => settle(false)}>Cancel</Button>
		{#if methods.totp || methods.password}
			<Button variant="primary" type="submit" form={formId} disabled={busy || !canSubmit}>{busy ? 'Checking…' : 'Confirm'}</Button>
		{:else if methods.passkey}
			<Button variant="primary" onclick={usePasskey} disabled={busy}>{busy ? 'Waiting…' : 'Use passkey'}</Button>
		{/if}
	{/snippet}
</Modal>
