<script>
	// a styled confirm modal driven by the confirm store, replacing native
	// confirm() for destructive actions. handles escape, overlay click, initial
	// focus, a focus trap between its two buttons, and body scroll lock.
	import { fade } from 'svelte/transition';
	import { motionDuration } from '$lib/utils/motion.js';
	import { tick } from 'svelte';
	import { confirmState, settleConfirm } from '$lib/stores/confirm.svelte.js';
	import Button from '$lib/components/Button.svelte';

	let dialogEl;
	let confirmBtn;
	let prevFocus = null;

	function focusable() {
		if (!dialogEl) return [];
		return Array.from(dialogEl.querySelectorAll('button:not([disabled])'));
	}

	function onKey(e) {
		if (e.key === 'Escape') {
			e.preventDefault();
			settleConfirm(false);
			return;
		}
		if (e.key === 'Tab') {
			const els = focusable();
			if (els.length === 0) return;
			const first = els[0];
			const last = els[els.length - 1];
			if (e.shiftKey && document.activeElement === first) {
				e.preventDefault();
				last.focus();
			} else if (!e.shiftKey && document.activeElement === last) {
				e.preventDefault();
				first.focus();
			}
		}
	}

	$effect(() => {
		if (!confirmState.open) return;
		prevFocus = document.activeElement;
		document.body.style.overflow = 'hidden';
		window.addEventListener('keydown', onKey);
		tick().then(() => confirmBtn?.focus());
		return () => {
			window.removeEventListener('keydown', onKey);
			document.body.style.overflow = '';
			if (prevFocus && typeof prevFocus.focus === 'function') prevFocus.focus();
		};
	});
</script>

{#if confirmState.open}
	<div
		transition:fade={{ duration: motionDuration(120) }}
		class="fixed inset-0 z-[60] bg-black/50"
		onclick={() => settleConfirm(false)}
		aria-hidden="true"
	></div>
	<!-- the confirm sits above any open Modal (z-50), so a confirm raised from inside a
	     modal, such as the move or rename dependents warning, is never hidden behind it. -->
	<div class="fixed inset-0 z-[70] flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-labelledby="confirm-title">
		<div
			bind:this={dialogEl}
			class="w-full max-w-sm rounded-xl border border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-950 p-6 shadow-xl"
		>
			<h2 id="confirm-title" class="font-phudu text-lg font-bold text-gray-900 dark:text-gray-100">{confirmState.title}</h2>
			{#if confirmState.body}
				<p class="mt-2 text-sm text-gray-700 dark:text-gray-100">{confirmState.body}</p>
			{/if}
			<div class="mt-6 flex justify-end gap-2">
				<Button
					variant="secondary"
					onclick={() => settleConfirm(false)}
				>Cancel</Button>
				<button
					bind:this={confirmBtn}
					type="button"
					onclick={() => settleConfirm(true)}
					class="rounded-md bg-red-600 px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-red-500"
				>{confirmState.confirmLabel}</button>
			</div>
		</div>
	</div>
{/if}
