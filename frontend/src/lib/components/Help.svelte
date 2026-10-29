<script>
	// A small outlined "?" badge (matching the phishingclub heading help) that opens a
	// modal with short, to the point help instead of linking out to docs. Pass the help
	// body as children; title names the modal.
	import { fade } from 'svelte/transition';
	import { motionDuration } from '$lib/utils/motion.js';
	import { tick } from 'svelte';

	let { title = 'Help', children } = $props();

	let open = $state(false);
	let closeBtn;
	let prevFocus = null;

	function openHelp() {
		prevFocus = document.activeElement;
		open = true;
		tick().then(() => closeBtn?.focus());
	}
	function close() {
		open = false;
		if (prevFocus && typeof prevFocus.focus === 'function') prevFocus.focus();
	}
	function onKey(e) {
		if (e.key === 'Escape') {
			e.preventDefault();
			close();
		}
	}

	$effect(() => {
		if (!open) return;
		document.body.style.overflow = 'hidden';
		window.addEventListener('keydown', onKey);
		return () => {
			window.removeEventListener('keydown', onKey);
			document.body.style.overflow = '';
		};
	});
</script>

<button
	type="button"
	onclick={openHelp}
	title={`Help: ${title}`}
	aria-label={`Help: ${title}`}
	class="inline-flex h-[1.1rem] w-[1.1rem] shrink-0 items-center justify-center rounded-full border border-gray-400 text-[11px] font-bold leading-none text-gray-700 transition-colors hover:border-cta-blue hover:bg-cta-blue hover:text-white dark:border-gray-400 dark:text-gray-200 dark:hover:border-highlight-blue dark:hover:bg-highlight-blue dark:hover:text-gray-950"
>?</button>

{#if open}
	<div
		transition:fade={{ duration: motionDuration(120) }}
		class="fixed inset-0 z-40 bg-black/50"
		onclick={close}
		aria-hidden="true"
	></div>
	<div
		class="fixed inset-0 z-50 flex items-center justify-center p-4"
		role="dialog"
		aria-modal="true"
		aria-labelledby="help-title"
	>
		<div
			class="flex max-h-[85vh] w-full max-w-lg flex-col rounded-xl border border-gray-200 bg-white shadow-xl dark:border-gray-800 dark:bg-gray-950"
		>
			<div class="flex items-start justify-between gap-4 border-b border-gray-100 px-6 py-4 dark:border-gray-800">
				<h2 id="help-title" class="font-phudu text-lg font-bold text-gray-900 dark:text-gray-100">{title}</h2>
				<button
					bind:this={closeBtn}
					type="button"
					onclick={close}
					aria-label="Close help"
					class="shrink-0 rounded-md border border-gray-300 px-2 py-0.5 text-sm font-medium text-gray-700 hover:bg-gray-100 dark:border-gray-700 dark:text-gray-200 dark:hover:bg-gray-800"
				>Close</button>
			</div>
			<div class="help-body overflow-y-auto px-6 py-4 text-sm leading-relaxed text-gray-800 dark:text-gray-100">
				{@render children?.()}
			</div>
		</div>
	</div>
{/if}

<style>
	/* readable rhythm for help content without each caller repeating classes */
	.help-body :global(p + p) {
		margin-top: 0.75rem;
	}
	.help-body :global(ul) {
		margin-top: 0.5rem;
		list-style: disc;
		padding-left: 1.1rem;
	}
	.help-body :global(li + li) {
		margin-top: 0.3rem;
	}
	.help-body :global(code) {
		border-radius: 0.25rem;
		background-color: rgb(243 244 246);
		padding: 0.05rem 0.3rem;
		font-size: 0.8125rem;
	}
	:global(.dark) .help-body :global(code) {
		background-color: rgb(31 41 55);
	}
	.help-body :global(strong) {
		font-weight: 600;
		color: rgb(17 24 39);
	}
	:global(.dark) .help-body :global(strong) {
		color: rgb(255 255 255);
	}
</style>
