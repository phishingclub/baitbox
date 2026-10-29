<script>
	// One modal shell for every dialog: a fading backdrop, a centered card panel, body
	// scroll lock, a focus trap, initial focus and Escape to close. open is bindable so
	// a page drives it with a boolean.
	import { fade } from 'svelte/transition';
	import { motionDuration } from '$lib/utils/motion.js';
	import { tick } from 'svelte';

	let {
		open = $bindable(false),
		title = '',
		size = 'md',
		onclose = undefined,
		children,
		footer
	} = $props();

	const SIZE = { sm: 'max-w-sm', md: 'max-w-md', lg: 'max-w-lg' };
	const titleId = `modal-${Math.random().toString(36).slice(2, 8)}`;
	let dialogEl = $state(null);
	let prevFocus = null;

	function close() {
		open = false;
		onclose?.();
	}
	function focusable() {
		if (!dialogEl) return [];
		return Array.from(
			dialogEl.querySelectorAll(
				'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
			)
		);
	}
	function onKey(e) {
		if (e.key === 'Escape') {
			e.preventDefault();
			close();
			return;
		}
		if (e.key === 'Tab') {
			const els = focusable();
			if (!els.length) return;
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
		if (!open) return;
		prevFocus = document.activeElement;
		document.body.style.overflow = 'hidden';
		window.addEventListener('keydown', onKey);
		tick().then(() => focusable()[0]?.focus());
		return () => {
			window.removeEventListener('keydown', onKey);
			document.body.style.overflow = '';
			if (prevFocus && typeof prevFocus.focus === 'function') prevFocus.focus();
		};
	});
</script>

{#if open}
	<div
		transition:fade={{ duration: motionDuration(120) }}
		class="fixed inset-0 z-40 bg-black/50"
		onclick={close}
		aria-hidden="true"
	></div>
	<div class="fixed inset-0 z-50 flex items-center justify-center p-4" role="dialog" aria-modal="true" aria-labelledby={title ? titleId : undefined}>
		<div bind:this={dialogEl} class="w-full {SIZE[size] ?? SIZE.md} pc-card p-6 shadow-xl">
			{#if title}<h2 id={titleId} class="font-phudu text-lg font-bold text-gray-900 dark:text-white">{title}</h2>{/if}
			<div class={title ? 'mt-2' : ''}>{@render children?.()}</div>
			{#if footer}<div class="mt-6 flex justify-end gap-2">{@render footer()}</div>{/if}
		</div>
	</div>
{/if}
