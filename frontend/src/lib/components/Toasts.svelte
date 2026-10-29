<script>
	import { fly } from 'svelte/transition';
	import { toastStore } from '$lib/stores/toast.svelte.js';
	import { motionDuration } from '$lib/utils/motion.js';
	const color = (t) =>
		t === 'error'
			? 'border-red-400 bg-red-50 text-red-800 dark:bg-red-950 dark:text-red-200'
			: t === 'success'
				? 'border-emerald-400 bg-emerald-50 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-200'
				: 'border-gray-300 bg-white text-gray-900 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-100';
</script>

<div class="fixed bottom-4 right-4 z-50 flex max-w-sm flex-col gap-2">
	{#each toastStore.items as t (t.id)}
		<div
			transition:fly={{ y: 12, duration: motionDuration(150) }}
			role={t.type === 'error' ? 'alert' : 'status'}
			aria-live={t.type === 'error' ? 'assertive' : 'polite'}
			class="flex items-start gap-3 rounded-lg border px-4 py-2 text-sm shadow-lg {color(t.type)}"
		>
			<span class="min-w-0 flex-1 break-words">{t.message}</span>
			<button
				type="button"
				onclick={() => toastStore.remove(t.id)}
				aria-label="Dismiss"
				class="shrink-0 leading-none opacity-60 hover:opacity-100"
			>✕</button>
		</div>
	{/each}
</div>
