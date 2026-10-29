<script>
	import { NS_COLORS, nsDotClass } from '$lib/utils/nsColor.js';
	import ColorSwatchPicker from './ColorSwatchPicker.svelte';

	// value is the selected color key (a named token or a custom #rrggbb), or '' for
	// no color.
	let { value = $bindable('') } = $props();
</script>

<div class="mt-1 flex flex-wrap items-center gap-1.5">
	<button
		type="button"
		onclick={() => (value = '')}
		title="No color"
		aria-label="No color"
		aria-pressed={value === ''}
		class="flex h-6 w-6 items-center justify-center rounded-full border {value === ''
			? 'border-active-blue ring-2 ring-active-blue/40'
			: 'border-gray-300 dark:border-gray-600'}"
	>
		<span class="h-2.5 w-2.5 rounded-full {nsDotClass('')}"></span>
	</button>
	{#each NS_COLORS as c}
		<button
			type="button"
			onclick={() => (value = c.key)}
			title={c.key}
			aria-label={c.key}
			aria-pressed={value === c.key}
			class="flex h-6 w-6 items-center justify-center rounded-full border {value === c.key
				? 'border-active-blue ring-2 ring-active-blue/40'
				: 'border-transparent'}"
		>
			<span class="h-3.5 w-3.5 rounded-full {c.dot}"></span>
		</button>
	{/each}
	<!-- custom color opens our own popover so it never lands off screen near the edge. -->
	<ColorSwatchPicker value={value} onpick={(hex) => (value = hex)} />
</div>
