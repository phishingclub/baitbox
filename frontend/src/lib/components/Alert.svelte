<script>
	// A notice banner. Colour is restrained: a neutral card border, one coloured accent
	// on the left edge and a matching icon, a very soft tint, and body text that stays
	// neutral grey so the message reads clearly instead of a block of tinted colour.
	let { variant = 'warning', title = '', children, class: cls = '' } = $props();

	const V = {
		info: { bar: 'border-l-cta-blue dark:border-l-highlight-blue', icon: 'text-cta-blue dark:text-highlight-blue', tint: 'bg-gray-50 dark:bg-gray-900/50' },
		warning: { bar: 'border-l-amber-500', icon: 'text-amber-600 dark:text-amber-400', tint: 'bg-amber-50/60 dark:bg-amber-500/10' },
		danger: { bar: 'border-l-red-500', icon: 'text-red-600 dark:text-red-400', tint: 'bg-red-50/60 dark:bg-red-500/10' },
		success: { bar: 'border-l-emerald-500', icon: 'text-emerald-600 dark:text-emerald-400', tint: 'bg-emerald-50/60 dark:bg-emerald-500/10' }
	};
	const v = $derived(V[variant] ?? V.warning);

	// one simple line icon per variant.
	const ICON = {
		info: 'M12 9v4m0 4h.01M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z',
		warning: 'M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z',
		danger: 'M12 8v4m0 4h.01M8.6 3h6.8L21 8.6v6.8L15.4 21H8.6L3 15.4V8.6L8.6 3z',
		success: 'M20 6 9 17l-5-5'
	};
</script>

<div class="flex items-start gap-3 rounded-lg border border-l-4 border-gray-200 {v.bar} {v.tint} px-4 py-3 dark:border-gray-800 {cls}">
	<svg class="mt-0.5 h-4 w-4 shrink-0 {v.icon}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
		<path d={ICON[variant] ?? ICON.warning} />
	</svg>
	<div class="text-sm text-gray-700 dark:text-gray-200">
		{#if title}<span class="font-semibold text-gray-900 dark:text-white">{title}</span>{' '}{/if}{@render children?.()}
	</div>
</div>
