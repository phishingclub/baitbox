<script>
	// A quiet status marker: a small colored dot and a plain label, not a tinted pill
	// with a ring. The dot carries the state color; the label stays in readable body
	// text so a row of these reads calmly instead of glowing. tone picks the dot.
	let { tone = 'neutral', children } = $props();

	const DOT = {
		on: 'bg-emerald-500',
		active: 'bg-emerald-500',
		public: 'bg-emerald-500',
		off: 'bg-gray-400 dark:bg-gray-400',
		warn: 'bg-amber-500',
		yanked: 'bg-amber-500',
		private: 'bg-gray-400 dark:bg-gray-400',
		danger: 'bg-red-500',
		revoked: 'bg-red-500',
		expired: 'bg-red-500',
		failed: 'bg-red-500',
		info: 'bg-cta-blue dark:bg-highlight-blue',
		latest: 'bg-cta-blue dark:bg-highlight-blue',
		neutral: 'bg-gray-400 dark:bg-gray-400'
	};
</script>

<span class="inline-flex items-center gap-1.5 whitespace-nowrap text-xs font-medium capitalize text-gray-700 dark:text-gray-200">
	<span class="h-1.5 w-1.5 shrink-0 rounded-full {DOT[tone] ?? DOT.neutral}"></span>
	{@render children?.()}
</span>
