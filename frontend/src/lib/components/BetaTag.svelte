<script>
	// Marks Bait Box as beta next to the brand name. onDark is for the blue sidebar.
	let { onDark = false } = $props();
</script>

<span
	class="inline-flex shrink-0 items-center rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase leading-none tracking-wide {onDark
		? 'bg-white/15 text-white'
		: 'bg-gray-100 text-gray-500 dark:bg-gray-800 dark:text-gray-400'}"
	title="Bait Box is in beta"
>
	Beta
</span>
