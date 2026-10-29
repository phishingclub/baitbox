<script>
	// The surface colors live in the pc-card utility so every card matches. Use
	// padding none when the card manages its own sections.
	let { padding = 'md', class: cls = '', children, ...rest } = $props();
	const PAD = { none: '', sm: 'p-4', md: 'p-5', lg: 'p-6', xl: 'p-8' };
	const klass = $derived(`pc-card ${PAD[padding] ?? PAD.md} ${cls}`.trim());
</script>

<div class={klass} {...rest}>{@render children?.()}</div>
