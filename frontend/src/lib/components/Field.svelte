<script>
	// Put a native input, select or textarea with the `pc-control` class inside.
	let { label = '', optional = false, hint = '', hintClass = '', children } = $props();
</script>

<label class="block">
	{#if label}
		<span class="pc-label-row">
			<span class="pc-label">{label}</span>
			{#if optional}<span class="pc-optional">optional</span>{/if}
		</span>
	{/if}
	{@render children?.()}
	{#if hint}<span class="pc-hint {hintClass}">{hint}</span>{/if}
</label>
