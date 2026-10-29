<script>
	// The page title row: the h1, an optional Help badge beside it, and an optional
	// actions cluster pushed to the right. Used on every list and detail page so the
	// header reads and aligns the same everywhere.
	let { title, help, actions, class: cls = '' } = $props();
</script>

<div class="flex flex-wrap items-center justify-between gap-3 {cls}">
	<div class="flex items-center gap-2">
		<h1 class="pc-h1">{title}</h1>
		{@render help?.()}
	</div>
	{#if actions}<div class="flex flex-wrap items-center gap-2">{@render actions()}</div>{/if}
</div>
