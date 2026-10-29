<script>
	// Consistent empty / no results state for list cards. Centered message with an
	// optional action passed as children. Sits inside the list card, so it carries
	// no border of its own.
	let { message, children } = $props();
</script>

<div class="p-10 text-center">
	<p class="pc-desc">{message}</p>
	{#if children}<div class="mt-3 flex justify-center">{@render children()}</div>{/if}
</div>
