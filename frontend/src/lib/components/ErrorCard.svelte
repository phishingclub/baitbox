<script>
	// The load failure block: a centered message with a Retry action, so a failed fetch
	// looks the same everywhere. bare drops the card surface for when it renders INSIDE
	// an existing card (a list container), avoiding a double border.
	import Button from './Button.svelte';
	let { message = 'Something went wrong', onretry = undefined, bare = false, class: cls = '' } = $props();
</script>

<div class="{bare ? '' : 'pc-card'} p-8 text-center {cls}">
	<p class="text-sm text-red-600 dark:text-red-400">{message}</p>
	{#if onretry}
		<div class="mt-3"><Button variant="secondary" onclick={onretry}>Retry</Button></div>
	{/if}
</div>
