<script>
	// password field with a button that shows or hides the typed value.
	let { value = $bindable(''), autocomplete = 'current-password', autofocus = false, ...rest } = $props();
	let shown = $state(false);
</script>

<div class="relative">
	<!-- svelte-ignore a11y_autofocus -->
	<input type={shown ? 'text' : 'password'} bind:value {autocomplete} {autofocus} spellcheck="false" class="pc-control pr-10" {...rest} />
	<button
		type="button"
		onclick={() => (shown = !shown)}
		aria-label={shown ? 'Hide password' : 'Show password'}
		aria-pressed={shown}
		title={shown ? 'Hide password' : 'Show password'}
		class="absolute inset-y-0 right-0 flex w-10 items-center justify-center rounded-r-md text-gray-500 hover:text-gray-800 focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-blue-500 dark:text-gray-400 dark:hover:text-gray-100"
	>
		{#if shown}
			<svg class="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9.88 9.88a3 3 0 1 0 4.24 4.24" /><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68" /><path d="M6.61 6.61A13.53 13.53 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61" /><path d="m2 2 20 20" /></svg>
		{:else}
			<svg class="h-4 w-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z" /><circle cx="12" cy="12" r="3" /></svg>
		{/if}
	</button>
</div>
