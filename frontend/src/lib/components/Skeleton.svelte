<script>
	// simple pulsing placeholder rows shown while a list or page loads, so the
	// screen does not flash blank before data arrives.
	let { rows = 4 } = $props();
</script>

<div class="divide-y divide-gray-100 dark:divide-gray-800">
	{#each Array(rows) as _, i (i)}
		<div class="flex items-center gap-4 px-4 py-4">
			<div class="h-4 w-1/4 animate-pulse rounded bg-gray-200 dark:bg-gray-800"></div>
			<div class="h-4 w-1/3 animate-pulse rounded bg-gray-200 dark:bg-gray-800"></div>
			<div class="ml-auto h-4 w-16 animate-pulse rounded bg-gray-200 dark:bg-gray-800"></div>
		</div>
	{/each}
</div>
