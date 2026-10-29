<script>
	// onchange fires after checked updates.
	let { checked = $bindable(false), label = '', disabled = false, onchange = undefined, class: cls = '' } = $props();
</script>

<label class="flex items-center gap-2 text-sm {disabled ? 'opacity-50' : ''} {cls}">
	<input
		type="checkbox"
		bind:checked
		{disabled}
		onchange={onchange}
		class="rounded border-gray-300 text-cta-blue focus:ring-cta-blue/40 dark:border-gray-700"
	/>
	{#if label}<span class="text-gray-800 dark:text-gray-100">{label}</span>{/if}
</label>
