<script>
	// edits an array of strings as removable chips. each value is one discrete entry,
	// so a value may contain commas, spaces, colons or quotes; there is no delimiter
	// parsing. value is the current array; onChange receives a new array on every
	// mutation so a parent using either direct assignment or an immutable spread can
	// wire it. the prop array is never mutated in place.
	let { value = [], onChange = () => {}, placeholder = 'Add a value, press Enter' } = $props();

	let draft = $state('');

	// the committed values as the parent holds them. a non array prop reads as empty.
	const items = $derived(Array.isArray(value) ? value : []);

	function add(raw) {
		const t = String(raw ?? '').trim();
		if (!t) return;
		if (!items.includes(t)) onChange([...items, t]);
		draft = '';
	}
	function removeAt(i) {
		onChange(items.filter((_, idx) => idx !== i));
	}
	function onKey(e) {
		if (e.key === 'Enter') {
			e.preventDefault();
			add(draft);
		} else if (e.key === 'Backspace' && !draft && items.length) {
			removeAt(items.length - 1);
		}
	}
</script>

<div class="mt-1 flex flex-wrap items-center gap-1.5 rounded-md border border-gray-300 bg-white p-1.5 dark:border-gray-700 dark:bg-gray-950">
	{#each items as item, i (i)}
		<span class="inline-flex items-center gap-1 rounded bg-gray-100 px-1.5 py-0.5 text-xs text-gray-800 dark:bg-gray-800 dark:text-gray-100">
			{item}
			<button type="button" onclick={() => removeAt(i)} title="Remove value" aria-label={`Remove ${item}`} class="ml-0.5 opacity-60 hover:opacity-100">&times;</button>
		</span>
	{/each}
	<input
		bind:value={draft}
		onkeydown={onKey}
		onblur={() => add(draft)}
		{placeholder}
		class="min-w-[8rem] flex-1 border-0 bg-transparent px-1 py-0.5 text-sm focus:outline-none focus:ring-0"
	/>
</div>
