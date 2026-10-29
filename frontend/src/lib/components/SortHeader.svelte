<script>
	// A sortable table header cell. Clicking asks the parent to sort by `column`;
	// the parent owns sortKey/sortDir and toggles direction. Shows an arrow and
	// sets aria-sort for the active column.
	let { label, column, sortKey, sortDir, onsort, align = 'left' } = $props();
	const active = $derived(sortKey === column);
	const arrow = $derived(active ? (sortDir === 'asc' ? ' ▲' : ' ▼') : '');
	const ariaSort = $derived(active ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none');
</script>

<th class="px-4 py-2 font-medium {align === 'right' ? 'text-right' : 'text-left'}" aria-sort={ariaSort}>
	<button
		type="button"
		onclick={() => onsort(column)}
		aria-label={`Sort by ${label}`}
		class="inline-flex select-none items-center font-medium hover:text-gray-900 dark:hover:text-white">{label}{arrow}</button
	>
</th>
