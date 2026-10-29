<script>
	// Shared list footer: "showing x to y of n" plus Prev/Next. Works for both
	// client paginated lists and server paged ones; the parent handles the page
	// change through onchange(nextPageNum). Renders nothing until there is more
	// than one page.
	let { pageNum, pageSize, total, onchange } = $props();
	const totalPages = $derived(Math.max(1, Math.ceil(total / pageSize)));
	const from = $derived(total === 0 ? 0 : (pageNum - 1) * pageSize + 1);
	const to = $derived(Math.min(pageNum * pageSize, total));
</script>

{#if total > pageSize}
	<div class="flex items-center justify-between gap-3 border-t border-gray-100 px-4 py-3 text-sm dark:border-gray-800">
		<span class="pc-label">Showing {from} to {to} of {total.toLocaleString()}</span>
		<div class="flex items-center gap-2">
			<button type="button" onclick={() => onchange(Math.max(1, pageNum - 1))} disabled={pageNum === 1} class="pc-pager-btn">Prev</button>
			<span class="pc-label">Page {pageNum} of {totalPages}</span>
			<button type="button" onclick={() => onchange(Math.min(totalPages, pageNum + 1))} disabled={pageNum >= totalPages} class="pc-pager-btn">Next</button>
		</div>
	</div>
{/if}
