<script>
	// The menu renders fixed to the viewport, anchored to the button, so a table's
	// overflow does not clip it. Any click inside closes it after the item runs.
	import { menu } from '$lib/stores/menu.svelte.js';

	let { id, label = 'Row actions', children } = $props();
	let wrap = $state(null);
	let btn = $state(null);
	let menuEl = $state(null);
	let pos = $state({ top: 0, left: 0 });
	const open = $derived(menu.openId === id);

	// anchor the fixed menu to the button: align its right edge under the button, and
	// flip above when it would run past the viewport bottom.
	function place() {
		if (!btn) return;
		const r = btn.getBoundingClientRect();
		const width = 176; // matches pc-menu w-44
		let left = Math.max(8, r.right - width);
		let top = r.bottom + 4;
		const h = menuEl ? menuEl.offsetHeight : 0;
		if (h && top + h > window.innerHeight - 8) top = Math.max(8, r.top - h - 4);
		pos = { top, left };
	}

	$effect(() => {
		if (!open) return;
		requestAnimationFrame(place);
		const onKey = (e) => {
			if (e.key === 'Escape') menu.close();
		};
		const onDocClick = (e) => {
			if (wrap && !wrap.contains(e.target)) menu.close();
		};
		// the menu is fixed, so a scroll would detach it from the row; close instead.
		const onScroll = () => menu.close();
		document.addEventListener('keydown', onKey);
		document.addEventListener('click', onDocClick, true);
		window.addEventListener('scroll', onScroll, true);
		window.addEventListener('resize', onScroll);
		return () => {
			document.removeEventListener('keydown', onKey);
			document.removeEventListener('click', onDocClick, true);
			window.removeEventListener('scroll', onScroll, true);
			window.removeEventListener('resize', onScroll);
		};
	});
</script>

<div bind:this={wrap} class="relative inline-block text-left">
	<button
		bind:this={btn}
		type="button"
		aria-haspopup="menu"
		aria-expanded={open}
		aria-label={label}
		onclick={(e) => {
			e.stopPropagation();
			menu.toggle(id);
		}}
		class="pc-kebab">⋯</button
	>
	{#if open}
		<div
			bind:this={menuEl}
			role="menu"
			tabindex="-1"
			class="pc-menu"
			style={`position:fixed; right:auto; margin:0; z-index:50; top:${pos.top}px; left:${pos.left}px;`}
			onclick={() => menu.close()}
			onkeydown={() => {}}
		>
			{@render children?.()}
		</div>
	{/if}
</div>
