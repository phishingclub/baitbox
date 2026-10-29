<script>
	// Picking calls onPick, clears the query and keeps the input focused so the
	// operator can add another right away (an add action, not a bound value).
	//
	// When onSearch is set the picker searches the server instead of filtering the
	// packages prop in the browser, so it works past the list page cap. Typing calls
	// onSearch(query) debounced; the parent runs the query and feeds back the matches
	// through the packages prop, which the picker then shows as is (no client filter).
	import { typeLabel } from '$lib/utils/packageType.js';

	let {
		packages = [],
		onPick = () => {},
		onSearch = null,
		placeholder = 'Search packages...',
		id = undefined,
		ariaLabel = ''
	} = $props();

	let query = $state('');
	let open = $state(false);
	let activeIdx = $state(-1);
	let inputEl = $state(null);
	let menuEl = $state(null);
	let pos = $state({ top: 0, left: 0, width: 0 });

	const listboxId = $derived((id || 'package-picker') + '-listbox');

	// server search mode shows exactly what the parent returned.
	const filtered = $derived.by(() => {
		if (onSearch) return packages;
		const q = query.trim().toLowerCase();
		if (!q) return packages;
		return packages.filter((p) => {
			const hay = [p.title, p.name, p.namespace, typeLabel(p.type)].join(' ').toLowerCase();
			return hay.includes(q);
		});
	});

	// debounce the server search so it does not fire on every keystroke. a fresh
	// query always restarts the timer.
	let searchDebounce;
	let searched = false; // whether the first server search has run, to seed on open
	function scheduleSearch(q) {
		if (!onSearch) return;
		searched = true;
		clearTimeout(searchDebounce);
		searchDebounce = setTimeout(() => onSearch(q), 300);
	}

	function place() {
		if (!inputEl) return;
		const r = inputEl.getBoundingClientRect();
		pos = { top: r.bottom + 4, left: r.left, width: r.width };
	}

	function openMenu() {
		place();
		open = true;
		activeIdx = -1;
		// seed the server list the first time the menu opens so it is not empty before
		// the operator types. fires immediately, not debounced.
		if (onSearch && !searched) {
			searched = true;
			onSearch(query);
		}
	}
	function close() {
		open = false;
		activeIdx = -1;
	}

	function scrollActiveIntoView() {
		const el = menuEl?.querySelector(`[data-idx="${activeIdx}"]`);
		el?.scrollIntoView({ block: 'nearest' });
	}
	function move(step) {
		const n = filtered.length;
		if (!n) return;
		activeIdx = (activeIdx + step + n) % n;
		scrollActiveIntoView();
	}

	function pick(pkg) {
		if (!pkg) return;
		onPick(pkg);
		query = '';
		activeIdx = -1;
		// keep the menu open and the input focused so the next package can be added.
		inputEl?.focus();
		place();
		// in server mode the cleared query should show the default list again.
		if (onSearch) scheduleSearch('');
	}

	function onInput(e) {
		query = e.target.value;
		open = true;
		activeIdx = -1;
		place();
		scheduleSearch(query);
	}

	function onKeyDown(e) {
		if (e.key === 'ArrowDown') {
			e.preventDefault();
			if (!open) openMenu();
			else move(1);
		} else if (e.key === 'ArrowUp') {
			e.preventDefault();
			if (open) move(-1);
		} else if (e.key === 'Enter') {
			e.preventDefault();
			if (open && activeIdx >= 0) pick(filtered[activeIdx]);
		} else if (e.key === 'Escape') {
			if (open) {
				e.preventDefault();
				close();
			}
		}
	}

	$effect(() => {
		if (!open) return;
		const onDoc = (e) => {
			if (!inputEl?.contains(e.target) && !menuEl?.contains(e.target)) close();
		};
		const onReflow = () => place();
		document.addEventListener('mousedown', onDoc);
		window.addEventListener('resize', onReflow);
		window.addEventListener('scroll', onReflow, true);
		return () => {
			document.removeEventListener('mousedown', onDoc);
			window.removeEventListener('resize', onReflow);
			window.removeEventListener('scroll', onReflow, true);
		};
	});
</script>

<div class="relative">
	<input
		bind:this={inputEl}
		{id}
		type="text"
		role="combobox"
		aria-label={ariaLabel}
		aria-expanded={open}
		aria-controls={listboxId}
		aria-autocomplete="list"
		aria-haspopup="listbox"
		autocomplete="off"
		{placeholder}
		value={query}
		oninput={onInput}
		onfocus={openMenu}
		onclick={openMenu}
		onkeydown={onKeyDown}
		class="pc-control"
	/>

	{#if open}
		<ul
			bind:this={menuEl}
			id={listboxId}
			role="listbox"
			aria-label={ariaLabel}
			class="fixed z-[9999] max-h-72 overflow-auto rounded-md border border-gray-200 bg-white py-1 shadow-lg dark:border-gray-800 dark:bg-gray-950"
			style="top: {pos.top}px; left: {pos.left}px; width: {pos.width}px;"
		>
			{#if filtered.length}
				{#each filtered as pkg, i (pkg.namespace + '/' + pkg.name)}
					<li>
						<button
							type="button"
							role="option"
							data-idx={i}
							aria-selected={i === activeIdx}
							onmousedown={(e) => {
								e.preventDefault();
								pick(pkg);
							}}
							onmouseenter={() => (activeIdx = i)}
							class="flex w-full items-center gap-3 px-3 py-2 text-left {i === activeIdx ? 'bg-gray-100 dark:bg-gray-800' : ''}"
						>
							<span class="w-28 shrink-0">
								<span class="inline-block truncate rounded bg-gray-100 px-2 py-0.5 text-xs text-gray-800 dark:bg-gray-800 dark:text-gray-100">{typeLabel(pkg.type)}</span>
							</span>
							<span class="min-w-0 flex-1 truncate font-medium text-gray-800 dark:text-gray-100">{pkg.title || pkg.name}</span>
							<span class="max-w-[14rem] shrink-0 truncate text-right font-mono text-xs text-gray-600 dark:text-gray-400">{pkg.namespace}/{pkg.name}</span>
						</button>
					</li>
				{/each}
			{:else}
				<li class="px-3 py-2 text-sm pc-muted">No packages match</li>
			{/if}
		</ul>
	{/if}
</div>
