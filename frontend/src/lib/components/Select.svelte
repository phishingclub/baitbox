<script>
	// A dropdown that opens downward by default, unlike a native select which the
	// browser may open upward to align the chosen option. It flips above only when the
	// space below is too small and there is more room above.
	let { value = $bindable(''), options = [], id = undefined, ariaLabel = '', class: cls = '', onchange = undefined } = $props();

	let open = $state(false);
	let openUp = $state(false);
	let activeIdx = $state(-1);
	let btnEl = $state(null);
	let menuEl = $state(null);

	const current = $derived(options.find((o) => o.value === value));
	const label = $derived(current ? current.label : '');

	// a group header shows when an option starts a new group, so consecutive options in
	// the same group share one header.
	function headerFor(i) {
		const g = options[i]?.group;
		if (!g) return '';
		return i === 0 || options[i - 1]?.group !== g ? g : '';
	}

	function place() {
		if (!btnEl) return;
		const r = btnEl.getBoundingClientRect();
		const below = window.innerHeight - r.bottom;
		const above = r.top;
		// prefer below; flip up only when below is cramped and above has more room.
		openUp = below < 240 && above > below;
	}

	function toggle() {
		if (open) {
			close();
			return;
		}
		place();
		open = true;
		activeIdx = Math.max(0, options.findIndex((o) => o.value === value));
		queueMicrotask(() => scrollActiveIntoView());
	}
	function close() {
		open = false;
		activeIdx = -1;
	}
	function choose(i) {
		const o = options[i];
		if (!o) return;
		const prev = value;
		value = o.value;
		close();
		btnEl?.focus();
		// fire after the value commits so a caller can react (confirm, revert, reset).
		// prev lets the caller restore the earlier value when it declines the change.
		if (o.value !== prev) onchange?.(o.value, prev);
	}
	function scrollActiveIntoView() {
		const el = menuEl?.querySelector(`[data-idx="${activeIdx}"]`);
		el?.scrollIntoView({ block: 'nearest' });
	}
	function move(step) {
		if (!options.length) return;
		let i = activeIdx;
		do {
			i = (i + step + options.length) % options.length;
		} while (options[i]?.disabled && i !== activeIdx);
		activeIdx = i;
		scrollActiveIntoView();
	}

	function onButtonKey(e) {
		if (e.key === 'ArrowDown' || e.key === 'Enter' || e.key === ' ') {
			e.preventDefault();
			if (!open) toggle();
			else move(1);
		} else if (e.key === 'ArrowUp') {
			e.preventDefault();
			if (!open) toggle();
			else move(-1);
		} else if (e.key === 'Escape' && open) {
			e.preventDefault();
			close();
		} else if ((e.key === 'Enter' || e.key === ' ') && open && activeIdx >= 0) {
			e.preventDefault();
			choose(activeIdx);
		}
	}

	$effect(() => {
		if (!open) return;
		const onDoc = (e) => {
			if (!btnEl?.contains(e.target) && !menuEl?.contains(e.target)) close();
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

<div class="relative {cls}">
	<button
		bind:this={btnEl}
		type="button"
		{id}
		aria-haspopup="listbox"
		aria-expanded={open}
		aria-label={ariaLabel}
		onclick={toggle}
		onkeydown={onButtonKey}
		class="flex w-full items-center justify-between gap-2 rounded-md border border-gray-300 bg-gray-50 px-3 py-2 text-left text-sm text-gray-800 transition-colors duration-200 focus:border-cta-blue focus:bg-white focus:outline-none dark:border-gray-700 dark:bg-gray-900/60 dark:text-gray-100 dark:focus:border-highlight-blue dark:focus:bg-gray-800/60"
	>
		<span class="truncate">{label}</span>
		<svg class="h-4 w-4 shrink-0 text-gray-500 dark:text-gray-400 transition-transform {open ? 'rotate-180' : ''}" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
			<path fill-rule="evenodd" d="M5.23 7.21a.75.75 0 0 1 1.06.02L10 11.168l3.71-3.938a.75.75 0 1 1 1.08 1.04l-4.25 4.5a.75.75 0 0 1-1.08 0l-4.25-4.5a.75.75 0 0 1 .02-1.06Z" clip-rule="evenodd" />
		</svg>
	</button>
	{#if open}
		<ul
			bind:this={menuEl}
			role="listbox"
			aria-label={ariaLabel}
			class="absolute left-0 z-30 max-h-72 w-full overflow-auto rounded-md border border-gray-200 bg-white py-1 shadow-lg dark:border-gray-800 dark:bg-gray-950 {openUp ? 'bottom-full mb-1' : 'top-full mt-1'}"
		>
			{#each options as o, i (o.value)}
				{#if headerFor(i)}
					<li class="px-2.5 pb-0.5 pt-1.5 text-[11px] font-semibold uppercase tracking-wider text-gray-500 dark:text-gray-400">{headerFor(i)}</li>
				{/if}
				<li>
					<button
						type="button"
						role="option"
						data-idx={i}
						aria-selected={o.value === value}
						onmousedown={(e) => { e.preventDefault(); choose(i); }}
						onmouseenter={() => (activeIdx = i)}
						class="flex w-full items-center justify-between px-2.5 py-1.5 text-left text-sm {i === activeIdx ? 'bg-gray-100 dark:bg-gray-800' : ''} {o.value === value ? 'font-medium text-cta-blue dark:text-highlight-blue' : 'text-gray-800 dark:text-gray-100'}"
					>
						<span class="truncate">{o.label}</span>
						{#if o.value === value}
							<svg class="h-4 w-4 shrink-0" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true"><path fill-rule="evenodd" d="M16.7 5.3a1 1 0 0 1 0 1.4l-7.5 7.5a1 1 0 0 1-1.4 0l-3.5-3.5a1 1 0 1 1 1.4-1.4l2.8 2.79 6.8-6.79a1 1 0 0 1 1.4 0Z" clip-rule="evenodd" /></svg>
						{/if}
					</button>
				</li>
			{/each}
		</ul>
	{/if}
</div>
