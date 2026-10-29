<script>
	import { onMount } from 'svelte';
	import CodeEditor from './CodeEditor.svelte';
	import PreviewPane from './PreviewPane.svelte';
	import { variableGroups } from '$lib/utils/pcVariables.js';
	import { vimPref } from '$lib/stores/vim.svelte.js';

	// Modelled on the phishingclub editor: the code editor fills the width and the
	// live preview opens beside it on demand.
	let {
		value = $bindable(''),
		lang = 'html',
		srcdoc = '',
		filename = 'index.html',
		type = '',
		showPreview = $bindable(false),
		previewHeader
	} = $props();

	let editorApi = $state(null);
	// send time Phishing Club variables offered for this type (null for types with none)
	let groups = $derived(variableGroups(type));

	function insertVar(e) {
		const token = e.currentTarget.value;
		if (token && editorApi) editorApi.insert(token);
		e.currentTarget.value = '';
	}

	let vimOn = $state(undefined);
	let fullscreen = $state(false);
	let collapsed = $state(false);
	let wide = $state(false);
	let dragging = $state(false);
	// editor share of the split, in percent
	let ratio = $state(55);
	let splitEl = $state(null);

	function loadRatio() {
		try {
			const n = parseFloat(localStorage.getItem('bs-split') || '');
			if (!isNaN(n) && n >= 25 && n <= 80) ratio = n;
		} catch (_) {
			/* ignore */
		}
	}
	function saveRatio() {
		try {
			localStorage.setItem('bs-split', String(Math.round(ratio)));
		} catch (_) {
			/* ignore */
		}
	}

	onMount(() => {
		loadRatio();
		const mq = window.matchMedia('(min-width: 1024px)');
		const sync = () => (wide = mq.matches);
		sync();
		mq.addEventListener('change', sync);
		return () => mq.removeEventListener('change', sync);
	});

	function onDividerDown(e) {
		if (!wide) return;
		dragging = true;
		try {
			e.target.setPointerCapture?.(e.pointerId);
		} catch (_) {
			/* synthetic or already released pointer */
		}
		e.preventDefault();
	}
	function onDividerMove(e) {
		if (!dragging || !splitEl) return;
		const rect = splitEl.getBoundingClientRect();
		let pct = ((e.clientX - rect.left) / rect.width) * 100;
		pct = Math.max(25, Math.min(80, pct));
		ratio = pct;
	}
	function onDividerUp(e) {
		if (!dragging) return;
		dragging = false;
		try {
			e.target.releasePointerCapture?.(e.pointerId);
		} catch (_) {
			/* ignore */
		}
		saveRatio();
	}

	function toggleFullscreen() {
		fullscreen = !fullscreen;
	}

	// Escape leaves the unified fullscreen (but not while vim owns Escape).
	$effect(() => {
		if (!fullscreen) return;
		const onKey = (e) => {
			if (e.key === 'Escape' && !vimOn) fullscreen = false;
		};
		window.addEventListener('keydown', onKey);
		return () => window.removeEventListener('keydown', onKey);
	});

	// per pane flex so the inline basis only applies to the horizontal (wide) split
	let editorFlex = $derived(wide && showPreview ? `flex: 0 0 ${ratio}%` : 'flex: 1 1 0');
	let previewFlex = $derived('flex: 1 1 0');
</script>

<div
	class={fullscreen
		? 'fixed inset-0 z-40 flex flex-col bg-white p-3 dark:bg-gray-950'
		: 'flex flex-col'}
>
	<!-- toolbar -->
	<div class="mb-2 flex flex-wrap items-center justify-between gap-2">
		<h2 class="text-sm font-semibold text-gray-900 dark:text-white">{filename}</h2>
		<div class="flex items-center gap-2 text-sm">
			{#if groups && !collapsed}
				<select
					onchange={insertVar}
					aria-label="Insert a variable"
					title="Insert a Phishing Club variable"
					class="rounded border border-gray-300 bg-white py-1.5 px-2 text-sm font-medium text-gray-800 hover:bg-gray-100 dark:border-gray-700 dark:bg-gray-900 dark:text-gray-100 dark:hover:bg-gray-800"
				>
					<option value="">Insert variable…</option>
					{#each Object.entries(groups) as [group, items]}
						<optgroup label={group}>
							{#each items as item}<option value={item.text}>{item.label}</option>{/each}
						</optgroup>
					{/each}
				</select>
			{/if}
			<button
				type="button"
				aria-pressed={showPreview}
				disabled={collapsed}
				onclick={() => (showPreview = !showPreview)}
				class="rounded border px-3 py-1.5 font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-40 {showPreview
					? 'border-cta-blue bg-cta-blue text-white'
					: 'border-gray-300 text-gray-800 hover:bg-gray-100 dark:border-gray-700 dark:text-gray-100 dark:hover:bg-gray-800'}"
				>{showPreview ? 'Hide preview' : 'Show preview'}</button
			>
			<button
				type="button"
				aria-pressed={!!vimOn}
				disabled={collapsed}
				onclick={() => vimPref.toggle()}
				title="Toggle vim keybindings (Ctrl+Alt+V)"
				class="rounded border px-3 py-1.5 font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-40 {vimOn
					? 'border-cta-blue bg-cta-blue text-white'
					: 'border-gray-300 text-gray-800 hover:bg-gray-100 dark:border-gray-700 dark:text-gray-100 dark:hover:bg-gray-800'}"
				>Vim</button
			>
			{#if !fullscreen}
				<button
					type="button"
					aria-pressed={collapsed}
					onclick={() => (collapsed = !collapsed)}
					title={collapsed ? 'Expand editor' : 'Minimize editor'}
					class="rounded border border-gray-300 px-3 py-1.5 font-medium text-gray-800 hover:bg-gray-100 dark:border-gray-700 dark:text-gray-100 dark:hover:bg-gray-800"
					>{collapsed ? 'Expand' : 'Minimize'}</button
				>
			{/if}
			<button
				type="button"
				aria-pressed={fullscreen}
				disabled={collapsed}
				onclick={toggleFullscreen}
				title={fullscreen ? 'Exit fullscreen (Esc)' : 'Fullscreen'}
				class="rounded border border-gray-300 px-3 py-1.5 font-medium text-gray-800 hover:bg-gray-100 disabled:cursor-not-allowed disabled:opacity-40 dark:border-gray-700 dark:text-gray-100 dark:hover:bg-gray-800"
				>{fullscreen ? 'Exit fullscreen' : 'Fullscreen'}</button
			>
		</div>
	</div>

	{#if collapsed}
		<button
			type="button"
			onclick={() => (collapsed = false)}
			class="flex w-full items-center justify-center gap-2 rounded-xl border border-dashed border-gray-300 py-3 text-xs font-medium text-gray-700 transition-colors hover:bg-gray-50 dark:border-gray-700 dark:text-gray-200 dark:hover:bg-gray-900"
		>
			<svg class="h-3.5 w-3.5" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6">
				<path d="M6 8l4 4 4-4" stroke-linecap="round" stroke-linejoin="round" />
			</svg>
			Editor minimized, click to expand
		</button>
	{:else}
	<!-- editor + optional preview split -->
	<div
		bind:this={splitEl}
		class="flex min-h-0 flex-col lg:flex-row {dragging ? 'select-none' : ''} {fullscreen
			? 'flex-1'
			: 'h-[32rem] lg:h-[60vh]'}"
	>
		<div class="flex min-h-0 min-w-0 flex-col" style={editorFlex}>
			<div class="min-h-0 flex-1 rounded-xl border border-gray-200 bg-white p-3 dark:border-gray-800 dark:bg-gray-950">
				<CodeEditor bind:value {lang} {type} chrome={false} bind:vim={vimOn} bind:api={editorApi} fill />
			</div>
		</div>

		{#if showPreview && wide}
			<div
				role="separator"
				aria-orientation="vertical"
				tabindex="-1"
				onpointerdown={onDividerDown}
				onpointermove={onDividerMove}
				onpointerup={onDividerUp}
				class="mx-1 w-1.5 shrink-0 cursor-col-resize self-stretch rounded bg-gray-200 transition-colors hover:bg-cta-blue dark:bg-gray-800 {dragging
					? 'bg-cta-blue'
					: ''}"
				title="Drag to resize"
			></div>
		{/if}

		{#if showPreview}
			<div class="mt-3 flex min-h-0 min-w-0 flex-col lg:mt-0" style={previewFlex}>
				<div class="flex min-h-0 flex-1 flex-col rounded-xl border border-gray-200 bg-white p-3 dark:border-gray-800 dark:bg-gray-950">
					{@render previewHeader?.()}
					<div class="min-h-0 flex-1"><PreviewPane {srcdoc} /></div>
				</div>
			</div>
		{/if}
	</div>
	{/if}
</div>
