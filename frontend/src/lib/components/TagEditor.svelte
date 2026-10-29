<script>
	import { NS_COLORS, nsDotClass, tagChipClass, tagChipStyle, nsDotStyle } from '$lib/utils/nsColor.js';
	import ColorSwatchPicker from './ColorSwatchPicker.svelte';
	import { api } from '$lib/api/api.js';
	import { toast } from '$lib/stores/toast.svelte.js';

	// value is the comma separated tags string, the same shape the form stores and
	// publishes. colors is a shared name to color token map, seeded by the parent from
	// api.tags.list(). saved lists the tags the package already carries on the
	// server. The server keeps a color only for a tag some package carries, so a
	// color for a tag in saved or already in colors is stored at once, and any other
	// goes into pending (tag name to color) for the parent to apply with
	// applyPendingTagColors after the package is saved.
	let { value = $bindable(''), colors = $bindable({}), pending = $bindable({}), saved = [] } = $props();

	let draft = $state('');
	let openFor = $state(''); // the tag whose color popover is open, or empty
	let sugOpen = $state(true); // suggestions dropdown; closed with Escape, reopened on input
	let activeIdx = $state(-1); // highlighted suggestion for keyboard select

	// the committed tags as a trimmed, deduped list, derived from the string value.
	const tags = $derived(
		value
			.split(',')
			.map((t) => t.trim())
			.filter(Boolean)
			.filter((t, i, a) => a.indexOf(t) === i)
	);

	// existing tags in the registry that match the draft and are not added yet, so the
	// author reuses a tag instead of coining a near duplicate. colors is keyed by every
	// known tag name, so its keys are the suggestion source. prefix matches sort first.
	const suggestions = $derived.by(() => {
		const q = draft.trim().toLowerCase();
		if (!q) return [];
		return Object.keys(colors)
			.filter((name) => !tags.includes(name) && name.toLowerCase().includes(q) && name.toLowerCase() !== q)
			.sort((a, b) => {
				const ap = a.toLowerCase().startsWith(q) ? 0 : 1;
				const bp = b.toLowerCase().startsWith(q) ? 0 : 1;
				return ap - bp || a.localeCompare(b);
			})
			.slice(0, 8);
	});

	function writeBack(list) {
		value = list.join(', ');
	}
	function addTag(raw) {
		const t = String(raw || '').trim();
		if (!t) return;
		if (!tags.includes(t)) writeBack([...tags, t]);
		draft = '';
	}
	function removeTag(t) {
		writeBack(tags.filter((x) => x !== t));
		if (openFor === t) openFor = '';
	}
	function onKey(e) {
		if (e.key === 'ArrowDown' && suggestions.length) {
			e.preventDefault();
			sugOpen = true;
			activeIdx = (activeIdx + 1) % suggestions.length;
		} else if (e.key === 'ArrowUp' && suggestions.length) {
			e.preventDefault();
			sugOpen = true;
			activeIdx = (activeIdx - 1 + suggestions.length) % suggestions.length;
		} else if (e.key === 'Escape' && sugOpen && suggestions.length) {
			// close the dropdown without clearing the draft; a second Escape is the page default
			e.preventDefault();
			sugOpen = false;
			activeIdx = -1;
		} else if (e.key === 'Enter' || e.key === ',') {
			e.preventDefault();
			if (e.key === 'Enter' && sugOpen && activeIdx >= 0 && suggestions[activeIdx]) addTag(suggestions[activeIdx]);
			else addTag(draft);
		} else if (e.key === 'Backspace' && !draft && tags.length) {
			removeTag(tags[tags.length - 1]);
		}
	}
	// a pasted or typed comma commits every part before it, leaving the rest as the draft.
	function onInput(e) {
		sugOpen = true;
		activeIdx = -1;
		if (e.target.value.includes(',')) {
			const parts = e.target.value.split(',');
			draft = parts.pop();
			for (const p of parts) addTag(p);
		}
	}
	// a tag is known to the server when the package carries it or it already has a
	// color row there, which exists only for tags in use.
	function storedOnServer(name) {
		const n = name.toLowerCase();
		return saved.some((t) => String(t).toLowerCase() === n) || (n in colors && !(name in pending));
	}
	function keepPending(name, key) {
		pending = { ...pending, [name]: key };
	}
	// recolor a tag's chip at once. A tag the server knows is stored now and reverted
	// on failure; any other waits in pending until the package is saved.
	async function pickColor(name, key) {
		openFor = '';
		const prev = colors[name] || '';
		const known = storedOnServer(name);
		colors = { ...colors, [name]: key };
		if (!known) {
			keepPending(name, key);
			return;
		}
		const res = await api.tags.setColor(name, key);
		if (res.ok) return;
		if (res.status === 404) {
			// the last package using the tag dropped it meanwhile; keep the color until save.
			keepPending(name, key);
			return;
		}
		colors = { ...colors, [name]: prev };
		toast(res.error || 'Could not save tag color', 'error');
	}
</script>

<div class="relative mt-1 flex flex-wrap items-center gap-1.5 rounded-md border border-gray-300 bg-white p-1.5 dark:border-gray-700 dark:bg-gray-950">
	{#each tags as t (t)}
		<span class="relative inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs {tagChipClass(colors[t])}" style={tagChipStyle(colors[t])}>
			<button
				type="button"
				onclick={() => (openFor = openFor === t ? '' : t)}
				title="Set tag color"
				aria-label={`Set color for ${t}`}
				class="inline-flex items-center gap-1"
			>
				<span class="h-2.5 w-2.5 rounded-full {nsDotClass(colors[t])}" style={nsDotStyle(colors[t])}></span>
				{t}
			</button>
			<button type="button" onclick={() => removeTag(t)} title="Remove tag" aria-label={`Remove ${t}`} class="ml-0.5 opacity-60 hover:opacity-100">&times;</button>
			{#if openFor === t}
				<div class="absolute left-0 top-full z-20 mt-1 w-max rounded-md border border-gray-200 bg-white p-2 shadow-lg dark:border-gray-800 dark:bg-gray-950">
					<div class="grid grid-cols-6 gap-1.5">
						<button
							type="button"
							onclick={() => pickColor(t, '')}
							title="No color"
							aria-label="No color"
							class="flex h-6 w-6 items-center justify-center rounded-full border {colors[t] ? 'border-gray-300 dark:border-gray-600' : 'border-active-blue ring-2 ring-active-blue/40'}"
						>
							<span class="h-2.5 w-2.5 rounded-full {nsDotClass('')}"></span>
						</button>
						{#each NS_COLORS as c}
							<button
								type="button"
								onclick={() => pickColor(t, c.key)}
								title={c.key}
								aria-label={c.key}
								class="flex h-6 w-6 items-center justify-center rounded-full border {colors[t] === c.key ? 'border-active-blue ring-2 ring-active-blue/40' : 'border-transparent'}"
							>
								<span class="h-3.5 w-3.5 rounded-full {c.dot}"></span>
							</button>
						{/each}
						<!-- custom color opens our own popover so it never lands off screen near the edge. -->
						<ColorSwatchPicker value={colors[t]} onpick={(hex) => pickColor(t, hex)} />
					</div>
				</div>
			{/if}
		</span>
	{/each}
	<input
		bind:value={draft}
		onkeydown={onKey}
		oninput={onInput}
		onblur={() => addTag(draft)}
		placeholder={tags.length ? 'Add tag…' : 'o365, email, credential-capture'}
		class="min-w-[8rem] flex-1 border-0 bg-transparent px-1 py-0.5 text-sm focus:outline-none focus:ring-0"
	/>
	{#if sugOpen && suggestions.length}
		<ul class="absolute left-0 top-full z-20 mt-1 max-h-56 w-full overflow-auto rounded-md border border-gray-200 bg-white py-1 shadow-lg dark:border-gray-800 dark:bg-gray-950">
			{#each suggestions as s, i (s)}
				<li>
					<!-- mousedown with preventDefault keeps the input from blurring and committing
					     the partial draft before the suggestion is chosen. -->
					<button
						type="button"
						onmousedown={(e) => { e.preventDefault(); addTag(s); }}
						onmouseenter={() => (activeIdx = i)}
						class="flex w-full items-center gap-2 px-2.5 py-1.5 text-left text-sm {i === activeIdx ? 'bg-gray-100 dark:bg-gray-800' : 'hover:bg-gray-50 dark:hover:bg-gray-900'}"
					>
						<span class="h-2.5 w-2.5 shrink-0 rounded-full {nsDotClass(colors[s])}" style={nsDotStyle(colors[s])}></span>
						<span class="truncate">{s}</span>
					</button>
				</li>
			{/each}
		</ul>
	{/if}
	{#if openFor}
		<!-- catch an outside click so the color popover closes. -->
		<button type="button" class="fixed inset-0 z-10 cursor-default" aria-label="Close color picker" onclick={() => (openFor = '')}></button>
	{/if}
</div>
