<script>
	// The settings Phishing Club applies to one asset when it installs it: a
	// display name and description, the content type it is served with, extra
	// response headers, and the allow or deny lists that decide who can get it.
	// asset is edited in place; errors comes from assetMetaErrors.
	//
	// The lists come from allow / deny packages in the same namespace, or are one
	// list the installer chooses at install, never both. Picking a package adds its
	// list names to the asset; the editor then makes the package depend on
	// it, so Phishing Club installs the list with it. listPkgs holds every list
	// package the editor knows, shared by all assets. listPicks maps each installer
	// pick variable to its pick kind. usedNames holds the list
	// names every asset uses and plainVars the variables the content uses as plain
	// values. namespace is the package's.
	import { api } from '$lib/api/api.js';
	import { toast } from '$lib/stores/toast.svelte.js';
	import Button from '$lib/components/Button.svelte';
	import Select from '$lib/components/Select.svelte';
	import Field from '$lib/components/Field.svelte';
	import PackagePicker from '$lib/components/PackagePicker.svelte';
	import StatusPill from '$lib/components/StatusPill.svelte';
	import { typeFromExtension, pickVarName, listKinds, MAX_ASSET_HEADERS, DEFAULT_LIST_PICK, LIST_PICK_KIND, fetchListPackage } from '$lib/utils/assetMeta.js';

	let {
		asset = $bindable(),
		errors,
		namespace = '',
		listPkgs = $bindable([]),
		listPicks = $bindable({}),
		usedNames = new Set(),
		plainVars = new Set()
	} = $props();

	const fileName = $derived(String(asset.filename || '').split('/').pop());
	const detectedType = $derived(typeFromExtension(asset.filename));
	// every list name the known packages in this namespace declare, with its kind
	// and package.
	const known = $derived(listKinds(listPkgs, namespace));
	// the known packages that could not be read, and the ones read from the
	// version being edited, to explain a name that no longer resolves.
	const unreadable = $derived(listPkgs.filter((p) => p.error && p.namespace === namespace));
	const loadedDeps = $derived(listPkgs.filter((p) => p.fromDeps && !p.error && p.namespace === namespace));
	// one row per name the asset uses: a packaged list, an installer pick, or a
	// name that no longer resolves.
	const rows = $derived(
		asset.allowDeny.map((n) => {
			const pick = pickVarName(n);
			if (pick) return { name: n, pick, kind: listPicks[pick] };
			const k = known.get(n);
			if (k) return { name: n, allowed: k.allowed, pkg: k.pkg };
			if (unreadable.length) return { name: n, missing: true, unreadable: unreadable[0] };
			if (loadedDeps.length)
				return {
					name: n,
					missing: true,
					why: loadedDeps.length === 1 ? `${loadedDeps[0].id} no longer declares it` : `none of ${loadedDeps.map((p) => p.id).join(', ')} declares it`
				};
			return { name: n, missing: true, why: 'no package in this namespace declares it' };
		})
	);
	// the kind the asset's lists have, true for allow, or null when it has none.
	const kind = $derived.by(() => {
		const r = rows.find((x) => x.pkg);
		return r ? r.allowed : null;
	});
	// where the asset's lists come from: allow / deny packages in this namespace,
	// or one list the installer chooses at install. never both.
	const pickRow = $derived(rows.find((r) => r.pick));
	const source = $derived(pickRow ? 'install' : 'namespace');
	// the value the source select shows, kept in step with the asset and set
	// back when a choice is refused.
	let sourceSel = $state('namespace');
	$effect(() => {
		sourceSel = source;
	});
	const SOURCES = [
		{ value: 'namespace', label: 'From namespace' },
		{ value: 'install', label: 'Chosen at install' }
	];

	let results = $state([]);
	// a package stays a candidate while it has a list of the asset's kind that is
	// not on the asset yet. one not read yet is always a candidate.
	const candidates = $derived(
		results.filter((p) => {
			const entry = listPkgs.find((x) => x.id === `${p.namespace}/${p.name}`);
			if (!entry || entry.error) return true;
			return entry.lists.some((l) => (kind === null || l.allowed === kind) && !asset.allowDeny.includes(l.name));
		})
	);
	async function search(q) {
		if (!namespace) return;
		const ns = namespace;
		const res = await api.packages.list({ q, type: 'allowdeny', namespace: ns, perPage: 50 });
		if (ns !== namespace) return;
		results = res.ok ? res.data.packages || [] : [];
	}
	// a search made for another namespace must not offer its packages.
	$effect(() => {
		namespace;
		results = [];
	});

	const kindWord = (allowed) => (allowed ? 'allow' : 'deny');
	const plural = (n, word) => `${n} ${word} list${n === 1 ? '' : 's'}`;

	// read the lists a package declares from its latest version and add the ones
	// of the asset's kind that are not on it yet. With no list on the asset yet,
	// a package that declares both kinds adds the kind of its first list.
	async function pickPackage(p) {
		const id = `${p.namespace}/${p.name}`;
		const entry = await fetchListPackage(api, id);
		if (entry.error) {
			toast(entry.error, 'error');
			return;
		}
		if (!entry.lists.length) {
			toast(`${id} declares no list`, 'error');
			return;
		}
		// two packages the assets use may not declare the same name, since the
		// package depends on both.
		for (const q of listPkgs) {
			if (q.id === id || !q.lists || !q.lists.some((l) => usedNames.has(l.name))) continue;
			const clash = q.lists.find((l) => entry.lists.some((x) => x.name === l.name));
			if (clash) {
				toast(`${q.id} and ${id} both declare a list named ${clash.name}, and a package can use only one of them`, 'error');
				return;
			}
		}
		const target = kind === null ? entry.lists[0].allowed : kind;
		const ofKind = entry.lists.filter((l) => l.allowed === target);
		const add = ofKind.filter((l) => !asset.allowDeny.includes(l.name)).map((l) => l.name);
		const other = entry.lists.length - ofKind.length;
		if (!ofKind.length) {
			toast(`${id} declares only ${kindWord(!target)} lists, and this asset uses ${kindWord(target)} lists. One asset uses only allow lists or only deny lists.`, 'error');
			return;
		}
		if (!add.length) {
			toast(`Every ${kindWord(target)} list of ${id} is already on this asset`, 'error');
			return;
		}
		listPkgs = [...listPkgs.filter((x) => x.id !== id), { ...entry, fromDeps: false }];
		asset.allowDeny = [...asset.allowDeny, ...add];
		if (other)
			toast(`Added ${plural(add.length, kindWord(target))} from ${id}. Its ${plural(other, kindWord(!target))} were left out, since one asset uses only allow lists or only deny lists.`, 'success');
	}
	async function retry(p) {
		const entry = await fetchListPackage(api, p.id);
		listPkgs = listPkgs.map((x) => (x.id === p.id ? { ...entry, fromDeps: p.fromDeps } : x));
		if (entry.error) toast(entry.error, 'error');
	}
	function removeName(n) {
		asset.allowDeny = asset.allowDeny.filter((x) => x !== n);
	}
	// make the installer pick the asset's only list. it is refused when the
	// content already uses that variable name as a plain value.
	function setPick() {
		const name = DEFAULT_LIST_PICK;
		if (plainVars.has(name)) {
			toast(`@@${name}@@ is already a variable in the content. Rename it there first.`, 'error');
			return false;
		}
		listPicks = { ...listPicks, [name]: LIST_PICK_KIND };
		asset.allowDeny = [`@@${name}@@`];
		return true;
	}
	function onSource(next) {
		if (next === source) return;
		if (next === 'install') {
			if (!setPick()) sourceSel = source;
		} else asset.allowDeny = [];
	}
	const errClass = 'mt-1 block text-xs text-red-600 dark:text-red-400';
</script>

<div class="space-y-3 rounded-md border border-gray-100 bg-gray-50/60 p-3 dark:border-gray-800 dark:bg-gray-900/40">
	<div class="grid gap-3 sm:grid-cols-2">
		<Field label="Name" optional>
			<input bind:value={asset.name} placeholder={fileName} class="pc-control" />
			{#if errors.name}<span class={errClass}>{errors.name}</span>{/if}
		</Field>
		<Field label="Content type" optional hint="Empty uses the file extension.">
			<input bind:value={asset.contentType} placeholder={detectedType || 'application/octet-stream'} class="pc-control font-mono text-xs" />
			{#if errors.contentType}<span class={errClass}>{errors.contentType}</span>{/if}
		</Field>
		<div class="sm:col-span-2">
			<Field label="Description" optional>
				<input bind:value={asset.description} class="pc-control" />
				{#if errors.description}<span class={errClass}>{errors.description}</span>{/if}
			</Field>
		</div>
	</div>

	<div>
		<div class="flex items-center justify-between">
			<span class="flex items-center gap-2"><span class="pc-label">Response headers</span> <span class="pc-optional">optional</span></span>
			<Button variant="blue" size="xs" disabled={asset.headers.length >= MAX_ASSET_HEADERS} onclick={() => (asset.headers = [...asset.headers, { key: '', value: '' }])}>+ Add header</Button>
		</div>
		{#each asset.headers as h, hi (hi)}
			<div class="mt-2 flex flex-wrap items-start gap-2">
				<div class="min-w-[8rem] flex-1">
					<input bind:value={h.key} placeholder="Cache-Control" aria-label="Header name" class="pc-control text-xs" />
					{#if errors.headers[hi]?.key}<span class={errClass}>{errors.headers[hi].key}</span>{/if}
				</div>
				<div class="min-w-[8rem] flex-1">
					<input bind:value={h.value} placeholder="no-store" aria-label="Header value" class="pc-control text-xs" />
					{#if errors.headers[hi]?.value}<span class={errClass}>{errors.headers[hi].value}</span>{/if}
				</div>
				<Button variant="danger" size="xs" class="mt-1.5" onclick={() => (asset.headers = asset.headers.filter((_, i) => i !== hi))}>Remove</Button>
			</div>
		{/each}
		{#if errors.headerList}<span class={errClass}>{errors.headerList}</span>{/if}
	</div>

	<div>
		<span class="flex items-center gap-2"><span class="pc-label">Allow / deny lists</span> <span class="pc-optional">optional</span></span>
		<div class="mt-1 flex flex-wrap items-center gap-2">
			<Select bind:value={sourceSel} onchange={onSource} options={SOURCES} ariaLabel="Where the lists come from" class="w-44" />
			{#if source === 'namespace'}
				<div class="min-w-[14rem] flex-1">
					{#key namespace}
						<PackagePicker packages={candidates} onPick={pickPackage} onSearch={search} placeholder="Search allow / deny packages..." ariaLabel="Add an allow / deny list" />
					{/key}
				</div>
			{:else}
				<code class="text-xs pc-muted">{pickRow.name}</code>
			{/if}
		</div>
		{#if source === 'namespace' && rows.length}
			<ul class="mt-2 divide-y divide-gray-200 rounded-md border border-gray-200 bg-white px-3 dark:divide-gray-800 dark:border-gray-800 dark:bg-gray-950">
				{#each rows as r (r.name)}
					<li class="flex items-center gap-3 py-2">
						<span class="w-20 shrink-0">
							{#if r.missing}
								<StatusPill tone="warn">{r.unreadable ? 'Unread' : 'Not found'}</StatusPill>
							{:else}
								<StatusPill tone={r.allowed ? 'on' : 'danger'}>{r.allowed ? 'Allow' : 'Deny'}</StatusPill>
							{/if}
						</span>
						<span class="min-w-0 flex-1 truncate text-sm font-medium text-gray-800 dark:text-gray-100">{r.name}</span>
						<span class="max-w-[16rem] shrink-0 truncate text-right text-xs pc-muted">
							{#if r.unreadable}Could not read {r.unreadable.id}
							{:else if r.missing}{r.why}
							{:else}from <span class="font-mono">{r.pkg.name}</span>{/if}
						</span>
						{#if r.unreadable}
							<Button variant="neutral" size="xs" onclick={() => retry(r.unreadable)}>Retry</Button>
						{/if}
						<Button variant="danger" size="xs" onclick={() => removeName(r.name)}>Remove</Button>
					</li>
				{/each}
			</ul>
		{/if}
		{#if errors.allowDeny}<span class={errClass}>{errors.allowDeny}</span>{/if}
	</div>
</div>
