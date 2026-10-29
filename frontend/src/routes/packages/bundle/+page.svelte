<script>
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { api } from '$lib/api/api.js';
	import { toast } from '$lib/stores/toast.svelte.js';
	import { askConfirm } from '$lib/stores/confirm.svelte.js';
	import Help from '$lib/components/Help.svelte';
	import TagEditor from '$lib/components/TagEditor.svelte';
	import { applyPendingTagColors } from '$lib/utils/tagColors.js';
	import Button from '$lib/components/Button.svelte';
	import Card from '$lib/components/Card.svelte';
	import Alert from '$lib/components/Alert.svelte';
	import Checkbox from '$lib/components/Checkbox.svelte';
	import ErrorCard from '$lib/components/ErrorCard.svelte';
	import Field from '$lib/components/Field.svelte';
	import Select from '$lib/components/Select.svelte';
	import PackagePicker from '$lib/components/PackagePicker.svelte';
	import { compareSemver } from '$lib/utils/semver.js';
	import { bumpPatch, decodeText, yamlStr } from '$lib/utils/authoring.js';
	import { typeLabel } from '$lib/utils/packageType.js';

	// A bundle is a named set of existing packages installed and uninstalled
	// together. It carries no content of its own; it references published packages
	// and, optionally, wires some of them into one or more campaign templates.
	// Installing it into Phishing Club installs or reuses each referenced package,
	// then creates any campaign templates. Referenced packages install at latest.

	let editingFrom = $state('');
	let namespaces = $state([]);
	let nsLoaded = $state(false);
	let nsError = $state('');
	let form = $state({ namespace: '', name: '', version: '1.0.0', title: '', description: '', tags: '' });
	let tagColors = $state({});
	let pendingTagColors = $state({}); // colors chosen for tags no package carries yet, stored after publish
	let searchResults = $state([]); // latest server search matches shown in the picker
	let picked = $state([]); // {id, namespace, name, title, type, entity, variables}
	let shareVars = $state(true);
	let templates = $state([]); // campaign templates, each wiring referenced entities by name
	let nextTid = $state(1);
	let busy = $state(false);
	// the server reason a publish failed, kept on the page so a long message such as
	// the install size limit stays readable after the toast is gone.
	let publishError = $state('');
	// Phishing Club refuses a bundle that references more packages than this.
	const MAX_BUNDLE_PACKAGES = 100;
	let tab = $state('content');
	const tabList = [['content', 'Content'], ['details', 'Details']];

	const LURE_CODE_ALGOS = [
		{ value: 'crockford32', label: 'Crockford base32 (upper case, no I L O U)' },
		{ value: 'base58', label: 'Base58 (mixed case, no 0 O I l)' }
	];
	const LURE_CODE_MIN = 6;
	const LURE_CODE_MAX = 16;

	// template slots that can instead ask the installer to supply one of their own
	// existing entities. each maps to the entity kind the installer picks and the base
	// name of the pick variable the bundle declares for it.
	const OWN_SLOTS = {
		domain: { kind: 'domain', base: 'OWN_DOMAIN', label: 'domain' },
		email: { kind: 'email', base: 'OWN_EMAIL', label: 'email' },
		landingPage: { kind: 'page', base: 'OWN_LANDING_PAGE', label: 'landing page' },
		landingProxy: { kind: 'proxy', base: 'OWN_LANDING_PROXY', label: 'landing proxy' },
		beforeLandingPage: { kind: 'page', base: 'OWN_BEFORE_PAGE', label: 'before landing page' },
		afterLandingPage: { kind: 'page', base: 'OWN_AFTER_PAGE', label: 'after landing page' },
		smtpConfiguration: { kind: 'smtpConfiguration', base: 'OWN_SMTP', label: 'SMTP configuration' },
		apiSender: { kind: 'apiSender', base: 'OWN_API_SENDER', label: 'API sender' }
	};
	// slot value that marks a slot as filled by the installer at install time.
	const OWN_SENTINEL = '__own__';

	const nameValid = $derived(/^[a-z0-9][a-z0-9-]*$/.test(form.name));
	const versionValid = $derived(/^\d+\.\d+\.\d+$/.test(form.version));

	// slugify turns the friendly title into the lowercase slug used as the bundle
	// address: lowercase, non slug chars to dashes, collapse and trim dashes.
	function slugify(s) {
		return s
			.toLowerCase()
			.replace(/[^a-z0-9]+/g, '-')
			.replace(/^-+|-+$/g, '');
	}
	// the address follows the title until the operator edits it directly, so the
	// title alone opens the package picker without extra typing.
	let slugLocked = $state(false);
	function onTitleInput() {
		if (!slugLocked) form.name = slugify(form.title);
	}

	const nsVisibility = $derived(namespaces.find((n) => n.name === form.namespace)?.visibility || 'private');

	function referenceable(p) {
		if (p.type === 'bundle' || p.type === 'template') return false; // no nesting
		if (`${p.namespace}/${p.name}` === `${form.namespace}/${form.name}`) return false; // not itself
		if (nsVisibility === 'public') return p.visibility === 'public';
		return p.visibility === 'public' || p.namespace === form.namespace;
	}
	const pickedIds = $derived(new Set(picked.map((p) => p.id)));
	// the picker searches the server; the returned rows are then held to the bundle's
	// own public/private reference rules and any already picked are dropped.
	const candidates = $derived(searchResults.filter((p) => referenceable(p) && !pickedIds.has(`${p.namespace}/${p.name}`)));

	// a server search works past the list page cap a full fetch would truncate at.
	async function doPackageSearch(q) {
		const res = await api.packages.list({ q, perPage: 50 });
		searchResults = res.ok ? res.data.packages || [] : [];
	}

	// the referenceable set and the campaign template slots depend on the namespace,
	// so changing it clears the picked packages and templates. warn first when there
	// is something to lose, and restore the previous namespace if the operator declines.
	async function onNamespaceChange(next, prev) {
		if (picked.length === 0 && templates.length === 0) return;
		const ok = await askConfirm({
			title: 'Change namespace',
			body: 'Changing the namespace resets this bundle. Its packages and campaign templates are cleared, since a bundle references packages for one namespace.',
			confirmLabel: 'Change and reset'
		});
		if (ok) {
			picked = [];
			templates = [];
		} else {
			form.namespace = prev;
		}
	}

	function entityNameFromSource(src) {
		const dy = (src.files || []).find((f) => /\/data\.yaml$/i.test(f.path));
		if (!dy) return '';
		const m = decodeText(dy.content).match(/-\s*name:\s*(.+)/);
		if (!m) return '';
		let v = m[1].trim();
		if (v.length >= 2 && v[0] === '"' && v[v.length - 1] === '"') v = v.slice(1, -1).replace(/\\(.)/g, (_, c) => (c === 'n' ? '\n' : c === 't' ? '\t' : c));
		return v;
	}

	const entitiesByKind = $derived.by(() => {
		const g = { email: [], page: [], proxy: [], domain: [], smtp: [], apisender: [] };
		for (const p of picked) if (p.entity && g[p.type]) g[p.type].push(p.entity);
		return g;
	});
	// slot options plus an "installer provides their own" choice, for slots that
	// can defer to an entity the installer already has.
	const slotOptionsWithOwn = (entities) => [
		{ value: '', label: '(none)' },
		{ value: OWN_SENTINEL, label: 'Installer provides their own' },
		...entities.map((e) => ({ value: e, label: e }))
	];
	// a stable variable name for a slot the installer fills. one template shares a
	// single name per slot; several templates each get their own so they stay
	// independent.
	const ownVarName = (slotKey, templateIndex) =>
		templates.length > 1 ? `${OWN_SLOTS[slotKey].base}_T${templateIndex + 1}` : OWN_SLOTS[slotKey].base;

	async function addPackage(p) {
		const id = `${p.namespace}/${p.name}`;
		if (picked.some((x) => x.id === id)) return;
		if (picked.length >= MAX_BUNDLE_PACKAGES) {
			toast(`A bundle can reference at most ${MAX_BUNDLE_PACKAGES} packages`, 'error');
			return;
		}
		const res = await api.packages.source(p.namespace, p.name, 'latest');
		if (!res.ok) {
			toast(`Could not read ${id}`, 'error');
			return;
		}
		const entity = entityNameFromSource(res.data);
		// the source carries type and title, so a dependency resolved by id alone (when
		// editing a bundle) still fills them without a full package list.
		picked = [...picked, { id, namespace: p.namespace, name: p.name, title: p.title || res.data.title || p.name, type: p.type || res.data.type, entity, variables: res.data.variables || [] }];
	}
	function removePackage(id) {
		const gone = picked.find((p) => p.id === id);
		picked = picked.filter((p) => p.id !== id);
		if (gone?.entity) {
			templates = templates.map((t) => {
				const nt = { ...t };
				for (const k of ['email', 'landingProxy', 'domain', 'smtpConfiguration', 'apiSender', 'landingPage', 'beforeLandingPage', 'afterLandingPage']) if (nt[k] === gone.entity) nt[k] = '';
				return nt;
			});
		}
	}

	function blankTemplate() {
		return { email: '', landingPage: '', landingProxy: '', beforeLandingPage: '', afterLandingPage: '', domain: '', smtpConfiguration: '', apiSender: '', afterLandingPageRedirectURL: '', urlPath: '', lureURLMode: 'query', lureCodeAlgo: 'crockford32', lureCodeLength: 12, isTraining: false };
	}
	function addTemplate() {
		const base = form.title.trim() || form.name || 'Campaign';
		const e = entitiesByKind;
		templates = [
			...templates,
			{
				tid: nextTid++,
				name: templates.length === 0 ? base : `${base} ${templates.length + 1}`,
				...blankTemplate(),
				email: e.email[0] || '',
				landingPage: e.page[0] || '',
				landingProxy: e.proxy[0] || '',
				domain: e.domain[0] || '',
				smtpConfiguration: e.smtp[0] || ''
			}
		];
	}
	const removeTemplate = (tid) => (templates = templates.filter((t) => t.tid !== tid));

	// a template sends through one sender, so choosing one clears the other.
	function onSenderPick(t, slotKey, next) {
		if (!next) return;
		if (slotKey === 'smtpConfiguration') t.apiSender = '';
		else t.smtpConfiguration = '';
	}

	const mergedVars = $derived.by(() => {
		if (shareVars) {
			const byName = new Map();
			for (const p of picked) for (const v of p.variables) byName.has(v.name) ? byName.get(v.name).from.push(p.title) : byName.set(v.name, { ...v, from: [p.title] });
			return [...byName.values()];
		}
		const out = [];
		for (const p of picked) for (const v of p.variables) out.push({ ...v, from: [p.title] });
		return out;
	});

	// pick variables the installer fills: one per template slot set to the sentinel,
	// each declaring the entity kind the installer chooses from. deduped by name so a
	// single template sharing a slot name across itself is declared once.
	const pickVars = $derived.by(() => {
		const byName = new Map();
		for (let i = 0; i < templates.length; i++) {
			const t = templates[i];
			for (const slotKey of Object.keys(OWN_SLOTS)) {
				if (t[slotKey] !== OWN_SENTINEL) continue;
				const name = ownVarName(slotKey, i);
				if (byName.has(name)) continue;
				const scope = templates.length > 1 ? ` for ${t.name || 'template ' + (i + 1)}` : '';
				byName.set(name, {
					name,
					type: 'text',
					required: true,
					pick: OWN_SLOTS[slotKey].kind,
					description: `Your ${OWN_SLOTS[slotKey].label}${scope}`
				});
			}
		}
		return [...byName.values()];
	});

	async function loadNamespaces() {
		nsError = '';
		const res = await api.namespaces.list({ perPage: 200 });
		if (res.ok) {
			namespaces = res.data.namespaces;
			if (namespaces.length && !form.namespace) form.namespace = namespaces[0].name;
		} else nsError = res.error || 'Could not load namespaces';
		nsLoaded = true;
	}

	onMount(async () => {
		await loadNamespaces();
		const tr = await api.tags.list();
		if (tr.ok) tagColors = Object.fromEntries((tr.data.tags || []).map((t) => [t.name, t.color || '']));
		const from = $page.url.searchParams.get('from');
		if (from) await loadFrom(from);
	});

	async function loadFrom(from) {
		const [ns, name, version] = from.split('/');
		const res = await api.packages.source(ns, name, version);
		if (!res.ok) {
			toast('Could not load that bundle to edit', 'error');
			return;
		}
		const src = res.data;
		editingFrom = `${ns}/${name}`;
		form.namespace = ns;
		form.name = name;
		// the address is fixed when editing an existing bundle, so a title edit must
		// not rewrite the slug.
		slugLocked = true;
		form.version = bumpPatch(src.version);
		form.title = src.title || '';
		form.description = src.description || '';
		form.tags = (src.tags || []).join(', ');
		for (const d of src.dependencies || []) {
			const [dns, dname] = d.id.split('/');
			// addPackage fetches the package source, which carries its type and title, so
			// each dependency resolves by id without loading the whole package list.
			await addPackage({ namespace: dns, name: dname });
		}
		if (src.shareVariables === false) shareVars = false;
		// parse the campaignTemplates list back into editable templates.
		const dy = (src.files || []).find((f) => /\/data\.yaml$/i.test(f.path));
		if (dy) {
			const y = decodeText(dy.content);
			const unq = (s) => (s.length >= 2 && s[0] === '"' && s[s.length - 1] === '"' ? s.slice(1, -1).replace(/\\(.)/g, (_, c) => (c === 'n' ? '\n' : c === 't' ? '\t' : c)) : s);
			const ctM = y.match(/^campaignTemplates:\s*$/m);
			if (ctM) {
				const rest = y.slice(ctM.index + ctM[0].length).replace(/^\n/, '');
				const out = [];
				let cur = null;
				for (const lineStr of rest.split('\n')) {
					const start = lineStr.match(/^\s{2}-\s*name:\s*(.+)$/);
					if (start) {
						if (cur) out.push(cur);
						cur = { tid: nextTid++, name: unq(start[1].trim()), ...blankTemplate() };
						continue;
					}
					if (!cur) {
						if (/^\S/.test(lineStr)) break;
						continue;
					}
					const kv = lineStr.match(/^\s{4}(\w+):\s*(.*)$/);
					if (kv && kv[1] in cur) {
						const v = unq(kv[2].trim());
						cur[kv[1]] = kv[1] === 'isTraining' ? v === 'true' : kv[1] === 'lureCodeLength' ? Number(v) || 12 : v;
					} else if (/^\S/.test(lineStr)) break;
				}
				if (cur) out.push(cur);
				// a slot parsed as @@VAR@@ whose manifest variable declares a pick kind was
				// an "installer provides their own" choice, so restore the sentinel.
				const pickNames = new Set((src.variables || []).filter((v) => v && v.pick).map((v) => v.name));
				for (const t of out) {
					for (const slotKey of Object.keys(OWN_SLOTS)) {
						const m = String(t[slotKey] || '').match(/^@@(.+)@@$/);
						if (m && pickNames.has(m[1])) t[slotKey] = OWN_SENTINEL;
					}
				}
				templates = out;
			}
		}
	}

	let existingVersions = $state([]);
	$effect(() => {
		const ns = form.namespace;
		const name = form.name;
		if (!ns || !nameValid) {
			existingVersions = [];
			return;
		}
		// fetch the package's versions straight from the server, debounced while the
		// address is typed. a package that does not exist returns an error, leaving the
		// list empty, so this works without a full package list to test membership.
		let cancelled = false;
		const t = setTimeout(() => {
			api.packages.detail(ns, name).then((res) => {
				if (!cancelled) existingVersions = res.ok ? (res.data.versions || []).map((v) => v.version) : [];
			});
		}, 300);
		return () => {
			cancelled = true;
			clearTimeout(t);
		};
	});
	const versionExists = $derived(existingVersions.includes(form.version));
	const highestExisting = $derived(existingVersions.length ? existingVersions.reduce((a, b) => (compareSemver(a, b) >= 0 ? a : b)) : '');
	const versionNotHigher = $derived(versionValid && !versionExists && !!highestExisting && compareSemver(form.version, highestExisting) < 0);

	// a template needs a name and a landing surface, which is exactly one of a landing
	// page or a landing proxy. these mirror the Phishing Club campaign template rules so
	// a published bundle always installs: the landing surface is required and cannot be
	// both, a training template needs an after landing page, and before and after cannot
	// each be both a page and a proxy (the bundle only offers a page slot for those, so
	// only the landing slot can be ambiguous).
	const trainingNeedsAfter = (t) => t.isTraining && !t.afterLandingPage;
	const landingSurfaceOk = (t) => (!!t.landingPage || !!t.landingProxy) && !(t.landingPage && t.landingProxy);
	// a template sends through one sender, so an SMTP configuration and an API sender
	// cannot both be set. the UI clears one when the other is chosen; this is a backstop.
	const bothSenders = (t) => !!t.smtpConfiguration && !!t.apiSender;
	const templatesValid = $derived(templates.every((t) => t.name.trim() && landingSurfaceOk(t) && !trainingNeedsAfter(t) && !bothSenders(t)));
	const templateNamesUnique = $derived(new Set(templates.map((t) => t.name.trim())).size === templates.length);
	const canPublish = $derived(!!form.namespace && nameValid && versionValid && !versionExists && picked.length > 0 && picked.length <= MAX_BUNDLE_PACKAGES && templatesValid && templateNamesUnique && !busy);

	function templateYaml() {
		const title = form.title.trim() || form.name;
		let y = `name: ${yamlStr(title)}\n`;
		if (templates.length) {
			y += `campaignTemplates:\n`;
			const line = (k, v) => (v && String(v).trim() ? `    ${k}: ${yamlStr(String(v).trim())}\n` : '');
			// a slot set to the sentinel emits a pick variable reference the installer
			// fills; otherwise it emits the chosen bundled entity, or nothing.
			// a @@VAR@@ reference must be quoted: a bare @ starts a reserved YAML indicator,
		// so an unquoted @@VAR@@ value fails to parse.
		const slotLine = (k, v, i) => (v === OWN_SENTINEL ? `    ${k}: ${yamlStr('@@' + ownVarName(k, i) + '@@')}\n` : line(k, v));
			for (let i = 0; i < templates.length; i++) {
				const t = templates[i];
				y += `  - name: ${yamlStr(t.name || title)}\n`;
				y += slotLine('domain', t.domain, i);
				y += slotLine('email', t.email, i);
				y += slotLine('landingPage', t.landingPage, i);
				y += slotLine('landingProxy', t.landingProxy, i);
				y += slotLine('beforeLandingPage', t.beforeLandingPage, i);
				y += slotLine('afterLandingPage', t.afterLandingPage, i);
				y += slotLine('smtpConfiguration', t.smtpConfiguration, i);
				y += slotLine('apiSender', t.apiSender, i);
				y += line('afterLandingPageRedirectURL', t.afterLandingPageRedirectURL);
				y += line('urlPath', t.urlPath);
				y += `    lureURLMode: ${yamlStr(t.lureURLMode)}\n`;
				if (t.lureURLMode === 'path') {
					y += `    lureCodeAlgo: ${yamlStr(t.lureCodeAlgo)}\n`;
					y += `    lureCodeLength: ${Math.min(LURE_CODE_MAX, Math.max(LURE_CODE_MIN, Math.round(Number(t.lureCodeLength) || 12)))}\n`;
				}
				y += `    isTraining: ${!!t.isTraining}\n`;
			}
		}
		return y;
	}
	const b64text = (s) => btoa(unescape(encodeURIComponent(s)));

	async function publish() {
		if (!canPublish) {
			if (!form.namespace) toast('Pick a namespace', 'error');
			else if (!nameValid) toast('Name must be a lowercase slug (a-z, 0-9, dashes)', 'error');
			else if (!versionValid) toast('Version must be semver, like 1.0.0', 'error');
			else if (versionExists) toast(`Version ${form.version} already exists; bump it`, 'error');
			else if (picked.length === 0) toast('Add at least one package to the bundle', 'error');
			else if (picked.length > MAX_BUNDLE_PACKAGES) toast(`A bundle can reference at most ${MAX_BUNDLE_PACKAGES} packages`, 'error');
			else if (!templateNamesUnique) toast('Each campaign template needs a unique name', 'error');
			else if (templates.some(trainingNeedsAfter)) toast('A training template needs an after landing page', 'error');
			else if (templates.some(bothSenders)) toast('A template cannot use both an SMTP configuration and an API sender', 'error');
			else if (templates.some((t) => t.landingPage && t.landingProxy)) toast('A template cannot use both a landing page and a landing proxy', 'error');
			else if (templates.some((t) => !landingSurfaceOk(t))) toast('Each campaign template needs a landing page or a landing proxy', 'error');
			else toast('Each campaign template needs a name', 'error');
			return;
		}
		busy = true;
		publishError = '';
		const res = await api.packages.author({
			namespace: form.namespace,
			name: form.name,
			title: form.title.trim(),
			type: 'bundle',
			version: form.version,
			description: form.description,
			tags: form.tags.split(',').map((t) => t.trim()).filter(Boolean),
			dependencies: picked.map((p) => ({ id: p.id, range: '*' })),
			shareVariables: shareVars,
			variables: pickVars,
			files: [{ path: `content/${form.name}/data.yaml`, content: b64text(templateYaml()) }]
		});
		busy = false;
		if (res.ok) {
			toast('Bundle published', 'success');
			// a color chosen for a tag no package carried can be stored now the bundle has it.
			const colorFailed = await applyPendingTagColors(form.namespace, form.name, pendingTagColors);
			pendingTagColors = {};
			if (colorFailed.length) toast(`Could not save the color of ${colorFailed.join(', ')}`, 'error');
			goto(`/packages/${form.namespace}/${form.name}`);
		} else {
			publishError = res.error || 'Publish failed';
			toast(publishError, 'error');
		}
	}

</script>

<div class="flex items-center gap-2">
	<h1 class="pc-h1">{editingFrom ? 'New bundle version' : 'New bundle'}</h1>
	<Help title="About bundles">
		<p>A bundle is a named set of published packages installed and uninstalled together. It carries no content of its own; it references existing packages and, optionally, wires some of them into one or more campaign templates.</p>
		<p>On install, Phishing Club installs or reuses each referenced package, then creates any campaign templates. Referenced packages install at their latest version.</p>
		<p>A public bundle can reference only public packages; a private bundle can reference public packages or packages in its own namespace.</p>
	</Help>
</div>

{#if nsError}
	<ErrorCard class="mt-6" message={nsError} onretry={loadNamespaces} />
{:else if nsLoaded && namespaces.length === 0}
	<Card padding="xl" class="mt-6 text-center">
		<p class="pc-desc">No namespaces yet. Create one before publishing a bundle.</p>
		<Button href="/namespaces" variant="primary" class="mt-4 inline-block">Create a namespace</Button>
	</Card>
{:else}
	<!-- identity -->
	<Card class="mt-6">
		<div class="flex flex-wrap items-start gap-3">
			<div class="text-sm w-44">
				<span class="pc-label">Namespace</span>
				<Select bind:value={form.namespace} onchange={onNamespaceChange} options={namespaces.map((n) => ({ value: n.name, label: n.name }))} ariaLabel="Namespace" class="mt-1" />
			</div>
			<label class="text-sm min-w-[12rem] flex-1">
				<span class="pc-label">Title</span>
				<input bind:value={form.title} oninput={onTitleInput} placeholder="Microsoft 365 campaign kit" class="mt-1 pc-control" />
				<span class="mt-1 block text-xs pc-muted">Address: <input bind:value={form.name} oninput={() => (slugLocked = true)} placeholder="microsoft-365-kit" title={form.name} class="ml-1 w-48 overflow-hidden text-ellipsis rounded border-0 bg-transparent p-0 font-mono text-gray-700 focus:outline-none dark:text-gray-200 {form.name && !nameValid ? 'text-red-600 dark:text-red-400' : ''}" /></span>
			</label>
			<label class="text-sm w-28">
				<span class="pc-label">Version</span>
				<input bind:value={form.version} class="mt-1 pc-control {(form.version && !versionValid) || versionExists ? 'border-red-400 dark:border-red-700' : ''}" />
			</label>
			<div class="ml-auto flex flex-col">
				<span class="pc-label invisible" aria-hidden="true">Publish</span>
				<Button variant="primary" onclick={publish} disabled={!canPublish} class="mt-1">{busy ? 'Publishing…' : 'Publish bundle'}</Button>
			</div>
		</div>
		{#if form.version && !versionValid}
			<p class="mt-2 text-xs text-red-600 dark:text-red-400">Version must be semver, like 1.0.0.</p>
		{:else if versionExists}
			<p class="mt-2 text-xs text-red-600 dark:text-red-400">Version {form.version} already exists; bump it (latest is {highestExisting}).</p>
		{:else if versionNotHigher}
			<p class="mt-2 text-xs text-amber-700 dark:text-amber-300">Version is lower than the current latest ({highestExisting}); it publishes but will not become the latest.</p>
		{/if}
		{#if publishError}
			<Alert variant="danger" title="Not published." class="mt-3">{publishError}</Alert>
		{/if}
	</Card>

	<div class="mt-4 flex items-center gap-1 overflow-x-auto overflow-y-hidden border-b border-gray-200 dark:border-gray-800">
		{#each tabList as [key, lbl]}
			<button type="button" onclick={() => (tab = key)} aria-current={tab === key ? 'page' : undefined} class="-mb-px shrink-0 whitespace-nowrap border-b-2 px-4 py-2 text-sm font-semibold transition-colors {tab === key ? 'border-cta-blue text-cta-blue dark:border-highlight-blue dark:text-highlight-blue' : 'border-transparent text-gray-700 hover:text-gray-700 dark:text-gray-200 dark:hover:text-gray-200'}">{lbl}</button>
		{/each}
	</div>

	<!-- content tab: referenced packages, campaign templates, variables -->
	<div class="{tab === 'content' ? '' : 'hidden'}">
	<!-- referenced packages -->
	<Card class="mt-6 space-y-3">
		<div class="flex items-center gap-2">
			<h2 class="pc-card-title">Packages in this bundle</h2>
			<span class="inline-flex items-center rounded-full bg-gray-100 px-2 py-0.5 text-xs font-medium text-gray-700 dark:bg-gray-800 dark:text-gray-200">{picked.length}</span>
		</div>
		<p class="pc-desc">Reference the published packages this bundle installs. Name the bundle first; only packages this bundle is allowed to reference are listed. Phishing Club installs at most {MAX_BUNDLE_PACKAGES} packages per bundle, and the bundle together with the latest version of each package may unpack to at most 64 MiB.</p>
		{#if picked.length}
			<ul class="divide-y divide-gray-200 dark:divide-gray-800">
				{#each picked as p (p.id)}
					<li class="flex items-center gap-3 py-2.5">
						<span class="w-28 shrink-0">
							<span class="inline-block truncate rounded bg-gray-100 px-2 py-0.5 text-xs font-medium text-gray-800 dark:bg-gray-800 dark:text-gray-100">{typeLabel(p.type)}</span>
						</span>
						<span class="min-w-0 flex-1 truncate font-medium text-gray-800 dark:text-gray-100">{p.title}</span>
						<span class="max-w-[16rem] shrink-0 truncate text-right font-mono text-xs pc-muted">{p.id}</span>
						<Button variant="danger" size="xs" onclick={() => removePackage(p.id)}>Remove</Button>
					</li>
				{/each}
			</ul>
		{/if}
		{#if !form.namespace || !nameValid}
			<Alert variant="info">Set the namespace and name above to choose packages.</Alert>
		{:else}
			<div class="block text-sm">
				<span class="pc-label">Add a package</span>
				<div class="mt-1">
					<PackagePicker packages={candidates} onPick={addPackage} onSearch={doPackageSearch} placeholder="Search packages to add..." ariaLabel="Add a package" />
				</div>
			</div>
		{/if}
	</Card>

	<!-- campaign templates (optional, repeatable) -->
	<Card class="mt-6 space-y-3">
		<div class="flex items-center justify-between gap-2">
			<div class="flex items-center gap-2">
				<h2 class="pc-card-title">Campaign templates</h2>
				<span class="pc-optional">optional</span>
			</div>
			<Button variant="neutral" size="xs" onclick={addTemplate} disabled={picked.length === 0}>Add campaign template</Button>
		</div>
		{#if templates.length === 0}
			<p class="pc-desc">None. This bundle just installs its packages together. Add a campaign template to wire some of them into a ready to run campaign.</p>
		{:else}
			<p class="pc-desc">Wire the referenced pieces into campaigns. Each template's slots offer the entities from the packages above.</p>
		{/if}
		{#each templates as t (t.tid)}
			<div class="rounded-lg border border-gray-200 p-4 space-y-3 dark:border-gray-800">
				<div class="flex items-end gap-2">
					<Field label="Template name" class="flex-1"><input bind:value={t.name} placeholder="Campaign" class="pc-control" /></Field>
					<Button variant="danger" size="xs" onclick={() => removeTemplate(t.tid)}>Remove</Button>
				</div>
				<div class="grid gap-3 sm:grid-cols-2">
					<div class="text-sm"><span class="pc-label">Email</span><Select bind:value={t.email} options={slotOptionsWithOwn(entitiesByKind.email)} ariaLabel="Email" class="mt-1" /></div>
					<div class="text-sm"><span class="pc-label">Landing page</span><Select bind:value={t.landingPage} options={slotOptionsWithOwn(entitiesByKind.page)} ariaLabel="Landing page" class="mt-1" /></div>
					<div class="text-sm"><span class="pc-label">Landing proxy</span><Select bind:value={t.landingProxy} options={slotOptionsWithOwn(entitiesByKind.proxy)} ariaLabel="Landing proxy" class="mt-1" /></div>
					<div class="text-sm"><span class="pc-label">Domain</span><Select bind:value={t.domain} options={slotOptionsWithOwn(entitiesByKind.domain)} ariaLabel="Domain" class="mt-1" /></div>
					<div class="text-sm"><span class="pc-label">Before landing page</span> <span class="pc-optional">optional</span><Select bind:value={t.beforeLandingPage} options={slotOptionsWithOwn(entitiesByKind.page)} ariaLabel="Before landing page" class="mt-1" /></div>
					<div class="text-sm"><span class="pc-label">After landing page</span> <span class="pc-optional">optional</span><Select bind:value={t.afterLandingPage} options={slotOptionsWithOwn(entitiesByKind.page)} ariaLabel="After landing page" class="mt-1" /></div>
					<div class="text-sm"><span class="pc-label">SMTP configuration</span> <span class="pc-optional">optional</span><Select bind:value={t.smtpConfiguration} onchange={(next) => onSenderPick(t, 'smtpConfiguration', next)} options={slotOptionsWithOwn(entitiesByKind.smtp)} ariaLabel="SMTP configuration" class="mt-1" /></div>
					<div class="text-sm"><span class="pc-label">API sender</span> <span class="pc-optional">optional</span><Select bind:value={t.apiSender} onchange={(next) => onSenderPick(t, 'apiSender', next)} options={slotOptionsWithOwn(entitiesByKind.apisender)} ariaLabel="API sender" class="mt-1" /></div>
					<Field label="After redirect URL" optional><input bind:value={t.afterLandingPageRedirectURL} placeholder="https://www.microsoft.com" class="pc-control" /></Field>
				</div>
				<div class="grid gap-3 sm:grid-cols-2">
					<Field label="URL path" optional hint="The path the lure link uses, for example /login."><input bind:value={t.urlPath} placeholder="/login" class="pc-control" /></Field>
					<div class="text-sm"><span class="pc-label">Lure URL mode</span><Select bind:value={t.lureURLMode} options={[{ value: 'query', label: 'Query parameter' }, { value: 'path', label: 'Path segment' }]} ariaLabel="Lure URL mode" class="mt-1" /></div>
				</div>
				{#if t.lureURLMode === 'path'}
					<div class="grid gap-3 sm:grid-cols-2">
						<div class="text-sm"><span class="pc-label">Lure code format</span><Select bind:value={t.lureCodeAlgo} options={LURE_CODE_ALGOS} ariaLabel="Lure code format" class="mt-1" /></div>
						<Field label={`Lure code length (${LURE_CODE_MIN}-${LURE_CODE_MAX})`}><input type="number" min={LURE_CODE_MIN} max={LURE_CODE_MAX} bind:value={t.lureCodeLength} class="pc-control" /></Field>
					</div>
				{/if}
				<Checkbox bind:checked={t.isTraining} label="Training campaign template" />
				{#if t.landingPage && t.landingProxy}
					<Alert variant="warning">Pick either a landing page or a landing proxy, not both.</Alert>
				{:else if !t.landingPage && !t.landingProxy}
					<Alert variant="warning">A campaign template needs a landing page or a landing proxy.</Alert>
				{/if}
				{#if trainingNeedsAfter(t)}
					<Alert variant="warning">A training template needs an after landing page set above.</Alert>
				{/if}
			</div>
		{/each}
	</Card>

	<!-- variables preview + share toggle -->
	<Card class="mt-6 space-y-3">
		<h2 class="pc-card-title">Variables</h2>
		<Checkbox bind:checked={shareVars} label="Share variables with the same name across packages (filled once on install)" />
		{#if mergedVars.length}
			<p class="pc-desc">On install, the operator fills these values{shareVars ? ', shared where names match' : ', one set per package'}:</p>
			<ul class="divide-y divide-gray-200 dark:divide-gray-800">
				{#each mergedVars as v}
					<li class="flex items-center gap-2 py-1.5 text-sm">
						<code class="rounded bg-gray-100 px-1.5 py-0.5 text-xs dark:bg-gray-800">@@{v.name}@@</code>
						<span class="pc-muted">{v.type}{v.required ? ' · required' : ''}</span>
						<span class="ml-auto text-xs pc-muted">{v.from.join(', ')}</span>
					</li>
				{/each}
			</ul>
		{:else}
			<p class="text-sm pc-muted">The referenced packages declare no install variables.</p>
		{/if}
		{#if pickVars.length}
			<p class="pc-desc">The installer provides these by choosing one of their own existing entities at install:</p>
			<ul class="divide-y divide-gray-200 dark:divide-gray-800">
				{#each pickVars as v}
					<li class="flex items-center gap-2 py-1.5 text-sm">
						<code class="rounded bg-gray-100 px-1.5 py-0.5 text-xs dark:bg-gray-800">@@{v.name}@@</code>
						<span class="pc-muted">{v.pick}{v.required ? ' · required' : ''}</span>
						<span class="ml-auto text-xs pc-muted">provided by installer at install</span>
					</li>
				{/each}
			</ul>
		{/if}
	</Card>
	</div>

	<!-- details tab: registry listing metadata -->
	<Card class="mt-6 space-y-3 {tab === 'details' ? '' : 'hidden'}">
		<h2 class="pc-card-title">Details</h2>
		<Field label="Description" optional><textarea bind:value={form.description} rows="2" placeholder="What this bundle is, shown when browsing the Library in Phishing Club" class="pc-control"></textarea></Field>
		<div class="block text-sm">
			<span class="pc-label">Tags</span> <span class="pc-optional">optional</span>
			<TagEditor bind:value={form.tags} bind:colors={tagColors} bind:pending={pendingTagColors} />
		</div>
	</Card>
	<div class="h-6"></div>
{/if}
