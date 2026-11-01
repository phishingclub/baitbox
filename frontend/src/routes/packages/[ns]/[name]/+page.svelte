<script>
	import { PREVIEW_ACCEPT, PREVIEW_LIMITS_TEXT, previewFileProblem } from '$lib/utils/previewLimits.js';
	import { onMount } from 'svelte';
	import { page } from '$app/stores';
	import { goto } from '$app/navigation';
	import { api } from '$lib/api/api.js';
	import { toast } from '$lib/stores/toast.svelte.js';
	import { askConfirm } from '$lib/stores/confirm.svelte.js';
	import Skeleton from '$lib/components/Skeleton.svelte';
	import CodeEditor from '$lib/components/CodeEditor.svelte';
	import PreviewPane from '$lib/components/PreviewPane.svelte';
	import Help from '$lib/components/Help.svelte';
	import StatusPill from '$lib/components/StatusPill.svelte';
	import Pagination from '$lib/components/Pagination.svelte';
	import Button from '$lib/components/Button.svelte';
	import Card from '$lib/components/Card.svelte';
	import StatTile from '$lib/components/StatTile.svelte';
	import ErrorCard from '$lib/components/ErrorCard.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import TagEditor from '$lib/components/TagEditor.svelte';
	import { applyPendingTagColors } from '$lib/utils/tagColors.js';
	import { typeLabel } from '$lib/utils/packageType.js';
	import { nsDotClass, nsDotStyle, tagChipClass, tagChipStyle } from '$lib/utils/nsColor.js';
	import { compareSemver, highestVersion } from '$lib/utils/semver.js';
	import { fillPreview } from '$lib/utils/pcVariables.js';

	// syntax highlighting language for a source file, so the read only detail view
	// matches how the file was authored. yaml has no highlighter, so it shows plain.
	function langForPath(path) {
		if (/\.(js|mjs)$/i.test(path)) return 'javascript';
		if (/\.html?$/i.test(path)) return 'html';
		if (/\.ya?ml$/i.test(path)) return 'yaml';
		return 'text';
	}

	const ns = $derived($page.params.ns);
	const name = $derived($page.params.name);

	// the package address is the string an operator pastes to install or reference the
	// package in Phishing Club, so make it one click to copy, like tokens and urls.
	let copiedAddr = $state(false);
	let copyTimer;
	async function copyAddress() {
		try {
			await navigator.clipboard.writeText(`${ns}/${name}`);
			copiedAddr = true;
			clearTimeout(copyTimer);
			copyTimer = setTimeout(() => (copiedAddr = false), 1500);
		} catch (_) {
			toast('Copy failed; select it manually', 'error');
		}
	}

	let pkg = $state(null);
	let loaded = $state(false);
	let tagColors = $state({}); // tag name -> color token, seeded from api.tags.list()
	let namespaces = $state([]); // all namespaces, for the move target picker
	let moveTarget = $state(''); // the namespace selected to move this package into
	let moveName = $state(''); // the target name (a move can also rename the package)
	let moveOpen = $state(false); // the move package modal is open
	let moveBusy = $state(false); // a move request is in flight
	const moveValid = $derived(/^[a-z0-9][a-z0-9._-]*$/.test((moveName || '').trim()));
	// the move does nothing when neither the namespace nor the name changes
	const moveUnchanged = $derived(moveTarget === ns && (moveName || '').trim() === name);
	// the edit details modal edits the package level metadata in place. these fields live
	// on the package, not a version, so saving them does not publish a new version.
	let showEditMeta = $state(false);
	let editTitle = $state('');
	let editDescription = $state('');
	let editTags = $state(''); // comma separated string bound to the tags input
	let pendingTagColors = $state({}); // colors chosen for tags this package does not carry yet
	let editMetaBusy = $state(false);
	let editMetaError = $state('');
	let exportOpen = $state(false); // the export menu (latest only vs all versions) is open
	let selected = $state('');
	let source = $state(null); // selected version's manifest detail (variables, type)
	let descExpanded = $state(false); // the description is shown in full instead of clamped
	// preview width: desktop fills the pane, mobile constrains to a phone width so
	// an operator can check how a published page or email looks on a small screen.

	// the version an install of "latest" resolves to: the highest semver not yanked
	// one, matching the server (effectiveLatest). shown as a badge so the effective
	// latest is obvious even when an older version was published most recently.
	const latestVersion = $derived(highestVersion(pkg?.versions || []));
	// versions shown highest semver first so the list reads like a changelog and the
	// latest badge sits at the top. the server returns them created_at ordered.
	const sortedVersions = $derived([...(pkg?.versions || [])].sort((a, b) => compareSemver(b.version, a.version)));
	// paginate the versions and variables tables so a package with a long history or a
	// config type with many variables stays readable. the pager hides itself under a page.
	const versionPageSize = 20;
	let versionPage = $state(1);
	const pagedVersions = $derived(sortedVersions.slice((versionPage - 1) * versionPageSize, versionPage * versionPageSize));
	const varPageSize = 20;
	let varPage = $state(1);
	const pagedVars = $derived((source?.variables || []).slice((varPage - 1) * varPageSize, varPage * varPageSize));
	// reset the variables pager when the selected version (and so its variable set) changes.
	$effect(() => {
		const _ = selected;
		varPage = 1;
	});
	const firstPublished = $derived.by(() => {
		const vs = pkg?.versions || [];
		if (!vs.length) return null;
		return vs.reduce((min, v) => (!min || new Date(v.createdAt) < new Date(min) ? v.createdAt : min), null);
	});

	let loadError = $state('');
	async function load() {
		loadError = '';
		const res = await api.packages.detail(ns, name);
		if (res.ok) {
			pkg = res.data;
			// default to the effective latest (highest semver) so the page opens on what
			// an install of "latest" would get, not whatever was published most recently.
			selected = highestVersion(pkg.versions) || pkg.versions?.[0]?.version || '';
		} else if (res.status === 404) {
			// genuinely absent, as opposed to a network or server error, which must not
			// be shown as "not found" (the package may well exist).
			pkg = null;
		} else {
			loadError = res.error || 'Could not load this package';
		}
		loaded = true;
		await loadSource();
	}
	async function loadTagColors() {
		const tr = await api.tags.list();
		if (tr.ok) tagColors = Object.fromEntries((tr.data.tags || []).map((t) => [t.name, t.color || '']));
	}
	onMount(async () => {
		await loadTagColors();
		// the move dropdown needs every namespace, not one server page.
		const nr = await api.namespaces.list({ perPage: 200 });
		if (nr.ok) namespaces = nr.data.namespaces || [];
	});
	// refetch the package and its source whenever the address changes. a move or
	// rename navigates to the new address but reuses this component, so without this
	// the page would keep showing the previously loaded package (its namespace dot,
	// tags and source) until a manual refresh.
	$effect(() => {
		ns;
		name;
		load();
	});

	// the current namespace is a valid move target too (a rename in place).
	const moveTargets = $derived(namespaces);

	// fetch the selected version's declared variables so authors and consumers
	// can see what an install will ask for.
	async function loadSource() {
		if (!selected) {
			source = null;
			return;
		}
		const want = selected;
		const res = await api.packages.source(ns, name, selected);
		if (want !== selected) return; // a newer selection won the race
		source = res.ok ? res.data : null;
	}
	async function selectVersion(v) {
		selected = v;
		await loadSource();
	}

	// package meta preview images (shown when browsing; not part of the archive). These
	// are curated on the package itself, so adding or removing them does not publish a
	// new version.
	let previewBusy = $state(false);
	// gallery cap comes from the backend so the UI limit never drifts from the enforced one.
	const previewMax = $derived(pkg?.previewMax || 8);
	const previewCount = $derived(pkg?.previewImages?.length || 0);
	async function addPreviewImages(fileList) {
		previewBusy = true;
		let added = 0;
		for (const file of fileList) {
			const problem = previewFileProblem(file);
			if (problem) {
				toast(problem, 'error');
				continue;
			}
			const b64 = await new Promise((resolve) => {
				const r = new FileReader();
				r.onload = () => resolve(String(r.result).split(',')[1] || '');
				r.readAsDataURL(file);
			});
			const res = await api.packages.addPreview(ns, name, b64);
			if (res.ok) added++;
			else toast(res.error || 'Could not add preview image', 'error');
		}
		previewBusy = false;
		if (added) toast(added === 1 ? 'Image added' : added + ' images added', 'success');
		await load();
	}
	function onPreviewPick(e) {
		// copy the files out before clearing the input: e.target.files is a live list,
		// so resetting value first would empty it and nothing would upload.
		const files = Array.from(e.target.files || []);
		e.target.value = '';
		if (files.length) addPreviewImages(files);
	}
	// gallery drag and drop reorder. previewImages are urls ending in the blob sha;
	// dragging a tile reorders the list optimistically and persists the new order.
	let dragFrom = $state(-1);
	const previewSha = (url) => String(url).split('/').pop();
	async function reorderPreviews(from, to) {
		if (from === to || from < 0 || to < 0 || !pkg?.previewImages) return;
		const urls = [...pkg.previewImages];
		const [moved] = urls.splice(from, 1);
		urls.splice(to, 0, moved);
		pkg.previewImages = urls;
		const res = await api.packages.reorderPreviews(ns, name, urls.map(previewSha));
		if (res.ok) {
			toast('Order saved', 'success');
		} else {
			toast(res.error || 'Could not reorder previews', 'error');
			await load();
		}
	}
	function onPreviewDrop(to) {
		const from = dragFrom;
		dragFrom = -1;
		reorderPreviews(from, to);
	}
	async function removePreview(url) {
		const sha = String(url).split('/').pop();
		const res = await api.packages.removePreview(ns, name, sha);
		if (res.ok) {
			await load();
			toast('Preview image removed', 'success');
		} else toast(res.error || 'Could not remove preview image', 'error');
	}

	// enlarged preview. holds the url of the image shown in the lightbox, or null.
	let lightbox = $state(null);
	function onLightboxKey(e) {
		if (e.key === 'Escape') lightbox = null;
	}

	// the package's preview image (a bundled asset marked as the thumbnail), served
	// from the selected version's archive.
	const previewImg = $derived(
		source?.preview && selected ? `/packages/${ns}/${name}/${selected}/rawfile/${source.preview}` : ''
	);
	// page, email and report template carry HTML and get a rendered preview, matching
	// what the authoring wizard shows.
	const isHtmlType = $derived(
		pkg?.type === 'page' || pkg?.type === 'email' || pkg?.type === 'reporttemplate'
	);

	// readable stand in for an install time @@VAR@@ slot, so the preview is not a wall of
	// raw tokens. matches the authoring wizard's default stand in.
	function sampleVar(name) {
		if (/EMAIL/.test(name)) return 'alex.taylor@example.com';
		if (/URL|LINK/.test(name)) return 'https://example.com';
		if (/NAME/.test(name)) return 'Alex Taylor';
		return name.toLowerCase().replace(/_/g, ' ');
	}
	// build a self contained preview document: inline every bundled asset as a data uri and
	// fill both variable layers, so the rendered page needs no authenticated subresource
	// request. PreviewPane then posts it to the server, which runs it in an opaque origin
	// sandbox: its scripts execute but cannot read the admin session or reach the admin app.
	function inlinePreview(html) {
		let h = html;
		for (const f of source?.files || []) {
			if (!f.path.startsWith('assets/')) continue;
			const fname = f.path.slice(7);
			const ext = (fname.split('.').pop() || '').toLowerCase();
			const mime = IMG_MIME[ext] || 'application/octet-stream';
			const uri = `data:${mime};base64,${f.content}`;
			h = h.split(`{{.BaseURL}}/${fname}`).join(uri);
			h = h.split(`assets/${fname}`).join(uri);
		}
		h = h.replace(/@@([A-Z_][A-Z0-9_]{0,63})@@/g, (_, n) => sampleVar(n));
		return fillPreview(h);
	}
	// the selected version's rendered HTML body, inlined, for the scripted preview. empty
	// for non HTML types or until the version content has loaded.
	const previewSrcdoc = $derived.by(() => {
		if (!isHtmlType || !source?.files) return '';
		const htmlFile = source.files.find((f) => /\.html?$/i.test(f.path));
		return htmlFile ? inlinePreview(decodeText(htmlFile.content)) : '';
	});

	// short local date for a version's publish time; blank if missing.
	function fmtDate(s) {
		if (!s) return '';
		const d = new Date(s);
		if (isNaN(d)) return '';
		return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
	}
	// a compact human size for the archive, like 12.3 KB.
	function fmtBytes(n) {
		if (!n || n < 0) return '';
		if (n < 1024) return n + ' B';
		if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
		return (n / (1024 * 1024)).toFixed(1) + ' MB';
	}
	// publish date and archive size as one muted line, like "Oct 3, 2026 · 438 B".
	function versionMeta(v) {
		const dl = (v.downloadCount ?? 0) + ' ' + ((v.downloadCount ?? 0) === 1 ? 'download' : 'downloads');
		return [fmtDate(v.createdAt), fmtBytes(v.size), dl].filter(Boolean).join(' · ');
	}

	function decodeText(b64) {
		try {
			return decodeURIComponent(escape(atob(b64)));
		} catch (_) {
			try {
				return atob(b64);
			} catch (_) {
				return '';
			}
		}
	}
	// the text content files of the selected version, for config style packages
	// (proxy, script, allowdeny, ...) that have no HTML preview.
	// true when the decoded bytes look binary (a NUL or many control chars), so
	// we show a placeholder instead of garbled text.
	function looksBinary(text) {
		if (!text) return false;
		let control = 0;
		const n = Math.min(text.length, 2000);
		for (let i = 0; i < n; i++) {
			const c = text.charCodeAt(i);
			if (c === 0) return true;
			if (c < 9 || (c > 13 && c < 32)) control++;
		}
		return n > 0 && control / n > 0.1;
	}
	// an asset bundle's data.yaml only holds the asset settings, which show in their
	// own card, so its preview stays the file gallery.
	const contentFiles = $derived.by(() => {
		if (!source?.files || source.type === 'asset') return [];
		return source.files
			.filter((f) => f.path.startsWith('content/') && !/\.html$/i.test(f.path))
			.map((f) => {
				const text = decodeText(f.content);
				return {
					path: f.path.replace(/^content\//, ''),
					text,
					binary: looksBinary(text),
					bytes: Math.floor((f.content.length * 3) / 4)
				};
			});
	});

	const IMG_MIME = {
		png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif',
		webp: 'image/webp', svg: 'image/svg+xml', bmp: 'image/bmp', ico: 'image/x-icon'
	};
	// files bundled under assets/, shown as a gallery so an operator can see what
	// an asset bundle (or any package shipping images) contains. images get an
	// inline thumbnail; other files show name and size.
	const assetFiles = $derived.by(() => {
		if (!source?.files) return [];
		return source.files
			.filter((f) => f.path.startsWith('assets/'))
			.map((f) => {
				const fname = f.path.replace(/^assets\//, '');
				const ext = (fname.split('.').pop() || '').toLowerCase();
				const mime = IMG_MIME[ext];
				return {
					name: fname,
					src: mime ? `data:${mime};base64,${f.content}` : '',
					bytes: Math.floor((f.content.length * 3) / 4)
				};
			});
	});

	// per asset settings from the data.yaml assets blocks: content type, response
	// headers and allow deny list names. an @@NAME@@ entry is a list the installer picks.
	const assetSettings = $derived.by(() =>
		(source?.assets || []).map((a) => ({
			...a,
			lists: (a.allowDeny || []).map((n) => {
				const m = n.match(/^@@([A-Z_][A-Z0-9_]{0,63})@@$/);
				return { label: n, pick: !!m };
			})
		}))
	);
	const assetSettingsByPath = $derived(new Map(assetSettings.map((a) => [a.path, a])));

	// email attachments shipped under content/<folder>/ and linked to the email on
	// install. the source API returns the structured list; match each entry to its
	// packed file for a thumbnail and a size.
	const attachmentList = $derived.by(() => {
		const files = source?.files || [];
		return (source?.attachments || []).map((a) => {
			const file = files.find((f) => f.path === a.file);
			const content = file?.content || '';
			const bytes = Math.floor((content.length * 3) / 4);
			const basename = a.file.split('/').pop();
			const ext = (basename.split('.').pop() || '').toLowerCase();
			const mime = IMG_MIME[ext];
			const src = mime && content ? `data:${mime};base64,${content}` : '';
			const display = a.name?.trim() || basename;
			return { ...a, bytes, basename, src, display };
		});
	});
	// distinct emails these attachments belong to, so a per item email label is only
	// shown when the list spans more than one email.
	const attachmentEmails = $derived.by(() => {
		const set = new Set();
		for (const a of source?.attachments || []) if (a.emailName) set.add(a.emailName);
		return set;
	});

	// the string to paste into another package's HTML to use this shared asset. the file
	// installs as a global asset in Phishing Club, served per sending domain, so the
	// reference is {{.BaseURL}}/<file> (not the archive path assets/<file>).
	function assetRef(name) {
		return `{{.BaseURL}}/${name}`;
	}
	function copyRef(name) {
		navigator.clipboard?.writeText(assetRef(name)).then(
			() => toast('Reference copied', 'success'),
			() => toast('Could not copy', 'error')
		);
	}

	const previewLabel = $derived(
		isHtmlType ? 'Preview' : contentFiles.length ? 'Source' : assetFiles.length ? 'Files' : 'Preview'
	);

	async function yank(v, yanked) {
		// confirm the yank direction (hiding from latest); unyank is a safe restore
		if (
			yanked &&
			!(await askConfirm({
				title: 'Yank version',
				body: `Yank version ${v.version} of ${ns}/${name}? It is hidden from latest installs. Existing installs keep working and it stays installable by its exact version. This is reversible.`,
				confirmLabel: 'Yank'
			}))
		)
			return;
		const res = await api.packages.yank(ns, name, v.version, yanked);
		if (res.ok) {
			toast(yanked ? 'Version yanked' : 'Version unyanked', 'success');
			for (const w of res.data?.warnings || []) toast(w, 'error');
			await load();
		} else toast(res.error || 'Failed', 'error');
	}
	async function removeVersion(v) {
		if (!(await askConfirm({ title: 'Delete version', body: `Delete version ${v.version} of ${ns}/${name}? This cannot be undone.`, confirmLabel: 'Delete' }))) return;
		const res = await api.packages.removeVersion(ns, name, v.version);
		if (res.ok) {
			toast('Version deleted', 'success');
			for (const w of res.data?.warnings || []) toast(w, 'error');
			await load();
		} else toast(res.error || 'Failed', 'error');
	}
	async function removePackage() {
		// the server refuses to delete a package others depend on, so say so up front.
		const dep = await api.packages.dependents(ns, name);
		const dependents = dep.ok ? dep.data.dependents || [] : [];
		if (dependents.length) {
			const shown = dependents.slice(0, 5).join(', ');
			const more = dependents.length > 5 ? `, and ${dependents.length - 5} more` : '';
			toast(`${ns}/${name} cannot be deleted: ${dependents.length} other package${dependents.length === 1 ? ' depends' : 's depend'} on it (${shown}${more}). Delete those packages, or their versions that use it, first.`, 'error');
			return;
		}
		const body = `Delete the whole package ${ns}/${name} and all its versions? This cannot be undone.`;
		if (!(await askConfirm({ title: 'Delete package', body, confirmLabel: 'Delete package' }))) return;
		const res = await api.packages.remove(ns, name);
		if (res.ok) {
			toast('Package deleted', 'success');
			goto('/packages');
		} else toast(res.error || 'Failed', 'error');
	}
	// prefill the edit details fields from the current package and open the modal.
	function openEditMeta() {
		editTitle = pkg.title || '';
		editDescription = pkg.description || '';
		editTags = (pkg.tags || []).join(', ');
		editMetaError = '';
		// colors picked for tags that a cancelled edit never saved are only local, so
		// read the stored colors again.
		if (Object.keys(pendingTagColors).length) {
			pendingTagColors = {};
			loadTagColors();
		}
		showEditMeta = true;
	}
	// save the edited metadata. nothing persists until this runs, then refetch so the
	// header reflects the saved values.
	async function saveEditMeta() {
		editMetaBusy = true;
		const tags = editTags.split(',').map((t) => t.trim()).filter(Boolean);
		const res = await api.packages.updateMeta(ns, name, {
			title: editTitle.trim(),
			description: editDescription,
			tags
		});
		if (res.ok) {
			// a color chosen for a tag new to this package can be stored now it is saved.
			const failed = await applyPendingTagColors(ns, name, pendingTagColors);
			pendingTagColors = {};
			editMetaBusy = false;
			toast('Details updated', 'success');
			if (failed.length) toast(`Could not save the color of ${failed.join(', ')}`, 'error');
			showEditMeta = false;
			await Promise.all([load(), loadTagColors()]);
		} else {
			editMetaBusy = false;
			editMetaError = res.error || 'Could not update details';
			toast(editMetaError, 'error');
		}
	}
	// move the package to another namespace. the address changes, so the modal warns
	// that the old address stops getting updates before this runs.
	async function movePackage() {
		const toNs = moveTarget;
		const toName = (moveName || name).trim();
		if (!toNs || !moveValid || moveUnchanged || moveBusy) return;
		// changing the address breaks any bundle that references this package at its
		// old address, so warn with the list before proceeding (the author republishes
		// those bundles to point at the new address).
		const dep = await api.packages.dependents(ns, name);
		const dependents = dep.ok ? dep.data.dependents || [] : [];
		if (dependents.length) {
			const shown = dependents.slice(0, 5).join(', ');
			const more = dependents.length > 5 ? `, and ${dependents.length - 5} more` : '';
			const ok = await askConfirm({
				title: 'Dependents will break',
				body: `${dependents.length} other ${dependents.length === 1 ? 'package references' : 'packages reference'} ${ns}/${name} (${shown}${more}). Changing its address to ${toNs}/${toName} breaks them until each is republished to point at the new address. Continue?`,
				confirmLabel: 'Move anyway'
			});
			if (!ok) return;
		}
		moveBusy = true;
		const res = await api.packages.move(ns, name, toNs, toName);
		moveBusy = false;
		if (res.ok) {
			moveOpen = false;
			toast(`Moved to ${toNs}/${toName}`, 'success');
			goto(`/packages/${toNs}/${toName}`);
		} else toast(res.error || 'Could not move package', 'error');
	}
</script>

<svelte:head><title>{ns}/{name} · Bait Box</title></svelte:head>
<svelte:window onkeydown={onLightboxKey} />

<div class="flex items-center justify-between">
	<div>
		<div class="flex items-center gap-2">
			<h1 class="flex items-center gap-2">
				<span class="h-3 w-3 shrink-0 rounded-full {nsDotClass(pkg?.namespaceColor)}" style={nsDotStyle(pkg?.namespaceColor)}></span>
				<span class="font-body text-2xl font-semibold tracking-tight text-gray-900 dark:text-gray-100">{pkg?.title || name}</span>
			</h1>
			<Help title="Install & publish">
				<p>To install from Phishing Club, open the <strong>Library</strong> page, add this registry with <strong>Add Bait Box</strong>, then find this package in the <strong>Library</strong>. A private package also needs a read token.</p>
				<p>Authoring and publishing are done here in the admin area: edit the content, then use <strong>Publish new version</strong>.</p>
			</Help>
		</div>
		<!-- the address is the package's canonical id (namespace/name). it is what an
		     operator references in a runbook or shares with a teammate, so keep it
		     below the friendly title with a one click copy. -->
		<div class="mt-1 flex items-center gap-2">
			<span class="font-mono text-sm text-gray-600 dark:text-gray-400">{ns}/{name}</span>
			<button
				type="button"
				onclick={copyAddress}
				title="Copy the package address"
				aria-label="Copy the package address"
				class="rounded border border-gray-300 px-2 py-0.5 font-sans text-xs font-medium text-gray-700 hover:bg-gray-100 dark:border-gray-700 dark:text-gray-200 dark:hover:bg-gray-800"
			>{copiedAddr ? 'Copied' : 'Copy address'}</button>
		</div>
	</div>
	{#if pkg}
		<div class="flex flex-wrap items-center gap-2">
			<div class="relative">
				<Button variant="secondary" onclick={() => (exportOpen = !exportOpen)}>Export</Button>
				{#if exportOpen}
					<div class="absolute right-0 z-20 mt-1 w-44 overflow-hidden rounded-md border border-gray-200 bg-white shadow-lg dark:border-gray-800 dark:bg-gray-950">
						<a href={`/admin/packages/${ns}/${name}/export?latest=true`} download={`${ns}-${name}-latest.tar.gz`} onclick={() => (exportOpen = false)} class="block px-3 py-2 text-sm text-gray-700 hover:bg-gray-100 dark:text-gray-200 dark:hover:bg-gray-800">Latest version</a>
						<a href={`/admin/packages/${ns}/${name}/export`} download={`${ns}-${name}.tar.gz`} onclick={() => (exportOpen = false)} class="block px-3 py-2 text-sm text-gray-700 hover:bg-gray-100 dark:text-gray-200 dark:hover:bg-gray-800">All versions</a>
					</div>
					<!-- catch an outside click so the export menu closes. -->
					<button type="button" class="fixed inset-0 z-10 cursor-default" aria-label="Close export menu" onclick={() => (exportOpen = false)}></button>
				{/if}
			</div>
			<Button variant="secondary" onclick={openEditMeta}>Edit details</Button>
			{#if moveTargets.length}
				<Button variant="secondary" onclick={() => { moveTarget = ns; moveName = name; moveOpen = true; }}>Move or rename</Button>
			{/if}
			<Button href={`${pkg.type === 'bundle' ? '/packages/bundle' : '/packages/new'}?from=${ns}/${name}/${selected || 'latest'}`} variant="primary">Publish new version</Button>
			<Button variant="danger" onclick={removePackage}>Delete package</Button>
		</div>
	{/if}
</div>

{#if !loaded}
	<Card padding="none" class="mt-6 overflow-hidden">
		<Skeleton rows={5} />
	</Card>
{:else if loadError}
	<ErrorCard message={loadError} onretry={load} class="mt-6" />
{:else if !pkg}
	<p class="mt-6 text-sm text-gray-700 dark:text-gray-200">Package not found.</p>
{:else}
	<div class="mt-1 flex flex-wrap items-center gap-2 text-sm text-gray-700 dark:text-gray-200">
		<span>{typeLabel(pkg.type)}</span>
		<StatusPill tone={pkg.visibility === 'public' ? 'public' : 'private'}>{pkg.visibility}</StatusPill>
	</div>
	{#if pkg?.tags && pkg.tags.length}
		<div class="mt-2 flex flex-wrap gap-1">
			{#each pkg.tags as t}
				<button
					type="button"
					onclick={() => goto(`/packages?tag=${encodeURIComponent(t)}`)}
					class="rounded px-2 py-0.5 text-xs {tagChipClass(tagColors[t])}"
					style={tagChipStyle(tagColors[t])}
				>{t}</button>
			{/each}
		</div>
	{/if}
	{#if previewImg}
		<img
			src={previewImg}
			alt={`${name} preview`}
			class="mt-3 h-28 w-auto max-w-[16rem] rounded-lg border border-gray-200 bg-white object-contain dark:border-gray-800 dark:bg-gray-900"
		/>
	{/if}
	{#if pkg?.description}
		<p class="mt-2 whitespace-pre-line text-sm text-gray-700 dark:text-gray-200 {descExpanded ? '' : 'line-clamp-6'}">{pkg.description}</p>
		{#if pkg.description.length > 360 || pkg.description.split('\n').length > 6}
			<button
				type="button"
				onclick={() => (descExpanded = !descExpanded)}
				class="mt-1 text-xs font-medium text-gray-600 underline hover:text-gray-900 dark:text-gray-300 dark:hover:text-gray-100"
			>{descExpanded ? 'Read less' : 'Read more'}</button>
		{/if}
	{/if}

	<div class="mt-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
		<StatTile value={(pkg.versions || []).length.toLocaleString()} label="Versions" />
		<StatTile value={(pkg.downloadCount ?? 0).toLocaleString()} label="Downloads" />
		<StatTile value={latestVersion || '-'} label="Latest" />
		<StatTile value={firstPublished ? new Date(firstPublished).toLocaleDateString() : '-'} label="First published" />
	</div>

	<Card padding="md" class="mt-6">
		<div class="flex items-center justify-between">
			<div class="flex items-center gap-2">
				<h2 class="text-sm font-semibold text-gray-900 dark:text-white">Preview images</h2>
				<Help title="Preview images">
					<p>Images shown when browsing this package in the Library and on this page.</p>
					<p>They are <strong>package metadata</strong>, not shipped inside the package and not referenceable from content. Add or remove them any time; it does not publish a new version.</p>
					<p>Drag a tile to reorder them. The first image leads the gallery. Up to {previewMax} images.</p>
					<p>{PREVIEW_LIMITS_TEXT}</p>
				</Help>
			</div>
			<div class="flex items-center gap-2">
				<span class="text-xs text-gray-600 dark:text-gray-300">{previewCount} / {previewMax}</span>
				<label class="pc-btn-xs-neutral cursor-pointer {previewBusy || previewCount >= previewMax ? 'pointer-events-none opacity-50' : ''}">
					{previewBusy ? 'Uploading…' : 'Add images'}
					<input type="file" accept={PREVIEW_ACCEPT} multiple class="hidden" onchange={onPreviewPick} disabled={previewBusy || previewCount >= previewMax} />
				</label>
			</div>
		</div>
		{#if pkg.previewImages && pkg.previewImages.length}
			<div class="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5">
				{#each pkg.previewImages as url, i (url)}
					<div
						role="listitem"
						draggable="true"
						ondragstart={() => (dragFrom = i)}
						ondragover={(e) => e.preventDefault()}
						ondrop={(e) => { e.preventDefault(); onPreviewDrop(i); }}
						class="group relative cursor-move overflow-hidden rounded-lg border border-gray-200 dark:border-gray-800 {dragFrom === i ? 'opacity-50' : ''}">
						<button type="button" onclick={() => (lightbox = url)} class="block w-full" aria-label="Enlarge preview">
							<img src={url} alt={`${name} preview`} draggable="false" class="h-32 w-full cursor-zoom-in bg-white object-cover dark:bg-gray-900" />
						</button>
						<span class="pointer-events-none absolute left-1 top-1 rounded bg-white px-1.5 py-0.5 text-xs font-medium text-gray-700 dark:bg-gray-950 dark:text-gray-200">{i + 1}</span>
						<Button variant="danger" size="xs" onclick={() => removePreview(url)} class="absolute right-1 top-1 bg-white opacity-0 shadow-sm focus-visible:opacity-100 group-hover:opacity-100 dark:bg-gray-950">Remove</Button>
					</div>
				{/each}
			</div>
		{:else}
			<p class="mt-3 text-xs text-gray-700 dark:text-gray-200">No preview images yet. Add a few so operators can recognize this package when browsing.</p>
		{/if}
	</Card>

	<div class="mt-6 grid gap-6 lg:grid-cols-[20rem_minmax(0,1fr)] lg:items-start">
		<Card padding="none" class="overflow-hidden">
			<div class="flex items-center gap-2 px-4 py-3 border-b border-gray-100 dark:border-gray-800">
				<span class="text-sm font-semibold text-gray-700 dark:text-gray-200">Versions</span>
				<Help title="Versions">
					<p><strong>Yank</strong> hides a version from latest installs but keeps it installable by its exact version, so existing installs keep working. It is reversible.</p>
					<p><strong>Delete</strong> removes a version permanently.</p>
				</Help>
			</div>
			<ul class="max-h-[460px] divide-y divide-gray-100 dark:divide-gray-800 overflow-y-auto">
				{#each pagedVersions as v (v.version)}
					<li class="px-4 py-3">
						<div class="min-w-0">
							<button class="font-medium hover:underline {selected === v.version ? 'text-cta-blue dark:text-pc-dusty-light-blue' : ''}" onclick={() => selectVersion(v.version)}>{v.version}</button>
							{#if v.version === latestVersion}<span class="ml-2 inline-flex"><StatusPill tone="latest">latest</StatusPill></span>{/if}
							{#if v.yanked}<span class="ml-2 inline-flex"><StatusPill tone="yanked">yanked</StatusPill></span>{/if}
							{#if versionMeta(v)}
								<div class="mt-0.5 text-xs text-gray-700 dark:text-gray-200">{versionMeta(v)}</div>
							{/if}
						</div>
						<div class="mt-2 flex flex-wrap gap-2 text-xs">
							<Button href={`/api/v1/admin/packages/${ns}/${name}/versions/${v.version}/archive`} download={`${name}-${v.version}.tar.gz`} variant="neutral" size="xs">Download</Button>
							<Button
								variant="warn"
								size="xs"
								onclick={() => yank(v, !v.yanked)}
								title={v.yanked
									? 'Make this version eligible to be installed as latest again.'
									: 'Hide this version from latest installs. It stays installable by its exact version, so existing installs keep working. Reversible.'}
							>{v.yanked ? 'Unyank' : 'Yank'}</Button>
							<Button variant="danger" size="xs" onclick={() => removeVersion(v)}>Delete</Button>
						</div>
					</li>
				{/each}
			</ul>
			<Pagination pageNum={versionPage} pageSize={versionPageSize} total={sortedVersions.length} onchange={(n) => (versionPage = n)} />
		</Card>

		<Card padding="sm" class="flex min-h-0 flex-col h-[28rem] lg:h-[38rem]">
			{#if isHtmlType && previewSrcdoc}
				<div class="min-h-0 flex-1"><PreviewPane srcdoc={previewSrcdoc} label={`${previewLabel}${selected ? ` (${selected})` : ''}`} /></div>
			{:else if contentFiles.length}
				<div class="mb-2 text-sm font-semibold text-gray-700 dark:text-gray-200">{previewLabel} {selected ? `(${selected})` : ''}</div>
				<div class="min-h-0 flex-1 space-y-3 overflow-auto">
					{#each contentFiles as f (f.path)}
						<div>
							<div class="text-xs font-mono text-gray-700 dark:text-gray-200 mb-1">{f.path}</div>
							{#if f.binary}
								<div class="rounded border border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-gray-900 p-3 text-xs text-gray-700 dark:text-gray-200">Binary file ({(f.bytes / 1024).toFixed(1)} KB), not shown.</div>
							{:else}
								<CodeEditor value={f.text} lang={langForPath(f.path)} readonly />
							{/if}
						</div>
					{/each}
				</div>
				<p class="mt-2 text-xs text-gray-700 dark:text-gray-200"><code>@@VARIABLES@@</code> show as tokens here; they are filled on install.</p>
			{:else if assetFiles.length}
				<div class="mb-2 text-sm font-semibold text-gray-700 dark:text-gray-200">{previewLabel} {selected ? `(${selected})` : ''}</div>
				<div class="grid min-h-0 flex-1 grid-cols-2 gap-3 overflow-auto sm:grid-cols-3 content-start">
					{#each assetFiles as f (f.name)}
						<div class="overflow-hidden rounded border border-gray-200 dark:border-gray-800">
							{#if f.src}
								<img src={f.src} alt={f.name} class="h-24 w-full bg-gray-50 object-contain dark:bg-gray-900" />
							{:else}
								<div class="flex h-24 items-center justify-center bg-gray-50 text-xs text-gray-700 dark:bg-gray-900 dark:text-gray-200">file</div>
							{/if}
							<div class="truncate px-2 pt-1 text-xs text-gray-800 dark:text-gray-100" title={f.name}>{f.name}</div>
							{#if assetSettingsByPath.get(f.name)}
								{@const st = assetSettingsByPath.get(f.name)}
								<div class="truncate px-2 text-xs text-gray-600 dark:text-gray-300" title={st.contentType || ''}>
									{[st.contentType, st.headers.length ? `${st.headers.length} header${st.headers.length === 1 ? '' : 's'}` : '', st.allowDeny.length ? `${st.allowDeny.length} list${st.allowDeny.length === 1 ? '' : 's'}` : ''].filter(Boolean).join(' · ')}
								</div>
							{/if}
							<div class="flex items-center justify-between gap-2 px-2 pb-1">
								<span class="text-xs text-gray-700 dark:text-gray-200">{(f.bytes / 1024).toFixed(1)} KB</span>
								<Button variant="neutral" size="xs" onclick={() => copyRef(f.name)} title={`Copy ${assetRef(f.name)}`} class="shrink-0">copy ref</Button>
							</div>
						</div>
					{/each}
				</div>
			{:else}
				<div class="flex min-h-0 flex-1 items-center justify-center">
					<p class="text-sm text-gray-700 dark:text-gray-200">No preview available.</p>
				</div>
			{/if}
		</Card>
	</div>

	{#if assetSettings.length}
		<Card padding="md" class="mt-6">
			<div class="flex items-center gap-2">
				<h2 class="text-sm font-semibold text-gray-900 dark:text-white">Asset settings</h2>
				<Help title="Asset settings">
					<p>How Phishing Club serves each file after install: its content type, extra response headers and the allow / deny lists that decide who gets it.</p>
					<p>A list written as <code>@@NAME@@</code> is one the installer picks from their own lists.</p>
				</Help>
			</div>
			<ul class="mt-3 space-y-3">
				{#each assetSettings as a (a.file)}
					<li class="rounded-lg border border-gray-200 dark:border-gray-800 p-3">
						<div class="flex flex-wrap items-center gap-2">
							<span class="font-medium text-gray-900 dark:text-gray-100">{a.name || a.path.split('/').pop()}</span>
							<code class="text-xs text-gray-700 dark:text-gray-200">{assetRef(a.path)}</code>
						</div>
						{#if a.description}<p class="mt-1 text-xs text-gray-700 dark:text-gray-200">{a.description}</p>{/if}
						<dl class="mt-2 grid gap-x-4 gap-y-1 text-xs sm:grid-cols-[8rem_1fr]">
							<dt class="pc-label">Content type</dt>
							<dd class="font-mono text-gray-800 dark:text-gray-100">{a.contentType || 'From the file extension'}</dd>
							{#if a.headers.length}
								<dt class="pc-label">Headers</dt>
								<dd class="space-y-0.5">
									{#each a.headers as h, hi (hi)}<div class="break-all font-mono text-gray-800 dark:text-gray-100">{h.key}: {h.value}</div>{/each}
								</dd>
							{/if}
							{#if a.lists.length}
								<dt class="pc-label">Allow / deny</dt>
								<dd class="flex flex-wrap gap-1.5">
									{#each a.lists as l, li (li)}
										<span class="rounded px-2 py-0.5 bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-100">{l.label}{#if l.pick}<span class="ml-1 text-gray-600 dark:text-gray-300">installer picks</span>{/if}</span>
									{/each}
								</dd>
							{/if}
						</dl>
					</li>
				{/each}
			</ul>
		</Card>
	{/if}

	{#if attachmentList.length}
		<Card padding="md" class="mt-6">
			<h2 class="text-sm font-semibold text-gray-900 dark:text-white">Attachments</h2>
			<ul class="mt-3 space-y-3">
				{#each attachmentList as a (a.file)}
					<li class="flex items-start gap-3 rounded-lg border border-gray-200 dark:border-gray-800 p-3">
						{#if a.src}
							<img src={a.src} alt={a.display} class="h-16 w-16 shrink-0 rounded border border-gray-200 bg-white object-contain dark:border-gray-800 dark:bg-gray-900" />
						{:else}
							<div class="flex h-16 w-16 shrink-0 items-center justify-center rounded border border-gray-200 bg-gray-50 text-xs text-gray-700 dark:border-gray-800 dark:bg-gray-900 dark:text-gray-200">file</div>
						{/if}
						<div class="min-w-0 flex-1">
							<div class="flex flex-wrap items-center gap-2">
								<span class="font-medium text-gray-900 dark:text-gray-100">{a.display}</span>
								{#if a.embedded}<span class="rounded px-2 py-0.5 text-xs bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-100">Embedded</span>{/if}
								{#if a.inline}<span class="rounded px-2 py-0.5 text-xs bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-100">Inline</span>{/if}
								{#if a.calendar}<span class="rounded px-2 py-0.5 text-xs bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-100">Calendar</span>{/if}
								{#if a.emailName && attachmentEmails.size > 1}<span class="text-xs text-gray-600 dark:text-gray-300">{a.emailName}</span>{/if}
							</div>
							<div class="mt-0.5 font-mono text-xs text-gray-700 dark:text-gray-200">{a.basename}</div>
							{#if a.description}<p class="mt-1 text-xs text-gray-700 dark:text-gray-200">{a.description}</p>{/if}
							<div class="mt-1 text-xs text-gray-600 dark:text-gray-300">{fmtBytes(a.bytes) || (a.bytes / 1024).toFixed(1) + ' KB'}</div>
							{#if a.inline}
								<p class="mt-1 text-xs text-gray-600 dark:text-gray-300">Reference it in the email HTML as <code>cid:{a.basename}</code></p>
							{/if}
						</div>
					</li>
				{/each}
			</ul>
		</Card>
	{/if}

		<Card padding="none" class="mt-6 overflow-hidden">
			<div class="flex items-center gap-2 px-4 py-3 border-b border-gray-100 dark:border-gray-800">
				<span class="text-sm font-semibold text-gray-700 dark:text-gray-200">Variables {selected ? `(${selected})` : ''}</span>
				<Help title="Variables">
					<p>Values the installer provides at install time. A <strong>secret</strong> is required and its value is never shipped in the package.</p>
				</Help>
			</div>
			{#if source && source.variables && source.variables.length}
				<div class="overflow-x-auto"><table class="w-full text-sm">
					<thead class="bg-gray-50 dark:bg-gray-900 text-gray-700 dark:text-gray-200">
						<tr>
							<th class="text-left px-4 py-2 font-medium">Name</th>
							<th class="text-left px-4 py-2 font-medium">Type</th>
							<th class="text-left px-4 py-2 font-medium">Required</th>
							<th class="text-left px-4 py-2 font-medium">Default</th>
							<th class="text-left px-4 py-2 font-medium">Description</th>
						</tr>
					</thead>
					<tbody>
						{#each pagedVars as v (v.name)}
							<tr class="border-t border-gray-100 dark:border-gray-800">
								<td class="px-4 py-3"><code>@@{v.name}@@</code></td>
								<td class="px-4 py-3">
									<span class="rounded px-2 py-0.5 text-xs {v.type === 'secret' ? 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300' : 'bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-100'}">{v.type}</span>
								</td>
								<td class="px-4 py-3">{v.required ? 'yes' : 'no'}</td>
								<td class="px-4 py-3 text-gray-700 dark:text-gray-200">{v.default ?? 'none'}</td>
								<td class="px-4 py-3 text-gray-700 dark:text-gray-200">{v.description || 'none'}</td>
							</tr>
						{/each}
					</tbody>
				</table></div>
				<Pagination pageNum={varPage} pageSize={varPageSize} total={source.variables.length} onchange={(n) => (varPage = n)} />
			{:else}
				<p class="px-4 py-4 text-sm text-gray-700 dark:text-gray-200">This version declares no variables.</p>
			{/if}
		</Card>

		{#if source && source.dependencies && source.dependencies.length}
			<Card padding="none" class="mt-6 overflow-hidden">
				<div class="px-4 py-3 text-sm font-semibold text-gray-700 dark:text-gray-200 border-b border-gray-100 dark:border-gray-800">
					Dependencies {selected ? `(${selected})` : ''}
				</div>
				<p class="px-4 pt-3 text-xs text-gray-700 dark:text-gray-200">Other packages this one reuses. They install automatically when this package is installed.</p>
				<ul class="px-4 py-3 space-y-1 text-sm">
					{#each source.dependencies as d (d.id)}
						<li class="flex items-center justify-between gap-2">
							<a href={`/packages/${d.id}`} class="font-medium text-cta-blue hover:underline dark:text-pc-dusty-light-blue">{d.id}</a>
							{#if d.range && d.range !== '>=0.0.0'}<code class="text-xs text-gray-700 dark:text-gray-200">{d.range}</code>{/if}
						</li>
					{/each}
				</ul>
			</Card>
		{/if}
{/if}

{#if lightbox}
	<!-- enlarged preview. click the overlay or press Escape to dismiss. -->
	<button
		type="button"
		class="fixed inset-0 z-50 flex items-center justify-center bg-black/80 p-4"
		onclick={() => (lightbox = null)}
		aria-label="Close preview">
		<img src={lightbox} alt={`${name} preview`} class="max-h-[90vh] max-w-[90vw] rounded-lg object-contain shadow-2xl" />
	</button>
{/if}

<Modal bind:open={moveOpen} title="Move or rename package" size="md">
	<div class="flex flex-wrap gap-3">
		<label class="block text-sm w-44">
			<span class="pc-label">Namespace</span>
			<select bind:value={moveTarget} class="mt-1 pc-control">
				{#each moveTargets as n}<option value={n.name}>{n.name}</option>{/each}
			</select>
		</label>
		<label class="block text-sm flex-1 min-w-48">
			<span class="pc-label">Name</span>
			<input bind:value={moveName} class="mt-1 pc-control {moveName && !moveValid ? 'border-red-400 dark:border-red-700' : ''}" />
			{#if moveName && !moveValid}
				<span class="mt-1 block text-xs text-red-600 dark:text-red-400">Lowercase letters, numbers, dots, dashes or underscores.</span>
			{/if}
		</label>
	</div>
	<p class="mt-3 text-sm text-gray-700 dark:text-gray-100">Old installs stop working. Reinstall from the new address:</p>
	<p class="mt-1 break-all font-mono text-sm text-gray-900 dark:text-gray-100">{moveTarget || ns}/{(moveName || '').trim() || name}</p>
	{#snippet footer()}
		<Button variant="secondary" onclick={() => (moveOpen = false)}>Cancel</Button>
		<Button variant="primary" onclick={movePackage} disabled={!moveTarget || !moveValid || moveUnchanged || moveBusy}>{moveBusy ? 'Saving…' : 'Save'}</Button>
	{/snippet}
</Modal>

<Modal bind:open={showEditMeta} title="Edit details" size="md">
	<div class="flex flex-col gap-3">
		<label class="block text-sm">
			<span class="pc-label">Title</span>
			<input bind:value={editTitle} class="mt-1 pc-control" />
		</label>
		<label class="block text-sm">
			<span class="pc-label">Description</span>
			<textarea bind:value={editDescription} rows="4" class="mt-1 pc-control"></textarea>
		</label>
		<!-- not a label: a label would forward any click inside the tag editor to its
		     first control (the first tag's color button). -->
		<div class="block text-sm">
			<span class="pc-label">Tags</span>
			<div class="mt-1"><TagEditor bind:value={editTags} bind:colors={tagColors} bind:pending={pendingTagColors} saved={pkg?.tags || []} /></div>
		</div>
	</div>
	{#snippet footer()}
		<Button variant="secondary" onclick={() => (showEditMeta = false)}>Cancel</Button>
		<Button variant="primary" onclick={saveEditMeta} disabled={editMetaBusy}>{editMetaBusy ? 'Saving…' : 'Save'}</Button>
	{/snippet}
</Modal>
