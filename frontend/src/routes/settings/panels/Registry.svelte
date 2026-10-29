<script>
	import { onMount } from 'svelte';
	import { api } from '$lib/api/api.js';
	import Help from '$lib/components/Help.svelte';
	import Button from '$lib/components/Button.svelte';
	import Card from '$lib/components/Card.svelte';
	import Alert from '$lib/components/Alert.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import Field from '$lib/components/Field.svelte';
	import PasswordInput from '$lib/components/PasswordInput.svelte';
	import { toast } from '$lib/stores/toast.svelte.js';
	import { askConfirm } from '$lib/stores/confirm.svelte.js';
	import ImportResult from '$lib/components/ImportResult.svelte';
	import { importSummary, importNeedsDetail } from '$lib/utils/importSummary.js';

	let importing = $state(false);
	// the import result: a toast for a plain add, and the detail dialog when the
	// import upgraded, skipped or refused existing packages.
	let importResult = $state(null);
	let importResultOpen = $state(false);
	function showImportResult(data) {
		toast(importSummary(data), data?.refused?.length ? 'error' : 'success');
		if (importNeedsDetail(data)) {
			importResult = data;
			importResultOpen = true;
		}
	}
	let fileInput;

	async function doImport(e) {
		const file = e.target.files?.[0];
		if (!file) return;
		const ok = await askConfirm({
			title: 'Import registry',
			body:
				`Import "${file.name}" into this registry? Existing packages with the same name and ` +
				'version are kept; new namespaces, packages and versions are added. Operators, ' +
				'passkeys, read tokens and drafts are not part of an export and are left as they are.',
			confirmLabel: 'Import'
		});
		if (!ok) {
			fileInput.value = '';
			return;
		}
		importing = true;
		try {
			const res = await fetch('/admin/import', {
				method: 'POST',
				credentials: 'same-origin',
				headers: { 'Content-Type': 'application/gzip' },
				body: file
			});
			let data = null;
			try {
				data = await res.json();
			} catch (_) {
				/* not json */
			}
			if (res.ok) {
				showImportResult(data);
			} else {
				toast((data && data.error) || 'Import failed', 'error');
			}
		} catch (_) {
			toast('Import failed', 'error');
		} finally {
			importing = false;
			fileInput.value = '';
		}
	}

	// the whole registry export carries every private package and its content, so it
	// is gated behind a confirmation before the download starts.
	async function doExport() {
		const ok = await askConfirm({
			title: 'Export registry',
			body:
				'Download the registry content (every namespace, package, version and preview image) ' +
				'as one file? It includes your private packages and their content, so store it ' +
				'somewhere safe. Operators, passkeys, read tokens and drafts are not included.',
			confirmLabel: 'Export'
		});
		if (!ok) return;
		const a = document.createElement('a');
		a.href = '/admin/export';
		// no filename here, so the browser uses the server's date stamped name from
		// Content-Disposition instead of a fixed one.
		a.download = '';
		document.body.appendChild(a);
		a.click();
		a.remove();
	}


	// the registry listener address comes from the server config, not this page:
	// the admin UI runs on its own port, which Phishing Club must not use.
	let registryUrl = $state('');
	let registryPublic = $state(false);
	let registryLoading = $state(true);
	onMount(async () => {
		const r = await api.instance();
		if (r.ok) {
			registryUrl = r.data?.registryUrl || '';
			registryPublic = !!r.data?.registryPublic;
		}
		registryLoading = false;
	});

	function copyUrl() {
		navigator.clipboard?.writeText(registryUrl).then(
			() => toast('Registry URL copied', 'success'),
			() => toast('Could not copy', 'error')
		);
	}

	// turning admin access off writes the config; only a change on the server
	// turns it back on.
	let disableOpen = $state(false);
	let disablePassword = $state('');
	let disabling = $state(false);
	let adminOff = $state(false);

	function closeDisable() {
		disableOpen = false;
		disablePassword = '';
	}

	async function disableAdmin(e) {
		e?.preventDefault();
		if (!disablePassword || disabling) return;
		disabling = true;
		const res = await api.disableAdmin(disablePassword);
		disabling = false;
		if (!res.ok) {
			toast(res.error || 'Could not turn off admin access', 'error');
			return;
		}
		closeDisable();
		adminOff = true;
	}
</script>

<div class="grid items-start gap-6 lg:grid-cols-2">
	<!-- Export and import -->
	<Card padding="lg">
		<h3 class="pc-card-title">Export and import</h3>
		<p class="mt-1 pc-desc">
			Export the registry content as one file, or import a file exported from Bait Box. Use it to
			move content to another registry or copy it between registries.
		</p>
		<p class="mt-2 pc-desc">
			<strong>Included:</strong> namespaces, packages, every version, preview images, package details
			and tag colors.
		</p>
		<p class="mt-1 pc-desc">
			<strong>Not included:</strong> operators, passkeys, read tokens and drafts. This is
			not a full backup of the server.
		</p>
		<div class="mt-4 space-y-3">
			<Button variant="secondary" onclick={doExport}>Export registry</Button>
			<div>
				<Button variant="secondary" disabled={importing} onclick={() => fileInput.click()}>
					{importing ? 'Importing...' : 'Import registry'}
				</Button>
				<input
					bind:this={fileInput}
					type="file"
					accept=".gz,.tar.gz,application/gzip"
					class="hidden"
					onchange={doImport}
				/>
				<p class="mt-2 pc-desc">Accepts a .tar.gz exported from Bait Box.</p>
			</div>
		</div>
	</Card>

	<!-- Connect to Phishing Club -->
	<Card padding="lg">
		<div class="flex items-center gap-2">
			<h3 class="pc-card-title">Connect from Phishing Club</h3>
			<Help title="Connect from Phishing Club">
				<p>
					1. In Phishing Club, open the <strong>Library</strong> page and choose
					<strong>Add Bait Box</strong>.
				</p>
				<p>2. Paste the registry URL shown here.</p>
				<p>
					3. Create a read token under Tokens and paste it in Phishing Club. Only a public
					registry lets Phishing Club read public namespaces without one.
				</p>
				<p>
					4. Open the <strong>Library</strong> in Phishing Club to browse and install. Required
					variables are filled in during install.
				</p>
			</Help>
		</div>
		<p class="mt-1 pc-desc">
			Operators add this registry in Phishing Club, then browse and install packages from it.
		</p>

		<div class="mt-4">
			<div class="pc-label">Registry URL</div>
			{#if registryLoading}
				<p class="mt-1 pc-desc">Loading…</p>
			{:else if registryUrl}
				<div class="mt-1 flex items-center gap-2">
					<code
						class="min-w-0 flex-1 break-all rounded border border-gray-200 bg-gray-50 px-3 py-2
							text-sm dark:border-gray-800 dark:bg-gray-900">{registryUrl}</code
					>
					<Button variant="neutral" size="xs" onclick={copyUrl}>Copy</Button>
				</div>
				<p class="mt-1 pc-desc">
					The registry address, not this admin page. It comes from
					<code>registry.tls_host</code> and the registry port in the config.
				</p>
				<div class="mt-4">
					{#if registryPublic}
						<Alert variant="warning" title="Public registry.">
							Anyone can read public namespaces without a token. Private namespaces still need
							one. Turn off <code>registry.public</code> in the config to require a token on every request.
						</Alert>
					{:else}
						<Alert variant="info" title="Private registry.">
							Every request needs a read token, and namespaces cannot be public. Set
							<code>registry.public</code> in the config to allow anonymous reads of public namespaces.
						</Alert>
					{/if}
				</div>
			{:else}
				<p class="mt-1 pc-desc">
					No registry address is configured. Set <code>registry.tls_host</code> in the config.
				</p>
			{/if}
		</div>
	</Card>

	<!-- Admin access -->
	<Card padding="lg">
		<h3 class="pc-card-title">Admin access</h3>
		{#if adminOff}
			<p class="mt-1 pc-desc">
				Admin access is off. Run <code>baitbox -enable-admin</code> on the server to turn it back on.
			</p>
		{:else}
			<p class="mt-1 pc-desc">
				Turns off the admin UI and API. The registry keeps serving. Only
				<code>baitbox -enable-admin</code> on the server turns it back on.
			</p>
			<div class="mt-4">
				<Button variant="danger" onclick={() => (disableOpen = true)}>Turn off admin access</Button>
			</div>
		{/if}
	</Card>
</div>

<Modal bind:open={disableOpen} title="Turn off admin access" size="sm" onclose={closeDisable}>
	<form id="disable-admin-form" class="space-y-4" onsubmit={disableAdmin}>
		<p class="pc-desc">The admin closes for everyone.</p>
		<Field label="Your password">
			<PasswordInput bind:value={disablePassword} autocomplete="current-password" autofocus />
		</Field>
	</form>
	{#snippet footer()}
		<Button variant="secondary" onclick={closeDisable}>Cancel</Button>
		<Button
			variant="danger"
			type="submit"
			form="disable-admin-form"
			disabled={!disablePassword || disabling}
		>
			{disabling ? 'Turning off…' : 'Turn off'}
		</Button>
	{/snippet}
</Modal>

<ImportResult bind:open={importResultOpen} result={importResult} />
