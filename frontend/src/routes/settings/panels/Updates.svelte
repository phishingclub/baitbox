<script>
	import { onMount, onDestroy } from 'svelte';
	import { api } from '$lib/api/api.js';
	import Alert from '$lib/components/Alert.svelte';
	import Button from '$lib/components/Button.svelte';
	import Card from '$lib/components/Card.svelte';
	import CodeBlock from '$lib/components/CodeBlock.svelte';
	import Help from '$lib/components/Help.svelte';
	import StatusPill from '$lib/components/StatusPill.svelte';
	import { toast } from '$lib/stores/toast.svelte.js';
	import { askConfirm } from '$lib/stores/confirm.svelte.js';
	import { setUpdateStatus } from '$lib/stores/update.svelte.js';

	// how often to ask the server if it is back after an update, and when to stop.
	const POLL_MS = 2000;
	const GIVE_UP_MS = 2 * 60 * 1000;

	let status = $state(null);
	let loading = $state(true);
	let loadError = $state('');
	let checking = $state(false);
	let running = $state(false);
	// idle, restarting (waiting for the new binary) or timeout (gave up waiting)
	let phase = $state('idle');
	let targetVersion = $state('');
	let pollTimer = null;
	// set when the panel is gone, so a tick still in flight stops there
	let destroyed = false;
	let now = $state(Date.now());
	let clock = null;

	const noRelease = $derived(!!status && !status.latestVersion && !status.error);

	// the one word status next to the title. none until a release is known.
	const summary = $derived.by(() => {
		if (!status) return { tone: 'neutral', label: '' };
		if (status.updateAvailable) return { tone: 'info', label: 'Outdated' };
		if (!status.latestVersion) return { tone: 'neutral', label: '' };
		return { tone: 'on', label: 'Latest' };
	});

	function relative(iso, nowMs) {
		if (!iso) return 'Never';
		const t = new Date(iso).getTime();
		if (Number.isNaN(t)) return 'Never';
		const sec = Math.max(0, Math.round((nowMs - t) / 1000));
		if (sec < 45) return 'Just now';
		const min = Math.round(sec / 60);
		if (min < 60) return `${min} minute${min === 1 ? '' : 's'} ago`;
		const hr = Math.round(min / 60);
		if (hr < 24) return `${hr} hour${hr === 1 ? '' : 's'} ago`;
		const day = Math.round(hr / 24);
		return `${day} day${day === 1 ? '' : 's'} ago`;
	}

	// the release tag is "v1.2.3" while the running binary reports "1.2.3"
	function bare(v) {
		return String(v || '').trim().replace(/^v/i, '');
	}

	function localTime(iso) {
		if (!iso) return '';
		const d = new Date(iso);
		return Number.isNaN(d.getTime()) ? '' : d.toLocaleString();
	}

	function apply(data) {
		status = data;
		setUpdateStatus(data);
	}

	async function load() {
		loading = true;
		const res = await api.update.status();
		loading = false;
		if (res.ok && res.data) {
			apply(res.data);
			loadError = '';
		} else {
			loadError = res.error || 'Could not load the update status';
		}
	}

	async function checkNow() {
		if (checking) return;
		checking = true;
		const res = await api.update.check();
		checking = false;
		if (!res.ok || !res.data) {
			toast(res.error || 'Could not check for updates', 'error');
			return;
		}
		apply(res.data);
		loadError = '';
		if (res.data.error) return; // shown in the warning below
		// the card shows the result and the new "last checked" time, so only an
		// up to date result gets a toast as confirmation.
		if (!res.data.updateAvailable && res.data.latestVersion) toast('Bait Box is up to date', 'success');
	}

	async function runUpdate() {
		if (running || !status?.updateAvailable || !status?.updateInApp) return;
		const ok = await askConfirm({
			title: 'Update Bait Box',
			body: `Install version ${status.latestVersion} now? The service restarts to load it, so the admin and the registry are unavailable for a short moment. This page reloads when it is back.`,
			confirmLabel: 'Update now'
		});
		if (!ok) return;
		running = true;
		const res = await api.update.run();
		if (!res.ok) {
			running = false;
			if (res.status === 409) toast('An update is already running', 'error');
			else toast(res.error || 'The update failed. The current version keeps running.', 'error');
			load();
			return;
		}
		targetVersion = res.data?.version || status.latestVersion;
		startWaiting();
	}

	// ask the server for its version every few seconds until it answers with the
	// new one. a plain fetch is used here so the outage does not raise the
	// connection error toast on every try.
	function startWaiting() {
		phase = 'restarting';
		const startedAt = Date.now();
		const oldVersion = status?.currentVersion;
		const tick = async () => {
			if (destroyed) return;
			if (Date.now() - startedAt > GIVE_UP_MS) {
				phase = 'timeout';
				running = false;
				return;
			}
			try {
				const r = await fetch('/api/v1/admin/update', { credentials: 'same-origin' });
				if (destroyed) return;
				if (r.status === 401) {
					// the server is back but the session is gone: reload to sign in
					location.reload();
					return;
				}
				if (r.ok) {
					const data = await r.json();
					if (destroyed) return;
					const back = targetVersion
						? bare(data.currentVersion) === bare(targetVersion)
						: bare(data.currentVersion) !== bare(oldVersion);
					if (back) {
						toast(`Updated to version ${data.currentVersion}`, 'success');
						setTimeout(() => {
							if (!destroyed) location.reload();
						}, 800);
						return;
					}
				}
			} catch (_) {
				/* still restarting */
			}
			if (destroyed) return;
			pollTimer = setTimeout(tick, POLL_MS);
		};
		// give the old process a moment to exit before the first try
		pollTimer = setTimeout(tick, POLL_MS);
	}

	function retryWaiting() {
		running = true;
		startWaiting();
	}

	onMount(() => {
		load();
		clock = setInterval(() => (now = Date.now()), 30000);
	});
	onDestroy(() => {
		destroyed = true;
		clearTimeout(pollTimer);
		clearInterval(clock);
	});
</script>

{#if phase === 'restarting'}
	<Alert variant="info" title="Restarting.">
		Installing version <span class="font-mono">{targetVersion}</span> and restarting the service. The
		admin is unavailable for a short moment; this page reloads when it is back.
	</Alert>
{:else if phase === 'timeout'}
	<Alert variant="danger" title="No answer after 2 minutes.">
		The server did not come back with version <span class="font-mono">{targetVersion}</span>. Check the
		service on the server, for example with <span class="font-mono">systemctl status baitbox</span> and
		<span class="font-mono">journalctl -u baitbox</span>.
		<div class="mt-2"><Button variant="secondary" size="xs" onclick={retryWaiting}>Keep waiting</Button></div>
	</Alert>
{/if}

{#if status?.error}
	<Alert variant="warning" title="Update check failed:" class={phase !== 'idle' ? 'mt-4' : ''}>{status.error}</Alert>
{/if}

<div class="grid items-start gap-6 lg:grid-cols-2 {phase !== 'idle' || status?.error ? 'mt-6' : ''}">
	<Card padding="lg">
		<div class="flex flex-wrap items-center gap-x-3 gap-y-1">
			<h3 class="pc-card-title">Software update</h3>
			<Help title="Software update">
				<p>Bait Box checks GitHub for a new release a minute after it starts and then every 6 hours. Use <strong>Check now</strong> to ask right away.</p>
				<p>Releases are signed. When Bait Box runs as the systemd service, <strong>Update now</strong> installs the release and restarts the service. Otherwise run the update command on the server.</p>
			</Help>
			{#if summary.label}<span class="ml-auto"><StatusPill tone={summary.tone}>{summary.label}</StatusPill></span>{/if}
		</div>
		<p class="mt-1 pc-desc">The version this server runs and the newest published release.</p>

		{#if loading && !status}
			<div class="mt-4 space-y-3" aria-hidden="true">
				{#each [0, 1, 2] as i (i)}
					<div class="h-4 w-2/3 animate-pulse rounded bg-gray-200 dark:bg-gray-800"></div>
				{/each}
			</div>
		{:else if loadError && !status}
			<div class="mt-4"><Alert variant="danger">{loadError}</Alert></div>
			<div class="mt-4"><Button variant="secondary" onclick={load}>Try again</Button></div>
		{:else if status}
			<dl class="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-3">
				<div class="pc-inset px-3 py-2">
					<dt class="text-xs font-medium pc-muted">Current version</dt>
					<dd class="mt-0.5 truncate font-mono text-sm font-semibold text-gray-900 dark:text-white">{status.currentVersion || 'Unknown'}</dd>
				</div>
				<div class="pc-inset px-3 py-2">
					<dt class="text-xs font-medium pc-muted">Latest version</dt>
					<dd class="mt-0.5 truncate font-mono text-sm font-semibold text-gray-900 dark:text-white">{status.latestVersion || 'None yet'}</dd>
				</div>
				<div class="pc-inset px-3 py-2">
					<dt class="text-xs font-medium pc-muted">Last checked</dt>
					<dd class="mt-0.5 truncate text-sm font-semibold text-gray-900 dark:text-white" title={localTime(status.checkedAt)}>{relative(status.checkedAt, now)}</dd>
				</div>
			</dl>

			<div class="mt-4 pc-desc">
				{#if status.updateAvailable}
					Version <span class="font-mono font-semibold">{status.latestVersion}</span> is available. You run
					<span class="font-mono font-semibold">{status.currentVersion}</span>.
				{:else if noRelease}
					No release has been published yet. Bait Box shows a notice here when one is.
				{:else if status.latestVersion}
					You run the latest release.
				{:else}
					The latest release is not known yet. Check now to ask GitHub.
				{/if}
			</div>

			<div class="mt-4 flex flex-wrap items-center gap-3">
				{#if status.updateAvailable && status.updateInApp}
					<Button variant="primary" disabled={running || phase !== 'idle'} onclick={runUpdate}>
						{running ? 'Updating...' : 'Update now'}
					</Button>
				{/if}
				<Button variant="secondary" disabled={checking || running} onclick={checkNow}>
					{checking ? 'Checking...' : 'Check now'}
				</Button>
			</div>
		{/if}
	</Card>

	{#if status?.updateAvailable && !status.updateInApp}
		<Card padding="lg">
			<h3 class="pc-card-title">Update on the server</h3>
			<p class="mt-1 pc-desc">
				This server cannot update itself from the app because Bait Box is not running as the systemd
				service. Run this command on the server to install version
				<span class="font-mono font-semibold">{status.latestVersion}</span>.
			</p>
			{#if status.manualCommand}
				<div class="mt-4"><CodeBlock code={status.manualCommand} /></div>
			{/if}
		</Card>
	{/if}
</div>
