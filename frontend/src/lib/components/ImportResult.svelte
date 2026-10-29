<script>
	// The result of a registry or package bundle import, shown when the import did
	// more than add rows: it lists the packages a newer bundle upgraded, the ones it
	// skipped because nothing newer came in, and the ones it refused, with the
	// reason for each refusal. result is the import response from the server.
	import Modal from '$lib/components/Modal.svelte';
	import Alert from '$lib/components/Alert.svelte';
	import Button from '$lib/components/Button.svelte';
	import { importSummary } from '$lib/utils/importSummary.js';

	let { open = $bindable(false), result = null } = $props();

	const refused = $derived(result?.refused || []);
	const warnings = $derived(result?.warnings || []);
	const upgraded = $derived(result?.upgraded || []);
	const skipped = $derived(result?.skipped || []);
</script>

<Modal bind:open title="Import result" size="lg">
	<div class="space-y-4 text-sm">
		<p class="text-gray-700 dark:text-gray-200">{importSummary(result)}</p>
		{#if refused.length || warnings.length}
			<Alert
				variant="warning"
				title={refused.length ? `${refused.length} package${refused.length === 1 ? '' : 's'} not imported.` : 'Imported with warnings.'}
			>
				<ul class="mt-1 list-disc space-y-1 pl-5">
					{#each warnings as w}<li class="break-words">{w}</li>{/each}
				</ul>
			</Alert>
		{/if}
		{#if upgraded.length}
			<div>
				<h3 class="font-semibold text-gray-900 dark:text-white">Upgraded</h3>
				<p class="text-gray-500 dark:text-gray-400">Existing packages the bundle carried a newer version for.</p>
				<ul class="mt-1 list-disc pl-5 font-mono text-xs text-gray-700 dark:text-gray-200">
					{#each upgraded as p}<li class="break-all">{p}</li>{/each}
				</ul>
			</div>
		{/if}
		{#if skipped.length}
			<div>
				<h3 class="font-semibold text-gray-900 dark:text-white">Skipped</h3>
				<p class="text-gray-500 dark:text-gray-400">Existing packages left as they are, since the bundle had nothing newer.</p>
				<ul class="mt-1 list-disc pl-5 font-mono text-xs text-gray-700 dark:text-gray-200">
					{#each skipped as p}<li class="break-all">{p}</li>{/each}
				</ul>
			</div>
		{/if}
	</div>
	{#snippet footer()}
		<Button variant="primary" onclick={() => (open = false)}>Close</Button>
	{/snippet}
</Modal>
