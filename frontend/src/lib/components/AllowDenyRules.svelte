<script>
	// The rule fields of one allow or deny list: the list kind, CIDRs, country
	// codes, ASNs, JA4 fingerprints and header match rules. list is an object with
	// allowed, cidrs, countryCodes, asns, ja4 and headerRules, edited in place.
	import Button from '$lib/components/Button.svelte';

	let { list = $bindable() } = $props();
</script>

<div class="flex gap-4 text-sm">
	<label class="flex items-center gap-1.5"><input type="radio" bind:group={list.allowed} value={true} /> Allow list</label>
	<label class="flex items-center gap-1.5"><input type="radio" bind:group={list.allowed} value={false} /> Deny list</label>
</div>
<div class="grid gap-3 sm:grid-cols-2">
	<label class="block text-sm">
		<span class="pc-label">CIDRs</span> <span class="text-gray-700 dark:text-gray-200 text-xs font-normal">(one per line)</span>
		<textarea bind:value={list.cidrs} rows="3" placeholder={'10.0.0.0/8\n192.168.0.0/16'} class="mt-1 pc-control font-mono text-xs"></textarea>
	</label>
	<label class="block text-sm">
		<span class="pc-label">Country codes</span> <span class="text-gray-700 dark:text-gray-200 text-xs font-normal">(one per line)</span> <span class="pc-optional">optional</span>
		<textarea bind:value={list.countryCodes} rows="3" placeholder={'US\nGB'} class="mt-1 pc-control font-mono text-xs"></textarea>
	</label>
	<label class="block text-sm">
		<span class="pc-label">ASNs</span> <span class="text-gray-700 dark:text-gray-200 text-xs font-normal">(one per line)</span> <span class="pc-optional">optional</span>
		<textarea bind:value={list.asns} rows="2" placeholder={'AS13335\nAS15169'} class="mt-1 pc-control font-mono text-xs"></textarea>
	</label>
	<label class="block text-sm sm:col-span-2">
		<span class="pc-label">JA4 fingerprints</span> <span class="text-gray-700 dark:text-gray-200 text-xs font-normal">(one per line)</span> <span class="pc-optional">optional</span>
		<textarea bind:value={list.ja4} rows="2" placeholder={'t13d1516h2_8daaf6152771_b186095e22b6'} class="mt-1 pc-control font-mono text-xs"></textarea>
	</label>
</div>
<div>
	<div class="flex items-center justify-between">
		<span class="flex items-center gap-2"><span class="pc-label">Header matches</span> <span class="pc-optional">optional</span></span>
		<Button variant="blue" size="xs" onclick={() => (list.headerRules = [...list.headerRules, { keyRegex: '', valueRegex: '' }])}>+ Add header rule</Button>
	</div>
	<p class="pc-hint">Each rule is a header name regex and a value regex (both matched against the request).</p>
	{#each list.headerRules as rule, ri (ri)}
		<div class="mt-2 flex flex-wrap items-center gap-2">
			<input bind:value={rule.keyRegex} placeholder="^X-Forwarded-For$" class="pc-control flex-1 min-w-[10rem] font-mono text-xs" />
			<input bind:value={rule.valueRegex} placeholder="1\.2\.3\.4" class="pc-control flex-1 min-w-[10rem] font-mono text-xs" />
			<Button variant="danger" size="xs" onclick={() => (list.headerRules = list.headerRules.filter((_, i) => i !== ri))}>Remove</Button>
		</div>
	{/each}
</div>
