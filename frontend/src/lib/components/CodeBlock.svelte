<script>
	// a read only code or command block with a copy button in the corner, for
	// things an operator copies to use elsewhere (CLI commands, generated
	// data.yaml). matches the copy affordance on tokens and the registry url.
	import { toast } from '$lib/stores/toast.svelte.js';

	let { code = '', class: extra = '' } = $props();
	let copied = $state(false);
	let timer;

	async function copy() {
		try {
			await navigator.clipboard.writeText(code);
			copied = true;
			clearTimeout(timer);
			timer = setTimeout(() => (copied = false), 1500);
		} catch (_) {
			toast('Copy failed; select it manually', 'error');
		}
	}
</script>

<div class="relative">
	<pre class="overflow-x-auto rounded bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-800 p-3 pr-16 text-xs {extra}">{code}</pre>
	<button
		type="button"
		onclick={copy}
		class="absolute right-2 top-2 rounded border border-gray-300 dark:border-gray-700 bg-white dark:bg-gray-950 px-2 py-1 text-xs font-medium text-gray-800 dark:text-gray-100 hover:bg-gray-100 dark:hover:bg-gray-800"
	>
		{copied ? 'Copied' : 'Copy'}
	</button>
</div>
