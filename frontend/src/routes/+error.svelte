<script>
	// a branded error page shown for a bad route or an unexpected load error. it renders
	// inside the layout, so the sidebar stays and the operator can navigate away or return
	// to the dashboard rather than hitting a bare SvelteKit default page.
	import { page } from '$app/stores';
	import Button from '$lib/components/Button.svelte';
	import Card from '$lib/components/Card.svelte';
	const status = $derived($page.status);
	const message = $derived($page.error?.message || 'Something went wrong.');
</script>

<svelte:head><title>{status} · Bait Box</title></svelte:head>

<div class="flex min-h-[60vh] items-center justify-center p-6">
	<Card padding="xl" class="w-full max-w-md text-center shadow-sm">
		<div class="font-phudu text-5xl font-bold text-cta-blue dark:text-highlight-blue">{status}</div>
		<p class="mt-3 text-sm text-gray-800 dark:text-gray-100">
			{#if status === 404}
				That page does not exist.
			{:else}
				{message}
			{/if}
		</p>
		<Button
			href="/"
			variant="primary"
			class="mt-6 inline-block"
			>Back to dashboard</Button
		>
	</Card>
</div>
