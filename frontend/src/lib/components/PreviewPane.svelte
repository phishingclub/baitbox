<script>
	let { srcdoc = undefined, label = 'Live preview' } = $props();
	let fullscreen = $state(false);
	let dev = $state('desktop');

	// srcdoc html is posted to the server preview endpoint, which echoes it back as an
	// opaque origin sandboxed document: its scripts run but cannot read the admin
	// session or reach the admin app. A unique name lets the form target this iframe.
	const frameName = 'bs-preview-' + Math.random().toString(36).slice(2);
	let formEl, htmlField;

	// true when there is nothing meaningful to show, so we render a muted placeholder
	// instead of acres of blank white.
	let isEmpty = $derived(!srcdoc || srcdoc.replace(/<[^>]*>/g, '').replace(/\s+/g, '') === '');

	// repost the html when it changes, debounced, so typing updates the preview.
	let debounce;
	$effect(() => {
		const html = srcdoc;
		if (!formEl || !htmlField || isEmpty) return;
		clearTimeout(debounce);
		debounce = setTimeout(() => {
			htmlField.value = html ?? '';
			formEl.submit();
		}, 200);
		return () => clearTimeout(debounce);
	});

	function toggleFullscreen() {
		fullscreen = !fullscreen;
	}

	// open the rendered preview in a separate browser window (a second monitor, say)
	function openNewWindow() {
		// open a window, sever its opener, then build and submit the preview form inside
		// it. Severing opener stops the opaque preview from navigating the admin tab
		// (reverse tabnabbing) without relying on the browser default for target=_blank.
		const w = window.open('about:blank', '_blank');
		if (!w) return;
		try {
			w.opener = null;
		} catch (_e) {
			/* ignore */
		}
		const d = w.document;
		d.open();
		d.write('<!doctype html><title>Preview</title><body></body>');
		d.close();
		const form = d.createElement('form');
		form.method = 'POST';
		form.action = '/preview';
		form.enctype = 'multipart/form-data';
		const ta = d.createElement('textarea');
		ta.name = 'html';
		ta.value = srcdoc ?? '';
		form.appendChild(ta);
		d.body.appendChild(form);
		form.submit();
	}
	$effect(() => {
		if (!fullscreen) return;
		const onKey = (e) => {
			if (e.key === 'Escape') fullscreen = false;
		};
		window.addEventListener('keydown', onKey);
		return () => window.removeEventListener('keydown', onKey);
	});
</script>

<div class={fullscreen ? 'fixed inset-0 z-50 flex flex-col bg-white p-3 dark:bg-gray-950' : 'flex h-full min-h-0 flex-col'}>
	<div class="mb-2 flex items-center justify-between gap-2 text-sm text-gray-700 dark:text-gray-200">
		<span class="font-medium">{label}</span>
		<div class="flex items-center gap-2">
			<div class="inline-flex overflow-hidden rounded-md border border-gray-300 dark:border-gray-700">
				<button
					type="button"
					aria-pressed={dev === 'desktop'}
					onclick={() => (dev = 'desktop')}
					class="px-3 py-1.5 {dev === 'desktop' ? 'bg-cta-blue text-white' : 'text-gray-800 hover:bg-gray-50 dark:text-gray-100 dark:hover:bg-gray-900'}">Desktop</button>
				<button
					type="button"
					aria-pressed={dev === 'mobile'}
					onclick={() => (dev = 'mobile')}
					class="border-l border-gray-300 px-3 py-1.5 dark:border-gray-700 {dev === 'mobile' ? 'bg-cta-blue text-white' : 'text-gray-800 hover:bg-gray-50 dark:text-gray-100 dark:hover:bg-gray-900'}">Mobile</button>
			</div>
			<button
				type="button"
				onclick={openNewWindow}
				title="Open preview in a new window"
				class="rounded border border-gray-300 px-3 py-1.5 font-medium text-gray-800 hover:bg-gray-100 dark:border-gray-700 dark:text-gray-100 dark:hover:bg-gray-800"
			>New window</button>
			<button
				type="button"
				aria-pressed={fullscreen}
				onclick={toggleFullscreen}
				title={fullscreen ? 'Exit fullscreen (Esc)' : 'Fullscreen'}
				class="rounded border border-gray-300 px-3 py-1.5 font-medium text-gray-800 hover:bg-gray-100 dark:border-gray-700 dark:text-gray-100 dark:hover:bg-gray-800"
			>{fullscreen ? 'Exit fullscreen' : 'Fullscreen'}</button>
		</div>
	</div>
	<div
		class="relative {fullscreen ? 'min-h-0 flex-1' : 'flex-1'}"
		style={fullscreen ? '' : 'min-height: 22rem'}
	>
		<!-- the html is posted to the preview endpoint and rendered in an opaque origin (no
		     allow-same-origin) so its scripts run without touching the admin app. No
		     allow-modals, so a package alert, confirm or print cannot open a dialog over
		     the admin tab. The server response carries the same sandbox CSP as a second
		     layer. -->
		<iframe
			title={label}
			name={frameName}
			sandbox="allow-scripts allow-forms allow-popups"
			class="h-full rounded border border-gray-200 bg-white dark:border-gray-800 {dev === 'mobile' ? 'mx-auto w-[375px] max-w-full' : 'w-full'}"
		></iframe>
		<form bind:this={formEl} method="POST" action="/preview" target={frameName} enctype="multipart/form-data" class="hidden">
			<textarea bind:this={htmlField} name="html"></textarea>
		</form>
		{#if isEmpty}
			<div
				class="pointer-events-none absolute inset-0 flex items-center justify-center rounded text-sm text-gray-700 dark:text-gray-200"
			>
				Preview renders here as you edit
			</div>
		{/if}
	</div>
</div>
