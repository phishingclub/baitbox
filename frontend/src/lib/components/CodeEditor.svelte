<script module>
	// disposing an editor rejects any pending monaco Delayer (the word highlighter runs
	// one on every cursor move) with a CancellationError that monaco itself never
	// catches. that rejection is expected cleanup, so it is dropped here. only monaco
	// cancellation is matched (an Error whose name and message are both "Canceled", the
	// same test as monaco isCancellationError); every other unhandled rejection still
	// reaches the console.
	function isCancellationError(err) {
		return err instanceof Error && err.name === 'Canceled' && err.message === 'Canceled';
	}

	let cancelGuard = false;
	function installCancelGuard() {
		if (cancelGuard || typeof window === 'undefined') return;
		cancelGuard = true;
		window.addEventListener('unhandledrejection', (e) => {
			if (isCancellationError(e.reason)) e.preventDefault();
		});
	}
</script>

<script>
	import { onMount, tick } from 'svelte';
	import * as monaco from 'monaco-editor';
	import editorWorker from 'monaco-editor/esm/vs/editor/editor.worker?worker';
	import htmlWorker from 'monaco-editor/esm/vs/language/html/html.worker?worker';
	import tsWorker from 'monaco-editor/esm/vs/language/typescript/ts.worker?worker';
	import * as vimModule from 'monaco-vim';
	import { registerTemplateCompletions } from '$lib/editor/templateCompletions.js';
	import { setupProxyYamlCompletion } from '$lib/editor/proxyYamlCompletion.js';
	import { scriptDTS } from '$lib/editor/scriptDTS.js';
	import { remoteBrowserDTS } from '$lib/editor/remoteBrowserDTS.js';
	import { vimPref } from '$lib/stores/vim.svelte.js';

	// set chrome false when a parent (the editor workbench) owns the toolbar. vim is
	// bindable so either toolbar can drive it.
	let {
		value = $bindable(''),
		placeholder = '',
		lang = 'html',
		type = '',
		readonly = false,
		fill = false,
		chrome = true,
		vim = $bindable(undefined),
		api = $bindable(null)
	} = $props();

	let el;
	let statusBar;
	let editor = null;
	let vimInstance = null;
	let setting = false;
	let fullscreen = $state(false);

	// one worker environment for the whole app; set before the first editor is made
	let envSet = false;
	function ensureEnv() {
		if (envSet) return;
		envSet = true;
		self.MonacoEnvironment = {
			getWorker(_, label) {
				if (label === 'html') return new htmlWorker();
				if (label === 'typescript' || label === 'javascript') return new tsWorker();
				return new editorWorker();
			}
		};
		// campaign and browser scripts reference globals injected at runtime (rb, page,
		// emitEvent), so TypeScript validation would flag false errors; keep JS as a
		// plain highlighted editor with no squiggles.
		monaco.languages.typescript.javascriptDefaults.setDiagnosticsOptions({
			noSemanticValidation: true,
			noSyntaxValidation: true
		});
		// the typescript worker must hold the current model to offer member completion
		// (page., event.); without eager sync the suggest list comes back empty.
		monaco.languages.typescript.javascriptDefaults.setEagerModelSync(true);
		monaco.languages.typescript.javascriptDefaults.setCompilerOptions({
			allowNonTsExtensions: true,
			allowJs: true,
			target: monaco.languages.typescript.ScriptTarget.ES2020,
			lib: ['es2020']
		});
	}

	function monacoLang(name) {
		if (name === 'javascript') return 'javascript';
		if (name === 'yaml') return 'yaml';
		if (name === 'html') return 'html';
		return 'plaintext';
	}

	onMount(() => {
		installCancelGuard();
		ensureEnv();
		if (vim === undefined) vim = !readonly && vimPref.enabled;
		editor = monaco.editor.create(el, {
			value,
			language: monacoLang(lang),
			theme: 'vs-dark',
			readOnly: readonly,
			automaticLayout: true,
			minimap: { enabled: false },
			fontSize: 13,
			lineNumbers: 'on',
			folding: true,
			wordWrap: 'on',
			scrollBeyondLastLine: false,
			contextmenu: true,
			tabSize: 2,
			scrollbar: { horizontal: 'hidden' }
		});
		const model = editor.getModel();
		const contentSub = model.onDidChangeContent(() => {
			if (setting) return;
			value = editor.getValue();
		});
		if (vim && !readonly) enableVim();
		registerCompletions();
		// expose the instance on the host node so a test can drive it (trigger suggest,
		// read the model). harmless in production; nothing reads it there.
		try {
			el.__bsEditor = editor;
		} catch (_) {
			/* ignore */
		}
		// lets toolbars (the variable inserter) insert at the cursor
		api = {
			insert(text) {
				if (!editor) return;
				const sel = editor.getSelection();
				editor.executeEdits('insert', [{ range: sel, text, forceMoveMarkers: true }]);
				editor.focus();
			}
		};
		// teardown order: listeners and vim first, then the editor (which releases its
		// contributions), then the model it was built on, then the completion providers.
		return () => {
			api = null;
			contentSub.dispose();
			disableVim();
			const ed = editor;
			editor = null;
			ed?.dispose();
			if (!model.isDisposed()) model.dispose();
			disposeCompletions();
		};
	});

	// language and type aware autocomplete, ported from phishingclub. html editors get the
	// send time template variables for the package type; the proxy yaml editor gets the
	// schema completion and hover; the script and remote browser js editors get their API
	// declarations so dot completion shows the real globals.
	let completions = [];
	function registerCompletions() {
		if (lang === 'html') {
			completions.push(registerTemplateCompletions(monaco, type));
		} else if (lang === 'yaml' && type === 'proxy') {
			completions.push(setupProxyYamlCompletion(monaco));
		} else if (lang === 'javascript') {
			const dts = type === 'remotebrowser' ? remoteBrowserDTS : type === 'script' ? scriptDTS : '';
			if (dts) {
				const uri = `ts:bs-${type}.d.ts`;
				completions.push(monaco.languages.typescript.javascriptDefaults.addExtraLib(dts, uri));
			}
		}
	}
	function disposeCompletions() {
		for (const d of completions) {
			try {
				d?.dispose?.();
			} catch (_) {
				/* ignore */
			}
		}
		completions = [];
	}

	function enableVim() {
		if (!editor || vimInstance || readonly) return;
		try {
			vimInstance = vimModule.initVimMode(editor, statusBar);
		} catch (e) {
			console.error('vim mode not available', e);
		}
	}
	function disableVim() {
		if (vimInstance) {
			try {
				vimInstance.dispose();
			} catch (_) {
				/* ignore */
			}
			vimInstance = null;
		}
	}

	function toggleFullscreen() {
		fullscreen = !fullscreen;
	}

	// follow the shared preference so a toggle anywhere (a toolbar button or the
	// global Ctrl+Alt+V) switches every open editor at once.
	$effect(() => {
		if (!readonly) vim = vimPref.enabled;
	});

	// apply vim changes from the shared preference (the initial state is set in onMount)
	$effect(() => {
		const want = !!vim && !readonly;
		if (!editor) return;
		if (want && !vimInstance) {
			tick().then(enableVim);
		} else if (!want && vimInstance) {
			disableVim();
		}
	});

	// Escape leaves fullscreen (but not while vim is on, where Escape is a vim key).
	$effect(() => {
		if (!fullscreen) return;
		const onKey = (e) => {
			if (e.key === 'Escape' && !vim) fullscreen = false;
		};
		window.addEventListener('keydown', onKey);
		return () => window.removeEventListener('keydown', onKey);
	});

	// reflect external value changes (loading an existing version) into the editor
	$effect(() => {
		const v = value;
		if (editor && v !== editor.getValue()) {
			setting = true;
			editor.setValue(v ?? '');
			setting = false;
		}
	});
</script>

<div
	class={fullscreen
		? 'fixed inset-0 z-50 flex flex-col bg-gray-950 p-3'
		: fill
			? 'flex h-full min-h-0 flex-col'
			: ''}
>
	{#if chrome}
		<div class="mb-1 flex items-center justify-end gap-2 text-xs">
			{#if !readonly}
				<button
					type="button"
					aria-pressed={!!vim}
					onclick={() => vimPref.toggle()}
					title="Toggle vim keybindings (Ctrl+Alt+V)"
					class="rounded border px-2 py-0.5 font-medium transition-colors {vim
						? 'border-cta-blue bg-cta-blue text-white'
						: 'border-gray-300 text-gray-800 hover:bg-gray-100 dark:border-gray-700 dark:text-gray-100 dark:hover:bg-gray-800'}"
					>Vim</button
				>
			{/if}
			<button
				type="button"
				aria-pressed={fullscreen}
				onclick={toggleFullscreen}
				title={fullscreen ? 'Exit fullscreen (Esc)' : 'Fullscreen'}
				class="rounded border border-gray-300 px-2 py-0.5 font-medium text-gray-800 hover:bg-gray-100 dark:border-gray-700 dark:text-gray-100 dark:hover:bg-gray-800"
				>{fullscreen ? 'Exit fullscreen' : 'Fullscreen'}</button
			>
		</div>
	{/if}
	<div class="relative flex min-h-0 flex-col {fullscreen || fill ? 'flex-1' : ''}">
		<div
			bind:this={el}
			class="monaco-host overflow-hidden rounded-md border border-gray-300 dark:border-gray-700 {fullscreen || fill
				? 'min-h-0 flex-1'
				: ''}"
			style={fullscreen || fill ? '' : 'height: 30rem'}
		></div>
		<div
			bind:this={statusBar}
			class="{vim && !readonly
				? ''
				: 'hidden'} h-5 bg-gray-800 px-2 font-mono text-[0.7rem] leading-5 text-gray-300"
		></div>
	</div>
	{#if placeholder && !value}
		<p class="mt-1 text-xs text-gray-700 dark:text-gray-400">{placeholder}</p>
	{/if}
</div>

<style>
	/* the faint active line overlay, matching the phishingclub editor */
	:global(.monaco-host .monaco-editor .current-line) {
		background-color: rgba(255, 255, 255, 0.05) !important;
	}
	:global(.monaco-host .monaco-editor) {
		height: 100%;
	}
</style>
