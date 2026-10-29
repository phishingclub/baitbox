<script>
	import { onMount } from 'svelte';
	import TextField from '$lib/components/TextField.svelte';
	import TextFieldSelect from '$lib/components/TextFieldSelect.svelte';
	import TextareaField from '$lib/components/TextareaField.svelte';
	import Search from '$lib/components/Search.svelte';
	import FileField from '$lib/components/FileField.svelte';
	import ProxyRuleEditors from '$lib/components/proxy/ProxyRuleEditors.svelte';
	import jsyaml, { dumpWithLiteralStrings } from '$lib/components/yaml/index.js';

	let {
		config = null,
		// basic info fields passed from parent
		name = '',
		description = '',
		startURL = '',
		// callbacks fired as the parent needs to react to edits
		onChange = undefined,
		onNameChange = undefined,
		onDescriptionChange = undefined,
		onStartURLChange = undefined,
		onCertChange = undefined
	} = $props();

	let initialized = $state(false);
	// track if we should skip the next reactive dispatch (used during mount)
	let skipNextDispatch = false;

	let configData = $state({
		version: '0.0',
		proxy: '',
		script: '',
		global: {
			tls: { mode: 'managed' },
			access: { mode: 'private', on_deny: '' },
			impersonate: { enabled: false, retain_ua: false },
			variables: { enabled: false, allowed: [] },
			capture: [],
			rewrite: [],
			response: [],
			rewrite_urls: []
		},
		hosts: []
	});

	// valid proxy template variables that can be used in rewrite rules
	const validProxyVariables = [
		// recipient fields
		'rID',
		'FirstName',
		'LastName',
		'Email',
		'To',
		'Phone',
		'ExtraIdentifier',
		'Position',
		'Department',
		'City',
		'Country',
		'Misc',
		// sender fields
		'From',
		'FromName',
		'FromEmail',
		'Subject',
		// general fields
		'BaseURL',
		'URL',
		// custom fields
		'CustomField1',
		'CustomField2',
		'CustomField3',
		'CustomField4'
	];

	let activeTab = $state('basic');

	// expanded host index (-1 = none)
	let expandedHostIndex = $state(-1);

	let hostSearchQuery = $state('');
	// the Search component expects a pagination object
	const hostSearchPagination = {
		_search: '',
		get search() {
			return this._search;
		},
		set search(val) {
			this._search = val;
			hostSearchQuery = val || '';
		},
		onChange: (callback) => {
			// not needed for our use case
			return () => {};
		}
	};
	const filteredHosts = $derived(
		configData.hosts
			.map((host, index) => ({ host, index }))
			.filter(({ host }) => {
				if (!hostSearchQuery.trim()) return true;
				const query = hostSearchQuery.toLowerCase();
				return (
					(host.to || '').toLowerCase().includes(query) ||
					(host.domain || '').toLowerCase().includes(query)
				);
			})
	);

	let hostActiveTabs = $state({});
	const currentHostTab = $derived(hostActiveTabs[expandedHostIndex] || 'settings');

	// unique id counter for form elements and rule tracking
	let idCounter = 0;
	const getRuleId = () => `rule-${idCounter++}`;

	// parse config only on initial mount
	onMount(() => {
		// skip the reactive dispatch that will fire when initialized becomes true
		skipNextDispatch = true;
		if (config) {
			parseYamlConfig(config);
		}
		initialized = true;
	});

	// report the yaml to the parent whenever configData changes, but not for the
	// initial parse on mount
	$effect(() => {
		const yaml = generateYaml();
		if (!initialized) {
			return;
		}
		if (skipNextDispatch) {
			skipNextDispatch = false;
			return;
		}
		onChange?.(yaml);
	});

	function parseYamlConfig(yamlStr) {
		if (!yamlStr || yamlStr.trim() === '') {
			resetConfig();
			return;
		}

		try {
			const parsed = jsyaml.load(yamlStr);
			if (parsed && typeof parsed === 'object') {
				configData.version = String(parsed.version || '0.0');
				configData.proxy = parsed.proxy || '';
				configData.script = parsed.script || '';

				if (parsed.global) {
					configData.global.tls = parsed.global.tls || { mode: 'managed' };
					configData.global.access = parsed.global.access || { mode: 'private', on_deny: '' };
					configData.global.impersonate = parsed.global.impersonate || {
						enabled: false,
						retain_ua: false
					};
					configData.global.variables = parsed.global.variables || {
						enabled: false,
						allowed: []
					};
					configData.global.capture = (parsed.global.capture || []).map((r) => ({
						...r,
						event: r.event || 'submit',
						_id: getRuleId()
					}));
					configData.global.rewrite = (parsed.global.rewrite || []).map((r) => ({
						...r,
						_id: getRuleId()
					}));
					configData.global.response = (parsed.global.response || []).map((r) => ({
						...r,
						_id: getRuleId()
					}));
					configData.global.rewrite_urls = (parsed.global.rewrite_urls || []).map((r) => ({
						...r,
						_id: getRuleId()
					}));
				}

				// extract hosts (keys that contain '.' and have a 'to' property)
				const hosts = [];
				for (const key of Object.keys(parsed)) {
					if (
						key !== 'version' &&
						key !== 'proxy' &&
						key !== 'script' &&
						key !== 'global' &&
						parsed[key] &&
						typeof parsed[key] === 'object' &&
						parsed[key].to
					) {
						const hostData = parsed[key];
						hosts.push({
							domain: key,
							to: hostData.to || '',
							scheme: hostData.scheme || 'https',
							tls: { mode: hostData.tls?.mode || '' },
							access: {
								mode: hostData.access?.mode || '',
								on_deny: hostData.access?.on_deny || ''
							},
							capture: (hostData.capture || []).map((r) => ({
								...r,
								event: r.event || 'submit',
								_id: getRuleId()
							})),
							rewrite: (hostData.rewrite || []).map((r) => ({ ...r, _id: getRuleId() })),
							response: (hostData.response || []).map((r) => ({ ...r, _id: getRuleId() })),
							rewrite_urls: (hostData.rewrite_urls || []).map((r) => ({ ...r, _id: getRuleId() }))
						});
					}
				}
				configData.hosts = hosts;

				if (hosts.length > 0 && expandedHostIndex === -1) {
					expandedHostIndex = 0;
				}
			}
		} catch (e) {
			console.warn('Failed to parse YAML config:', e);
		}
	}

	function resetConfig() {
		configData = {
			version: '0.0',
			proxy: '',
			script: '',
			global: {
				tls: { mode: 'managed' },
				access: { mode: 'private', on_deny: '' },
				impersonate: { enabled: false, retain_ua: false },
				variables: { enabled: false, allowed: [] },
				capture: [],
				rewrite: [],
				response: [],
				rewrite_urls: []
			},
			hosts: []
		};
		expandedHostIndex = -1;
		globalTLSKey = '';
		globalTLSPem = '';
	}

	// helper to remove internal _id fields before serialization
	function stripIds(obj) {
		if (Array.isArray(obj)) {
			return obj.map(stripIds);
		}
		if (obj && typeof obj === 'object') {
			const result = {};
			for (const [key, value] of Object.entries(obj)) {
				if (key !== '_id') {
					result[key] = stripIds(value);
				}
			}
			return result;
		}
		return obj;
	}

	// helper to remove empty values from objects for cleaner YAML output
	function cleanObject(obj) {
		if (Array.isArray(obj)) {
			return obj.map(cleanObject);
		}
		if (obj && typeof obj === 'object') {
			const result = {};
			for (const [key, value] of Object.entries(obj)) {
				const cleaned = cleanObject(value);
				// skip empty strings, empty arrays, empty objects, null, undefined
				if (
					cleaned !== '' &&
					cleaned !== null &&
					cleaned !== undefined &&
					!(Array.isArray(cleaned) && cleaned.length === 0) &&
					!(
						typeof cleaned === 'object' &&
						!Array.isArray(cleaned) &&
						Object.keys(cleaned).length === 0
					)
				) {
					result[key] = cleaned;
				}
			}
			return result;
		}
		return obj;
	}

	function generateYaml() {
		const output = {};

		output.version = configData.version || '0.0';

		if (configData.proxy) {
			output.proxy = configData.proxy;
		}

		if (configData.script) {
			output.script = configData.script;
		}

		const global = {};
		if (configData.global.tls?.mode) {
			global.tls = { mode: configData.global.tls.mode };
		}
		if (configData.global.access?.mode) {
			global.access = { mode: configData.global.access.mode };
			if (configData.global.access.on_deny) {
				global.access.on_deny = configData.global.access.on_deny;
			}
		}
		if (configData.global.impersonate?.enabled) {
			global.impersonate = {
				enabled: configData.global.impersonate.enabled
			};
			if (configData.global.impersonate.retain_ua) {
				global.impersonate.retain_ua = configData.global.impersonate.retain_ua;
			}
		}
		if (configData.global.variables?.enabled) {
			global.variables = {
				enabled: configData.global.variables.enabled
			};
			if (configData.global.variables.allowed?.length > 0) {
				global.variables.allowed = configData.global.variables.allowed;
			}
		}
		// filter and add global rules (only include touched/valid rules)
		const globalCapture = (configData.global.capture || []).filter(isCaptureRuleTouched);
		if (globalCapture.length > 0) {
			global.capture = stripIds(globalCapture);
		}
		const globalRewrite = (configData.global.rewrite || []).filter(isRewriteRuleTouched);
		if (globalRewrite.length > 0) {
			global.rewrite = stripIds(globalRewrite);
		}
		const globalResponse = (configData.global.response || []).filter(isResponseRuleTouched);
		if (globalResponse.length > 0) {
			global.response = stripIds(globalResponse);
		}
		const globalRewriteUrls = (configData.global.rewrite_urls || []).filter(
			isUrlRewriteRuleTouched
		);
		if (globalRewriteUrls.length > 0) {
			global.rewrite_urls = stripIds(globalRewriteUrls);
		}

		if (Object.keys(global).length > 0) {
			output.global = global;
		}

		for (const host of configData.hosts) {
			if (!host.domain || !host.to) continue;

			const hostObj = { to: host.to };

			if (host.scheme && host.scheme !== 'https') {
				hostObj.scheme = host.scheme;
			}
			if (host.tls?.mode) {
				hostObj.tls = { mode: host.tls.mode };
			}
			if (host.access?.mode) {
				hostObj.access = { mode: host.access.mode };
				if (host.access.on_deny) {
					hostObj.access.on_deny = host.access.on_deny;
				}
			}
			// filter and add host rules (only include touched/valid rules)
			const hostCapture = (host.capture || []).filter(isCaptureRuleTouched);
			if (hostCapture.length > 0) {
				hostObj.capture = stripIds(hostCapture);
			}
			const hostRewrite = (host.rewrite || []).filter(isRewriteRuleTouched);
			if (hostRewrite.length > 0) {
				hostObj.rewrite = stripIds(hostRewrite);
			}
			const hostResponse = (host.response || []).filter(isResponseRuleTouched);
			if (hostResponse.length > 0) {
				hostObj.response = stripIds(hostResponse);
			}
			const hostRewriteUrls = (host.rewrite_urls || []).filter(isUrlRewriteRuleTouched);
			if (hostRewriteUrls.length > 0) {
				hostObj.rewrite_urls = stripIds(hostRewriteUrls);
			}

			output[host.domain] = cleanObject(hostObj);
		}

		// serialize to YAML with literal block style for replace/body fields
		return dumpWithLiteralStrings(output);
	}

	// host management
	function addHost() {
		configData.hosts = [
			...configData.hosts,
			{
				domain: '',
				to: '',
				scheme: 'https',
				tls: { mode: '' },
				access: { mode: '', on_deny: '' },
				capture: [],
				rewrite: [],
				response: [],
				rewrite_urls: []
			}
		];
		expandedHostIndex = configData.hosts.length - 1;
		hostActiveTabs[expandedHostIndex] = 'settings';
	}

	function removeHost(index) {
		configData.hosts = configData.hosts.filter((_, i) => i !== index);
		if (expandedHostIndex >= configData.hosts.length) {
			expandedHostIndex = configData.hosts.length - 1;
		}
		if (expandedHostIndex < 0 && configData.hosts.length > 0) {
			expandedHostIndex = 0;
		}
	}

	function duplicateHost(index) {
		const host = configData.hosts[index];
		const newHost = JSON.parse(JSON.stringify(host));
		// assign new IDs to all rules in the duplicated host
		if (newHost.capture) newHost.capture = newHost.capture.map((r) => ({ ...r, _id: getRuleId() }));
		if (newHost.rewrite) newHost.rewrite = newHost.rewrite.map((r) => ({ ...r, _id: getRuleId() }));
		if (newHost.response)
			newHost.response = newHost.response.map((r) => ({ ...r, _id: getRuleId() }));
		if (newHost.rewrite_urls)
			newHost.rewrite_urls = newHost.rewrite_urls.map((r) => ({ ...r, _id: getRuleId() }));
		configData.hosts = [...configData.hosts, newHost];
		expandedHostIndex = configData.hosts.length - 1;
	}

	// options
	const tlsModes = [
		{ value: 'managed', label: 'Managed' },
		{ value: 'self-signed', label: 'Self signed' },
		{ value: 'custom', label: 'Custom' }
	];
	const tlsModesWithEmpty = [
		{ value: '', label: '(Use global default)' },
		{ value: 'managed', label: 'Managed' },
		{ value: 'self-signed', label: 'Self signed' }
	];
	const accessModes = [
		{ value: 'public', label: 'Public' },
		{ value: 'private', label: 'Private' }
	];
	const accessModesWithEmpty = [
		{ value: '', label: '(Use global default)' },
		{ value: 'public', label: 'Public' },
		{ value: 'private', label: 'Private' }
	];
	const schemes = [
		{ value: 'https', label: 'HTTPS' },
		{ value: 'http', label: 'HTTP' }
	];

	let validationErrors = $state({});

	// helper to check if find has a value (find can be string or array)
	function hasFindValue(find) {
		if (!find) return false;
		if (typeof find === 'string') return !!find.trim();
		if (Array.isArray(find)) return find.length > 0 && find.some((f) => f && String(f).trim());
		return false;
	}

	// helper to check if a rule has been touched (user started filling it in)
	function isCaptureRuleTouched(rule) {
		return !!(rule.name?.trim() || rule.path?.trim() || hasFindValue(rule.find));
	}

	function isRewriteRuleTouched(rule) {
		return !!(rule.find?.trim() || rule.replace?.trim() || rule.path?.trim());
	}

	function isResponseRuleTouched(rule) {
		return !!(rule.path?.trim() || rule.body?.trim() || rule.status);
	}

	function isUrlRewriteRuleTouched(rule) {
		return !!(rule.find?.trim() || rule.replace?.trim());
	}

	function isHostTouched(host) {
		return !!(host.to?.trim() || host.domain?.trim());
	}

	// validate all rules and return errors object
	function validateConfig() {
		const errors = {};

		// validate capture rules (global) - only if touched
		configData.global.capture.forEach((rule, i) => {
			if (!isCaptureRuleTouched(rule)) return;
			const prefix = `global.capture.${i}`;
			if (!rule.name?.trim()) {
				errors[`${prefix}.name`] = 'Name is required';
			}
			if (!rule.path?.trim()) {
				errors[`${prefix}.path`] = 'Path is required';
			}
			// find is required except for path based navigation tracking (path set, find empty)
			if (!hasFindValue(rule.find) && !rule.path?.trim()) {
				errors[`${prefix}.find`] = 'Find pattern is required';
			}
		});

		// validate rewrite rules (global) - only if touched
		configData.global.rewrite.forEach((rule, i) => {
			if (!isRewriteRuleTouched(rule)) return;
			const prefix = `global.rewrite.${i}`;
			if (!rule.find?.trim()) {
				errors[`${prefix}.find`] = 'Find is required';
			}
			if (rule.engine === 'dom') {
				if (!rule.action) {
					errors[`${prefix}.action`] = 'Action is required for DOM engine';
				}
				// replace is required for most actions except 'remove'
				if (rule.action && rule.action !== 'remove' && !rule.replace?.trim()) {
					errors[`${prefix}.replace`] = `Replace is required for ${rule.action}`;
				}
			}
		});

		// validate response rules (global) - only if touched
		configData.global.response.forEach((rule, i) => {
			if (!isResponseRuleTouched(rule)) return;
			const prefix = `global.response.${i}`;
			if (!rule.path?.trim()) {
				errors[`${prefix}.path`] = 'Path is required';
			}
		});

		// validate URL rewrite rules (global) - only if touched
		configData.global.rewrite_urls.forEach((rule, i) => {
			if (!isUrlRewriteRuleTouched(rule)) return;
			const prefix = `global.rewrite_urls.${i}`;
			if (!rule.find?.trim()) {
				errors[`${prefix}.find`] = 'Find pattern is required';
			}
			if (!rule.replace?.trim()) {
				errors[`${prefix}.replace`] = 'Replace path is required';
			}
		});

		// validate hosts - only if touched
		configData.hosts.forEach((host, hostIndex) => {
			if (!isHostTouched(host)) return;
			const hostPrefix = `hosts.${hostIndex}`;
			if (!host.to?.trim()) {
				errors[`${hostPrefix}.to`] = 'Phishing domain is required';
			}
			if (!host.domain?.trim()) {
				errors[`${hostPrefix}.domain`] = 'Target domain is required';
			}

			// validate capture rules (host) - only if touched
			(host.capture || []).forEach((rule, i) => {
				if (!isCaptureRuleTouched(rule)) return;
				const prefix = `${hostPrefix}.capture.${i}`;
				if (!rule.name?.trim()) {
					errors[`${prefix}.name`] = 'Name is required';
				}
				if (!rule.path?.trim()) {
					errors[`${prefix}.path`] = 'Path is required';
				}
				// find is required except for path based navigation tracking (path set, find empty)
				if (!hasFindValue(rule.find) && !rule.path?.trim()) {
					errors[`${prefix}.find`] = 'Find pattern is required';
				}
			});

			// validate rewrite rules (host) - only if touched
			(host.rewrite || []).forEach((rule, i) => {
				if (!isRewriteRuleTouched(rule)) return;
				const prefix = `${hostPrefix}.rewrite.${i}`;
				if (!rule.find?.trim()) {
					errors[`${prefix}.find`] = 'Find is required';
				}
				if (rule.engine === 'dom') {
					if (!rule.action) {
						errors[`${prefix}.action`] = 'Action is required for DOM engine';
					}
					if (rule.action && rule.action !== 'remove' && !rule.replace?.trim()) {
						errors[`${prefix}.replace`] = `Replace is required for ${rule.action}`;
					}
				}
			});

			// validate response rules (host) - only if touched
			(host.response || []).forEach((rule, i) => {
				if (!isResponseRuleTouched(rule)) return;
				const prefix = `${hostPrefix}.response.${i}`;
				if (!rule.path?.trim()) {
					errors[`${prefix}.path`] = 'Path is required';
				}
			});

			// validate URL rewrite rules (host) - only if touched
			(host.rewrite_urls || []).forEach((rule, i) => {
				if (!isUrlRewriteRuleTouched(rule)) return;
				const prefix = `${hostPrefix}.rewrite_urls.${i}`;
				if (!rule.find?.trim()) {
					errors[`${prefix}.find`] = 'Find pattern is required';
				}
				if (!rule.replace?.trim()) {
					errors[`${prefix}.replace`] = 'Replace path is required';
				}
			});
		});

		return errors;
	}

	$effect(() => {
		const errors = validateConfig();
		if (initialized) {
			validationErrors = errors;
		}
	});

	function hasError(path) {
		return !!validationErrors[path];
	}

	function getError(path) {
		return validationErrors[path] || '';
	}

	let globalRulesTab = $state('capture');

	function setHostActiveTab(hostIndex, tab) {
		hostActiveTabs = { ...hostActiveTabs, [hostIndex]: tab };
	}

	// report to the parent on every keystroke
	function handleNameInput(e) {
		const value = e.target.value;
		onNameChange?.(value);
	}

	function handleDescriptionInput(e) {
		const value = e.target.value;
		onDescriptionChange?.(value);
	}

	function handleStartURLInput(e) {
		const value = e.target.value;
		onStartURLChange?.(value);
	}

	// global cert for custom TLS mode (not part of yaml config, sent separately to parent)
	let globalTLSKey = '';
	let globalTLSPem = '';

	/**
	 * @param {Event} event
	 * @param {'globalTLSKey'|'globalTLSPem'} target
	 */
	function onGlobalCertFile(event, target) {
		const file = /** @type {HTMLInputElement} */ (event.target).files[0];
		if (!file) return;
		const reader = new FileReader();
		reader.onload = (e) => {
			if (target === 'globalTLSKey') {
				globalTLSKey = e.target.result.toString();
			} else {
				globalTLSPem = e.target.result.toString();
			}
			dispatchCertChange();
		};
		reader.readAsText(file);
	}

	function dispatchCertChange() {
		onCertChange?.({
			globalTLSKey,
			globalTLSPem
		});
	}

	let wrapperElement;

	function handleWrapperClick() {
		// focus the wrapper so Ctrl+S works (FormGrid checks if activeElement is inside the form)
		if (wrapperElement && document.activeElement === document.body) {
			wrapperElement.focus();
		}
	}
</script>

<!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_noninteractive_element_interactions -->
<div
	class="proxy-builder-wrapper"
	tabindex="-1"
	role="region"
	aria-label="Proxy configuration builder"
	bind:this={wrapperElement}
	onclick={handleWrapperClick}
>
	<div class="proxy-builder">
		<!-- main tabs -->
		<div class="main-tabs">
			<button
				type="button"
				class="main-tab"
				class:active={activeTab === 'basic'}
				onclick={() => (activeTab = 'basic')}
			>
				<svg
					class="tab-icon"
					viewBox="0 0 24 24"
					fill="none"
					stroke="currentColor"
					stroke-width="2"
				>
					<path
						d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
					/>
				</svg>
				General
			</button>
			<button
				type="button"
				class="main-tab"
				class:active={activeTab === 'global'}
				onclick={() => (activeTab = 'global')}
			>
				<svg
					class="tab-icon"
					viewBox="0 0 24 24"
					fill="none"
					stroke="currentColor"
					stroke-width="2"
				>
					<path
						d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"
					/>
					<path d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
				</svg>
				Global Settings
			</button>
			<button
				type="button"
				class="main-tab"
				class:active={activeTab === 'hosts'}
				onclick={() => (activeTab = 'hosts')}
			>
				<svg
					class="tab-icon"
					viewBox="0 0 24 24"
					fill="none"
					stroke="currentColor"
					stroke-width="2"
				>
					<path
						d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"
					/>
				</svg>
				Hosts
				{#if configData.hosts.length > 0}
					<span class="badge">{configData.hosts.length}</span>
				{/if}
			</button>
		</div>

		<!-- tab content -->
		<div class="tab-content">
			<!-- basic information tab content -->
			<div class="basic-panel" style={activeTab !== 'basic' ? 'display:none' : ''}>
				<div class="settings-section">
					<div class="settings-section-header">
						<h3 class="settings-section-title">General</h3>
					</div>
					<div class="settings-grid">
						<div class="field-wrapper">
							<label class="flex flex-col py-2">
								<div class="flex items-center">
									<p
										class="font-semibold text-gray-600 dark:text-gray-400 py-2 transition-colors duration-200"
									>
										Name
									</p>
								</div>
								<input
									type="text"
									value={name}
									oninput={handleNameInput}
									placeholder="Company Auth Proxy"
									required
									minlength="1"
									maxlength="64"
									class="w-full text-ellipsis rounded-md py-2 pl-2 text-gray-600 dark:text-gray-300 border border-transparent dark:border-gray-700/60 focus:outline-none focus:border-solid focus:border-gray-400 dark:focus:border-highlight-blue/80 focus:bg-gray-100 dark:focus:bg-gray-700/60 bg-grayblue-light dark:bg-gray-900/60 font-normal transition-colors duration-200"
								/>
							</label>
						</div>
						<div class="field-wrapper">
							<label class="flex flex-col py-2">
								<div class="flex items-center">
									<p
										class="font-semibold text-gray-600 dark:text-gray-400 py-2 transition-colors duration-200"
									>
										Description
									</p>
								</div>
								<input
									type="text"
									value={description}
									oninput={handleDescriptionInput}
									placeholder="Optional description"
									maxlength="255"
									class="w-full text-ellipsis rounded-md py-2 pl-2 text-gray-600 dark:text-gray-300 border border-transparent dark:border-gray-700/60 focus:outline-none focus:border-solid focus:border-gray-400 dark:focus:border-highlight-blue/80 focus:bg-gray-100 dark:focus:bg-gray-700/60 bg-grayblue-light dark:bg-gray-900/60 font-normal transition-colors duration-200"
								/>
							</label>
						</div>
						<div class="field-wrapper full">
							<label class="flex flex-col py-2">
								<div class="flex items-center">
									<p
										class="font-semibold text-gray-600 dark:text-gray-400 py-2 transition-colors duration-200"
									>
										Start URL
									</p>
								</div>
								<input
									type="text"
									value={startURL}
									oninput={handleStartURLInput}
									placeholder="https://login.example.com/auth"
									required
									minlength="3"
									class="w-full text-ellipsis rounded-md py-2 pl-2 text-gray-600 dark:text-gray-300 border border-transparent dark:border-gray-700/60 focus:outline-none focus:border-solid focus:border-gray-400 dark:focus:border-highlight-blue/80 focus:bg-gray-100 dark:focus:bg-gray-700/60 bg-grayblue-light dark:bg-gray-900/60 font-normal transition-colors duration-200"
								/>
							</label>
							<span class="settings-field-hint"
								>Domain must match a phishing domain in the Hosts tab</span
							>
						</div>
					</div>
				</div>
				<!-- proxy configuration section -->
				<div class="settings-section">
					<h3 class="settings-section-title">Proxy Settings</h3>
					<div class="settings-grid">
						<div class="field-wrapper">
							<TextField
								width="full"
								bind:value={configData.proxy}
								placeholder="socks5://proxy.example.com:1080 (optional)"
							>
								Forward Proxy
							</TextField>
							<span class="settings-field-hint">Route all traffic through this proxy</span>
						</div>
						<div class="field-wrapper">
							<TextField
								width="full"
								bind:value={configData.script}
								placeholder="script-name (optional)"
							>
								Session Script
							</TextField>
							<span class="settings-field-hint">
								Saved script run once when a session starts. It receives the incoming connection
								(ip, country, asns, ja4, headers) and can return a proxy to forward that session
								through. Falls back to Forward Proxy when empty or on error
							</span>
						</div>
					</div>
				</div>
			</div>
			<div class="hosts-panel" style={activeTab !== 'hosts' ? 'display:none' : ''}>
				<!-- hosts list sidebar -->
				<div class="hosts-sidebar">
					<div class="sidebar-header">
						<span class="sidebar-title">Domain Mappings</span>
						<button type="button" class="add-btn small" onclick={addHost} title="Add Host">
							<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
								<path d="M12 4v16m8-8H4" />
							</svg>
						</button>
					</div>
					{#if configData.hosts.length > 3}
						<div class="px-2 pb-2 host-search-wrapper">
							<Search pagination={hostSearchPagination} />
						</div>
					{/if}
					<div class="flex-1 overflow-y-auto p-2">
						{#if configData.hosts.length > 0}
							<div class="flex flex-col gap-1.5">
								{#each filteredHosts as { host, index: i }}
									<button
										type="button"
										class="flex flex-col gap-2 w-full p-3 text-left bg-white dark:bg-gray-800/40 border rounded-lg cursor-pointer transition-all duration-150
												{expandedHostIndex === i
											? 'border-cta-blue dark:border-highlight-blue bg-pc-lightblue dark:bg-active-blue/20 shadow-sm ring-1 ring-cta-blue/20 dark:ring-highlight-blue/20'
											: 'border-gray-200 dark:border-gray-700/60 hover:border-gray-300 dark:hover:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-700/30'}"
										onclick={() => (expandedHostIndex = i)}
									>
										<div class="flex flex-col gap-0.5 min-w-0">
											<span
												class="text-[0.625rem] font-semibold text-gray-400 dark:text-gray-500 uppercase tracking-wider"
												>From</span
											>
											<span
												class="text-sm font-medium text-gray-800 dark:text-gray-100 truncate"
												title={host.to || 'New Host'}>{host.to || 'New Host'}</span
											>
										</div>
										<div class="flex flex-col gap-0.5 min-w-0">
											<span
												class="text-[0.625rem] font-semibold text-gray-400 dark:text-gray-500 uppercase tracking-wider"
												>To</span
											>
											<span
												class="text-sm text-gray-600 dark:text-gray-300 truncate"
												title={host.domain || '...'}>{host.domain || '...'}</span
											>
										</div>
										{#if host.capture?.length || host.rewrite?.length || host.response?.length}
											<div
												class="flex flex-wrap items-center gap-x-3 gap-y-1 pt-2 border-t border-gray-100 dark:border-gray-700/40 text-[0.6875rem]"
											>
												{#if host.capture?.length}
													<span class="flex items-center gap-1 text-emerald-600 dark:text-emerald-400">
														<span class="w-1.5 h-1.5 rounded-full bg-emerald-500 dark:bg-emerald-400"
														></span>
														{host.capture.length} capture
													</span>
												{/if}
												{#if host.rewrite?.length}
													<span class="flex items-center gap-1 text-blue-600 dark:text-blue-400">
														<span class="w-1.5 h-1.5 rounded-full bg-blue-500 dark:bg-blue-400"
														></span>
														{host.rewrite.length} rewrite
													</span>
												{/if}
												{#if host.response?.length}
													<span class="flex items-center gap-1 text-amber-600 dark:text-amber-400">
														<span class="w-1.5 h-1.5 rounded-full bg-amber-500 dark:bg-amber-400"
														></span>
														{host.response.length} response
													</span>
												{/if}
											</div>
										{/if}
									</button>
								{/each}
							</div>
						{:else}
							<div class="empty-state small">
								<p>No hosts configured</p>
								<button type="button" class="add-btn" onclick={addHost}>
									<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
										<path d="M12 4v16m8-8H4" />
									</svg>
									Add First Host
								</button>
							</div>
						{/if}
					</div>
				</div>

				<!-- host detail panel -->
				<div class="host-detail">
					{#if expandedHostIndex >= 0 && configData.hosts[expandedHostIndex]}
						<div class="detail-header">
							<div class="detail-title">
								<span class="domain-label"
									>{configData.hosts[expandedHostIndex].to || 'New Host'}</span
								>
								<span class="arrow">→</span>
								<span class="target-label"
									>{configData.hosts[expandedHostIndex].domain || 'target'}</span
								>
							</div>
							<div class="detail-actions">
								<button
									type="button"
									class="icon-btn"
									title="Duplicate"
									onclick={() => duplicateHost(expandedHostIndex)}
								>
									<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
										<rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
										<path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" />
									</svg>
								</button>
								<button
									type="button"
									class="icon-btn danger"
									title="Delete"
									onclick={() => removeHost(expandedHostIndex)}
								>
									<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
										<path
											d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
										/>
									</svg>
								</button>
							</div>
						</div>

						<!-- sub tabs -->
						<div class="sub-tabs">
							<button
								type="button"
								class="sub-tab"
								class:active={currentHostTab === 'settings'}
								onclick={() => setHostActiveTab(expandedHostIndex, 'settings')}
							>
								Settings
							</button>
							<button
								type="button"
								class="sub-tab"
								class:active={currentHostTab === 'capture'}
								onclick={() => setHostActiveTab(expandedHostIndex, 'capture')}
							>
								Capture
								{#if configData.hosts[expandedHostIndex].capture?.length}
									<span class="sub-badge">{configData.hosts[expandedHostIndex].capture.length}</span
									>
								{/if}
							</button>
							<button
								type="button"
								class="sub-tab"
								class:active={currentHostTab === 'rewrite'}
								onclick={() => setHostActiveTab(expandedHostIndex, 'rewrite')}
							>
								Rewrite
								{#if configData.hosts[expandedHostIndex].rewrite?.length}
									<span class="sub-badge">{configData.hosts[expandedHostIndex].rewrite.length}</span
									>
								{/if}
							</button>
							<button
								type="button"
								class="sub-tab"
								class:active={currentHostTab === 'response'}
								onclick={() => setHostActiveTab(expandedHostIndex, 'response')}
							>
								Response
								{#if configData.hosts[expandedHostIndex].response?.length}
									<span class="sub-badge"
										>{configData.hosts[expandedHostIndex].response.length}</span
									>
								{/if}
							</button>
							<button
								type="button"
								class="sub-tab"
								class:active={currentHostTab === 'urlrewrite'}
								onclick={() => setHostActiveTab(expandedHostIndex, 'urlrewrite')}
							>
								URL Rewrite
								{#if configData.hosts[expandedHostIndex].rewrite_urls?.length}
									<span class="sub-badge"
										>{configData.hosts[expandedHostIndex].rewrite_urls.length}</span
									>
								{/if}
							</button>
						</div>

						<div class="sub-content">
							<div
								class="settings-grid host-settings"
								style={currentHostTab !== 'settings' ? 'display:none' : ''}
							>
								<div class="field-wrapper full">
									<TextField
										width="full"
										bind:value={configData.hosts[expandedHostIndex].to}
										placeholder="login.phish.test"
										required
										error={hasError(`hosts.${expandedHostIndex}.to`)}
									>
										Phishing Domain
									</TextField>
									{#if hasError(`hosts.${expandedHostIndex}.to`)}
										<span class="field-error">{getError(`hosts.${expandedHostIndex}.to`)}</span>
									{:else}
										<span class="form-hint">Your phishing domain that will serve the content</span>
									{/if}
								</div>
								<div class="field-wrapper full">
									<TextField
										width="full"
										bind:value={configData.hosts[expandedHostIndex].domain}
										placeholder="login.target.com"
										required
										error={hasError(`hosts.${expandedHostIndex}.domain`)}
									>
										Target Domain
									</TextField>
									{#if hasError(`hosts.${expandedHostIndex}.domain`)}
										<span class="field-error">{getError(`hosts.${expandedHostIndex}.domain`)}</span>
									{:else}
										<span class="form-hint">The legitimate domain being impersonated</span>
									{/if}
								</div>
								<div class="field-wrapper">
									<TextFieldSelect
										id={`host-${expandedHostIndex}-scheme`}
										bind:value={configData.hosts[expandedHostIndex].scheme}
										options={schemes}
										size="normal"
									>
										Scheme
									</TextFieldSelect>
								</div>
								{#if configData.hosts[expandedHostIndex].tls}
									<div class="field-wrapper">
										<TextFieldSelect
											id={`host-${expandedHostIndex}-tls-mode`}
											bind:value={configData.hosts[expandedHostIndex].tls.mode}
											options={tlsModesWithEmpty}
											size="normal"
											optional
										>
											TLS Mode
										</TextFieldSelect>
									</div>
								{/if}
								{#if configData.hosts[expandedHostIndex].access}
									<div class="field-wrapper">
										<TextFieldSelect
											id={`host-${expandedHostIndex}-access-mode`}
											bind:value={configData.hosts[expandedHostIndex].access.mode}
											options={accessModesWithEmpty}
											size="normal"
											optional
										>
											Access Mode
										</TextFieldSelect>
										<span class="form-hint"
											>Private requires visiting a lure URL first (recommended)</span
										>
									</div>
									{#if configData.hosts[expandedHostIndex].access?.mode === 'private'}
										<div class="field-wrapper">
											<TextField
												width="full"
												bind:value={configData.hosts[expandedHostIndex].access.on_deny}
												placeholder="404"
											>
												On Deny
											</TextField>
											<span class="form-hint"
												>Status code (e.g. 404, 503) or redirect URL (e.g. https://example.com)</span
											>
										</div>
									{/if}
								{/if}
							</div>
							<ProxyRuleEditors
								rules={configData.hosts[expandedHostIndex]}
								tab={currentHostTab}
								idPrefix={`host-${expandedHostIndex}`}
								errorPrefix={`hosts.${expandedHostIndex}`}
								newRuleId={getRuleId}
								{hasError}
								{getError}
							/>
						</div>
					{:else}
						<div class="empty-state">
							<svg
								class="empty-icon"
								viewBox="0 0 24 24"
								fill="none"
								stroke="currentColor"
								stroke-width="1.5"
							>
								<path
									d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9"
								/>
							</svg>
							<p>Select a host or add a new one</p>
							<button type="button" class="add-btn" onclick={addHost}>
								<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
									<path d="M12 4v16m8-8H4" />
								</svg>
								Add Host
							</button>
						</div>
					{/if}
				</div>
			</div>
			<div class="global-panel" style={activeTab !== 'global' ? 'display:none' : ''}>
				<div class="global-grid">
					<!-- TLS & Access -->
					<div class="global-section">
						<h3 class="section-title">
							<svg
								class="section-icon"
								viewBox="0 0 24 24"
								fill="none"
								stroke="currentColor"
								stroke-width="2"
							>
								<path
									d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
								/>
							</svg>
							Security
						</h3>
						<div class="section-content">
							<div class="field-wrapper">
								<TextFieldSelect
									id="global-tls-mode"
									bind:value={configData.global.tls.mode}
									options={tlsModes}
									size="normal"
								>
									TLS Mode
								</TextFieldSelect>
								<span class="form-hint"
									>Controls certificate verification for upstream connections</span
								>
							</div>
							{#if configData.global.tls.mode === 'custom'}
								<div class="field-wrapper">
									<FileField
										name="globalCertKey"
										accept=".key"
										optional
										onchange={(e) => onGlobalCertFile(e, 'globalTLSKey')}
										>Private Key (.key)</FileField
									>
									<span class="form-hint">leave empty to keep existing certificate</span>
								</div>
								<div class="field-wrapper">
									<FileField
										name="globalCertPem"
										accept=".pem,.crt"
										optional
										onchange={(e) => onGlobalCertFile(e, 'globalTLSPem')}
										>Certificate (.pem, .crt)</FileField
									>
									<span class="form-hint">leave empty to keep existing certificate</span>
								</div>
							{/if}
							<div class="field-wrapper">
								<TextFieldSelect
									id="global-access-mode"
									bind:value={configData.global.access.mode}
									options={accessModes}
									size="normal"
								>
									Access Mode
								</TextFieldSelect>
								<span class="form-hint"
									>Private requires visiting a lure URL first (recommended)</span
								>
							</div>
							{#if configData.global.access?.mode === 'private'}
								<div class="field-wrapper">
									<TextField
										width="full"
										bind:value={configData.global.access.on_deny}
										placeholder="404"
									>
										On Deny
									</TextField>
									<span class="form-hint"
										>Status code (e.g. 404, 503) or redirect URL (e.g. https://example.com)</span
									>
								</div>
							{/if}
						</div>
					</div>

					<!-- Impersonation -->
					<div class="global-section">
						<h3 class="section-title">
							<svg
								class="section-icon"
								viewBox="0 0 24 24"
								fill="none"
								stroke="currentColor"
								stroke-width="2"
							>
								<path d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
							</svg>
							Client Browser Impersonation
						</h3>
						<div class="section-content">
							<label class="checkbox-label">
								<input
									type="checkbox"
									checked={configData.global.impersonate.enabled}
									onchange={(e) => {
										configData.global.impersonate.enabled = e.currentTarget.checked;
										configData = configData;
									}}
									class="checkbox-input"
								/>
								<span class="checkbox-text">Enable Impersonation</span>
							</label>
							<span class="form-hint"
								>Detects client browser and uses a matching fingerprint profile (Chrome or Firefox
								only, others default to Chrome)</span
							>
							{#if configData.global.impersonate.enabled}
								<label class="checkbox-label" style="margin-top: 0.5rem;">
									<input
										type="checkbox"
										checked={configData.global.impersonate.retain_ua}
										onchange={(e) => {
											configData.global.impersonate.retain_ua = e.currentTarget.checked;
											configData = configData;
										}}
										class="checkbox-input"
									/>
									<span class="checkbox-text">Retain User Agent</span>
								</label>
								<span class="form-hint"
									>Use the client's User-Agent header instead of the impersonated browser's default</span
								>
							{/if}
						</div>
					</div>

					<!-- Template Variables -->
					<div class="global-section">
						<h3 class="section-title">
							<svg
								class="section-icon"
								viewBox="0 0 24 24"
								fill="none"
								stroke="currentColor"
								stroke-width="2"
							>
								<path
									d="M7 8h10M7 12h4m1 8l-4-4H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-3l-4 4z"
								/>
							</svg>
							Template Variables
						</h3>
						<div class="section-content">
							<label class="checkbox-label">
								<input
									type="checkbox"
									checked={configData.global.variables.enabled}
									onchange={(e) => {
										configData.global.variables.enabled = e.currentTarget.checked;
										if (!e.currentTarget.checked) {
											configData.global.variables.allowed = [];
										}
										configData = configData;
									}}
									class="checkbox-input"
								/>
								<span class="checkbox-text">Enable Variables</span>
							</label>
							<span class="form-hint"
								>Allow template variables like <code>{'{{.Email}}'}</code> in rewrite rules to be replaced
								with recipient data</span
							>
							{#if configData.global.variables.enabled}
								<div class="field-wrapper" style="margin-top: 0.75rem;">
									<label class="flex flex-col">
										<span class="text-sm font-medium text-pc-darkblue dark:text-white mb-1.5"
											>Allowed Variables (optional)</span
										>
										<div class="variables-selector">
											{#each validProxyVariables as varName}
												<label class="variable-chip">
													<input
														type="checkbox"
														checked={configData.global.variables.allowed?.includes(varName)}
														onchange={(e) => {
															if (e.currentTarget.checked) {
																configData.global.variables.allowed = [
																	...(configData.global.variables.allowed || []),
																	varName
																];
															} else {
																configData.global.variables.allowed =
																	configData.global.variables.allowed?.filter(
																		(v) => v !== varName
																	) || [];
															}
															configData = configData;
														}}
														class="hidden"
													/>
													<span
														class="chip-text"
														class:selected={configData.global.variables.allowed?.includes(varName)}
														>{varName}</span
													>
												</label>
											{/each}
										</div>
									</label>
									<span class="form-hint"
										>Leave empty to allow all variables, or select specific ones to restrict which
										can be used</span
									>
								</div>
							{/if}
						</div>
					</div>
				</div>

				<!-- Global Rules Tabs -->
				<div class="global-rules">
					<div class="rules-tabs">
						<button
							type="button"
							class="rules-tab"
							class:active={(activeTab === 'global' && !globalRulesTab) ||
								globalRulesTab === 'capture'}
							onclick={() => (globalRulesTab = 'capture')}
						>
							Capture Rules
							{#if configData.global.capture?.length}
								<span class="sub-badge">{configData.global.capture.length}</span>
							{/if}
						</button>
						<button
							type="button"
							class="rules-tab"
							class:active={globalRulesTab === 'rewrite'}
							onclick={() => (globalRulesTab = 'rewrite')}
						>
							Rewrite Rules
							{#if configData.global.rewrite?.length}
								<span class="sub-badge">{configData.global.rewrite.length}</span>
							{/if}
						</button>
						<button
							type="button"
							class="rules-tab"
							class:active={globalRulesTab === 'response'}
							onclick={() => (globalRulesTab = 'response')}
						>
							Response Rules
							{#if configData.global.response?.length}
								<span class="sub-badge">{configData.global.response.length}</span>
							{/if}
						</button>
						<button
							type="button"
							class="rules-tab"
							class:active={globalRulesTab === 'urlrewrite'}
							onclick={() => (globalRulesTab = 'urlrewrite')}
						>
							URL Rewrite Rules
							{#if configData.global.rewrite_urls?.length}
								<span class="sub-badge">{configData.global.rewrite_urls.length}</span>
							{/if}
						</button>
					</div>

					<div class="rules-content">
						<ProxyRuleEditors
							rules={configData.global}
							tab={globalRulesTab || 'capture'}
							idPrefix="global"
							errorPrefix="global"
							newRuleId={getRuleId}
							{hasError}
							{getError}
						/>
					</div>
				</div>
			</div>
		</div>
	</div>
</div>

<style>
	/* wrapper */
	.proxy-builder-wrapper {
		width: 100%;
		height: 100%;
		min-height: 500px;
		overflow: auto;
	}

	.proxy-builder {
		display: flex;
		flex-direction: column;
		height: 100%;
		background: white;
		border-radius: 0.5rem;
	}

	:global(.dark) .proxy-builder {
		background: rgb(17 24 39 / 0.6);
	}

	/* settings section */
	.settings-section {
		padding: 1.5rem;
		border-bottom: 1px solid #e5e7eb;
	}

	.settings-section:last-child {
		border-bottom: none;
	}

	:global(.dark) .settings-section {
		border-bottom-color: rgb(55 65 81 / 0.6);
	}

	.settings-section-header {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-bottom: 0.75rem;
	}

	.settings-section-title {
		font-size: 0.875rem;
		font-weight: 600;
		color: rgb(71, 85, 105);
		margin-bottom: 0;
	}

	.settings-section-header + .settings-grid {
		margin-top: 0;
	}

	.hidden {
		display: none;
	}

	:global(.dark) .settings-section-title {
		color: #9ca3af;
	}

	.settings-grid {
		display: grid;
		grid-template-columns: repeat(2, 1fr);
		gap: 0.5rem 1.5rem;
	}

	.field-wrapper {
		display: flex;
		flex-direction: column;
	}

	.field-wrapper.full {
		grid-column: span 2;
	}

	.settings-field-hint,
	.form-hint {
		font-size: 0.75rem;
		color: #6b7280;
		margin-top: 0.25rem;
		padding-left: 0.125rem;
	}

	:global(.dark) .settings-field-hint,
	:global(.dark) .form-hint {
		color: #9ca3af;
	}

	/* main tabs */
	.main-tabs {
		display: flex;
		gap: 0.25rem;
		padding: 0.75rem;
		background: #f9fafb;
		border-bottom: 1px solid #e5e7eb;
		border-radius: 0.5rem 0.5rem 0 0;
	}

	:global(.dark) .main-tabs {
		background: rgb(31 41 55 / 0.6);
		border-bottom-color: rgb(55 65 81 / 0.6);
	}

	.main-tab {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		padding: 0.625rem 1rem;
		font-size: 0.875rem;
		font-weight: 500;
		color: #6b7280;
		background: transparent;
		border: none;
		border-radius: 0.375rem;
		cursor: pointer;
		transition: all 0.15s ease;
	}

	.main-tab:hover {
		background: #e5e7eb;
		color: #4b5563;
	}

	:global(.dark) .main-tab:hover {
		background: rgb(55 65 81 / 0.6);
		color: #d1d5db;
	}

	.main-tab.active {
		background: white;
		color: #445ecc;
		box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
	}

	:global(.dark) .main-tab.active {
		background: rgb(17 24 39 / 0.8);
		color: #6887ea;
	}

	.tab-icon {
		width: 1.125rem;
		height: 1.125rem;
	}

	.badge {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-width: 1.25rem;
		height: 1.25rem;
		padding: 0 0.375rem;
		font-size: 0.75rem;
		font-weight: 600;
		background: #445ecc;
		color: white;
		border-radius: 9999px;
	}

	.main-tab:not(.active) .badge {
		background: #9ca3af;
	}

	:global(.dark) .main-tab:not(.active) .badge {
		background: rgb(75 85 99 / 0.8);
	}

	/* tab content */
	.tab-content {
		flex: 1;
		overflow: auto;
	}

	/* basic panel */
	.basic-panel {
		height: 100%;
		overflow-y: auto;
	}

	/* hosts panel */
	.hosts-panel {
		display: grid;
		grid-template-columns: 280px 1fr;
		height: 100%;
	}

	.hosts-sidebar {
		border-right: 1px solid #e5e7eb;
		background: #f9fafb;
		display: flex;
		flex-direction: column;
		overflow: hidden;
	}

	:global(.dark) .hosts-sidebar {
		background: rgb(31 41 55 / 0.4);
		border-right-color: rgb(55 65 81 / 0.6);
	}

	.sidebar-header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 1rem;
		border-bottom: 1px solid #e5e7eb;
	}

	:global(.dark) .sidebar-header {
		border-bottom-color: rgb(55 65 81 / 0.6);
	}

	.sidebar-title {
		font-size: 0.75rem;
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.05em;
		color: #6b7280;
	}

	:global(.dark) .sidebar-title {
		color: #9ca3af;
	}

	.host-search-wrapper :global(input) {
		width: 100% !important;
	}

	.host-search-wrapper :global(> div) {
		width: 100%;
	}

	/* host detail */
	.host-detail {
		display: flex;
		flex-direction: column;
		overflow: hidden;
	}

	.detail-header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 1rem 1.5rem;
		background: #f9fafb;
		border-bottom: 1px solid #e5e7eb;
	}

	:global(.dark) .detail-header {
		background: rgb(31 41 55 / 0.4);
		border-bottom-color: rgb(55 65 81 / 0.6);
	}

	.detail-title {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		font-size: 1rem;
		font-weight: 500;
	}

	.domain-label {
		color: #445ecc;
	}

	.arrow {
		color: #9ca3af;
	}

	.target-label {
		color: #6b7280;
	}

	:global(.dark) .target-label {
		color: #9ca3af;
	}

	.detail-actions {
		display: flex;
		gap: 0.5rem;
	}

	/* sub tabs */
	.sub-tabs {
		display: flex;
		gap: 0.25rem;
		padding: 0.5rem 1rem;
		background: white;
		border-bottom: 1px solid #e5e7eb;
	}

	:global(.dark) .sub-tabs {
		background: rgb(17 24 39 / 0.6);
		border-bottom-color: rgb(55 65 81 / 0.6);
	}

	.sub-tab {
		display: flex;
		align-items: center;
		gap: 0.375rem;
		padding: 0.5rem 0.875rem;
		font-size: 0.8125rem;
		font-weight: 500;
		color: #6b7280;
		background: transparent;
		border: none;
		border-radius: 0.375rem;
		cursor: pointer;
		transition: all 0.15s ease;
	}

	.sub-tab:hover {
		background: #f3f4f6;
		color: #4b5563;
	}

	:global(.dark) .sub-tab:hover {
		background: rgb(55 65 81 / 0.4);
		color: #d1d5db;
	}

	.sub-tab.active {
		background: #445ecc;
		color: white;
	}

	:global(.dark) .sub-tab.active {
		background: #1e3fa8;
	}

	.sub-badge {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-width: 1.125rem;
		height: 1.125rem;
		padding: 0 0.25rem;
		font-size: 0.625rem;
		font-weight: 600;
		background: #e5e7eb;
		color: #4b5563;
		border-radius: 9999px;
	}

	:global(.dark) .sub-badge {
		background: rgb(55 65 81 / 0.6);
		color: #d1d5db;
	}

	.sub-tab.active .sub-badge {
		background: rgba(255, 255, 255, 0.2);
		color: white;
	}

	.sub-content {
		flex: 1;
		overflow-y: auto;
		padding: 1rem;
	}

	/* host settings grid */
	.host-settings {
		max-width: 600px;
	}

	/* buttons */
	.add-btn {
		display: inline-flex;
		align-items: center;
		gap: 0.375rem;
		padding: 0.5rem 1rem;
		font-size: 0.875rem;
		font-weight: 500;
		color: white;
		background: #445ecc;
		border: none;
		border-radius: 0.375rem;
		cursor: pointer;
		transition: background 0.15s ease;
	}

	.add-btn:hover {
		background: #1e3fa8;
	}

	.add-btn.small {
		padding: 0.375rem 0.5rem;
	}

	.add-btn svg {
		width: 1rem;
		height: 1rem;
	}

	.icon-btn {
		display: flex;
		align-items: center;
		justify-content: center;
		width: 2rem;
		height: 2rem;
		padding: 0;
		background: transparent;
		border: 1px solid #e5e7eb;
		border-radius: 0.375rem;
		color: #6b7280;
		cursor: pointer;
		transition: all 0.15s ease;
	}

	:global(.dark) .icon-btn {
		border-color: rgb(55 65 81 / 0.6);
		color: #9ca3af;
	}

	.icon-btn:hover {
		background: #f3f4f6;
		border-color: #9ca3af;
	}

	:global(.dark) .icon-btn:hover {
		background: rgb(55 65 81 / 0.4);
	}

	.icon-btn.danger:hover {
		background: #fef2f2;
		border-color: #fca5a5;
		color: #dc2626;
	}

	:global(.dark) .icon-btn.danger:hover {
		background: rgb(127 29 29 / 0.3);
		border-color: #f87171;
		color: #f87171;
	}

	.icon-btn svg {
		width: 1rem;
		height: 1rem;
	}

	/* empty state */
	.empty-state {
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		padding: 3rem;
		text-align: center;
	}

	.empty-state.small {
		padding: 1.5rem;
	}

	.empty-state p {
		color: #6b7280;
		margin-bottom: 1rem;
	}

	:global(.dark) .empty-state p {
		color: #9ca3af;
	}

	.empty-icon {
		width: 3rem;
		height: 3rem;
		color: #d1d5db;
		margin-bottom: 1rem;
	}

	:global(.dark) .empty-icon {
		color: #4b5563;
	}

	/* global panel */
	.global-panel {
		display: flex;
		flex-direction: column;
		gap: 1.5rem;
		padding: 1.5rem;
	}

	.global-grid {
		display: grid;
		grid-template-columns: repeat(2, 1fr);
		gap: 1.5rem;
	}

	.global-section {
		background: #f9fafb;
		border: 1px solid #e5e7eb;
		border-radius: 0.5rem;
		padding: 1rem;
	}

	:global(.dark) .global-section {
		background: rgb(31 41 55 / 0.4);
		border-color: rgb(55 65 81 / 0.6);
	}

	.section-title {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		font-size: 0.875rem;
		font-weight: 600;
		color: #4b5563;
		margin-bottom: 1rem;
		padding-bottom: 0.75rem;
		border-bottom: 1px solid #e5e7eb;
	}

	:global(.dark) .section-title {
		color: #d1d5db;
		border-bottom-color: rgb(55 65 81 / 0.6);
	}

	.section-icon {
		width: 1.125rem;
		height: 1.125rem;
		color: #445ecc;
	}

	:global(.dark) .section-icon {
		color: #6887ea;
	}

	.section-content {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
	}

	/* global rules */
	.global-rules {
		background: #f9fafb;
		border: 1px solid #e5e7eb;
		border-radius: 0.5rem;
		overflow: hidden;
	}

	:global(.dark) .global-rules {
		background: rgb(31 41 55 / 0.4);
		border-color: rgb(55 65 81 / 0.6);
	}

	.rules-tabs {
		display: flex;
		gap: 0.25rem;
		padding: 0.75rem;
		background: white;
		border-bottom: 1px solid #e5e7eb;
	}

	:global(.dark) .rules-tabs {
		background: rgb(17 24 39 / 0.4);
		border-bottom-color: rgb(55 65 81 / 0.6);
	}

	.rules-tab {
		display: flex;
		align-items: center;
		gap: 0.375rem;
		padding: 0.5rem 0.875rem;
		font-size: 0.8125rem;
		font-weight: 500;
		color: #6b7280;
		background: transparent;
		border: none;
		border-radius: 0.375rem;
		cursor: pointer;
		transition: all 0.15s ease;
	}

	.rules-tab:hover {
		background: #f3f4f6;
		color: #4b5563;
	}

	:global(.dark) .rules-tab:hover {
		background: rgb(55 65 81 / 0.4);
		color: #d1d5db;
	}

	.rules-tab.active {
		background: #445ecc;
		color: white;
	}

	:global(.dark) .rules-tab.active {
		background: #1e3fa8;
	}

	.rules-content {
		padding: 1rem;
	}

	/* checkbox styling */
	.checkbox-label {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		cursor: pointer;
		padding: 0.5rem 0;
	}

	.checkbox-input {
		width: 1.25rem;
		height: 1.25rem;
		border: 2px solid #d1d5db;
		border-radius: 0.25rem;
		background: #f9fafb;
		cursor: pointer;
		accent-color: #445ecc;
	}

	:global(.dark) .checkbox-input {
		border-color: rgb(55 65 81 / 0.6);
		background: rgb(17 24 39 / 0.6);
	}

	.checkbox-input:checked {
		background: #445ecc;
		border-color: #445ecc;
	}

	:global(.dark) .checkbox-input:checked {
		background: #1e3fa8;
		border-color: #1e3fa8;
	}

	.checkbox-input:focus {
		outline: none;
		border-color: #9ca3af;
	}

	:global(.dark) .checkbox-input:focus {
		border-color: #6887ea;
	}

	.checkbox-text {
		font-size: 0.875rem;
		font-weight: 500;
		color: #4b5563;
	}

	:global(.dark) .checkbox-text {
		color: #9ca3af;
	}

	/* field error styles */
	.field-error {
		display: block;
		font-size: 0.75rem;
		color: #dc2626;
		margin-top: 0.25rem;
	}

	:global(.dark) .field-error {
		color: #f87171;
	}

	/* Variables selector styles */
	.variables-selector {
		display: flex;
		flex-wrap: wrap;
		gap: 0.375rem;
		padding: 0.5rem;
		background: #f9fafb;
		border-radius: 0.5rem;
		border: 1px solid #e5e7eb;
	}

	:global(.dark) .variables-selector {
		background: rgba(17, 24, 39, 0.4);
		border-color: rgba(55, 65, 81, 0.6);
	}

	.variable-chip {
		cursor: pointer;
	}

	.chip-text {
		display: inline-block;
		padding: 0.25rem 0.5rem;
		font-size: 0.75rem;
		font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
		border-radius: 0.25rem;
		background: #e5e7eb;
		color: #6b7280;
		transition: all 0.15s;
		user-select: none;
	}

	:global(.dark) .chip-text {
		background: rgba(55, 65, 81, 0.6);
		color: #9ca3af;
	}

	.chip-text:hover {
		background: #d1d5db;
		color: #4b5563;
	}

	:global(.dark) .chip-text:hover {
		background: rgba(75, 85, 99, 0.8);
		color: #d1d5db;
	}

	.chip-text.selected {
		background: #445ecc;
		color: white;
	}

	:global(.dark) .chip-text.selected {
		background: #445ecc;
		color: white;
	}

	.chip-text.selected:hover {
		background: #445ecc;
	}

	:global(.dark) .chip-text.selected:hover {
		background: #1e3fa8;
	}

	.section-content code {
		font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
		font-size: 0.8125rem;
		padding: 0.125rem 0.375rem;
		background: #e5e7eb;
		border-radius: 0.25rem;
		color: #4b5563;
	}

	:global(.dark) .section-content code {
		background: rgba(55, 65, 81, 0.6);
		color: #d1d5db;
	}
</style>
