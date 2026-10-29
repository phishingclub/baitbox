<script>
	// The capture, rewrite, response and URL rewrite rule editors. One instance
	// renders the rules for a scope (the whole proxy under Global, or a single
	// domain under Hosts), so both scopes share one editor instead of two copies.
	// rules is the scope object holding the rule arrays; mutating its arrays here
	// updates the shared config directly through the state proxy.
	import TextField from '$lib/components/TextField.svelte';
	import TextFieldSelect from '$lib/components/TextFieldSelect.svelte';
	import TextareaField from '$lib/components/TextareaField.svelte';

	let {
		rules,
		tab,
		idPrefix,
		errorPrefix,
		newRuleId,
		hasError = () => false,
		getError = () => ''
	} = $props();

	// options
	const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];
	const fromOptions = [
		{ value: 'request_body', label: 'Request Body' },
		{ value: 'request_header', label: 'Request Header' },
		{ value: 'response_body', label: 'Response Body' },
		{ value: 'response_header', label: 'Response Header' },
		{ value: 'any', label: 'Any' }
	];
	const headerFromOptions = [
		{ value: 'request_header', label: 'Request Header' },
		{ value: 'response_header', label: 'Response Header' }
	];
	const captureEngines = [
		{ value: 'regex', label: 'Regex' },
		{ value: 'header', label: 'Header' },
		{ value: 'cookie', label: 'Cookie' },
		{ value: 'json', label: 'JSON' },
		{ value: 'form', label: 'Form' },
		{ value: 'urlencoded', label: 'URL Encoded' },
		{ value: 'formdata', label: 'Form Data' },
		{ value: 'multipart', label: 'Multipart' }
	];
	const captureEventOptions = [
		{ value: 'submit', label: 'Submit' },
		{ value: 'info', label: 'Info' }
	];
	const engines = [
		{ value: 'regex', label: 'Regex' },
		{ value: 'dom', label: 'DOM' },
		{ value: 'header', label: 'Header' }
	];
	const headerActions = [
		{ value: 'set', label: 'Set' },
		{ value: 'add', label: 'Add' },
		{ value: 'remove', label: 'Remove' }
	];
	const rewriteHeaderFromOptions = [
		{ value: 'request_header', label: 'Request Header' },
		{ value: 'response_header', label: 'Response Header' },
		{ value: 'any', label: 'Any' }
	];
	const domActions = [
		{ value: 'setText', label: 'Set Text' },
		{ value: 'setHtml', label: 'Set HTML' },
		{ value: 'setAttr', label: 'Set Attribute' },
		{ value: 'removeAttr', label: 'Remove Attribute' },
		{ value: 'addClass', label: 'Add Class' },
		{ value: 'removeClass', label: 'Remove Class' },
		{ value: 'remove', label: 'Remove' }
	];
	const targets = [
		{ value: 'first', label: 'First' },
		{ value: 'last', label: 'Last' },
		{ value: 'all', label: 'All' }
	];

	// get from options based on engine - cookie ignores from, header only uses header options
	function getFromOptionsForEngine(engine) {
		if (engine === 'cookie') return [];
		if (engine === 'header') return headerFromOptions;
		return fromOptions;
	}

	function getDefaultFromForEngine(engine) {
		if (engine === 'cookie') return '';
		if (engine === 'header') return 'request_header';
		return 'request_body';
	}

	// handle engine change - always reset 'from' to default for consistency
	function handleCaptureEngineChange(rule, newEngine) {
		rule.engine = newEngine;
		rule.from = getDefaultFromForEngine(newEngine);
	}

	function getFromOptionsForRewriteEngine(engine) {
		if (engine === 'header') return rewriteHeaderFromOptions;
		return fromOptions;
	}

	function getDefaultFromForRewriteEngine(engine) {
		if (engine === 'header') return 'response_header';
		return 'response_body';
	}

	function handleRewriteEngineChange(rule, newEngine) {
		rule.engine = newEngine;
		rule.from = getDefaultFromForRewriteEngine(newEngine);
		if (newEngine !== 'dom') {
			rule.action = newEngine === 'header' ? 'set' : '';
		}
	}

	// response header helpers, headers is an object of name -> value
	function addResponseHeader(rule) {
		if (!rule.headers) rule.headers = {};
		const newKey = `Header-${Object.keys(rule.headers).length + 1}`;
		rule.headers[newKey] = '';
	}

	function removeResponseHeader(rule, key) {
		delete rule.headers[key];
	}

	function updateResponseHeaderKey(rule, oldKey, newKey) {
		if (oldKey !== newKey && newKey) {
			const value = rule.headers[oldKey];
			delete rule.headers[oldKey];
			rule.headers[newKey] = value;
		}
	}

	// url rewrite query param helpers, query is []{ find, replace }
	function addURLRewriteQueryParam(rule) {
		rule.query = [...(rule.query || []), { find: '', replace: '' }];
	}

	function removeURLRewriteQueryParam(rule, index) {
		rule.query = (rule.query || []).filter((_, i) => i !== index);
	}

	// url rewrite filter helpers, filter is []string (param name allowlist)
	function addURLRewriteFilter(rule) {
		rule.filter = [...(rule.filter || []), ''];
	}

	function removeURLRewriteFilter(rule, index) {
		rule.filter = (rule.filter || []).filter((_, i) => i !== index);
	}

	// the default rule for each editor type
	function makeRule(type) {
		if (type === 'capture') {
			return {
				_id: newRuleId(),
				name: '',
				method: 'POST',
				path: '',
				find: '',
				engine: 'regex',
				from: 'request_body',
				required: false,
				event: 'submit'
			};
		}
		if (type === 'rewrite') {
			return {
				_id: newRuleId(),
				name: '',
				engine: 'regex',
				find: '',
				replace: '',
				from: 'response_body',
				action: '',
				path: '',
				method: ''
			};
		}
		if (type === 'response') {
			return { _id: newRuleId(), path: '', status: 200, headers: {}, body: '', forward: false };
		}
		return { _id: newRuleId(), find: '', replace: '', query: [], filter: [] };
	}

	function addRule(type) {
		rules[type] = [...(rules[type] || []), makeRule(type)];
	}

	function removeRule(type, index) {
		rules[type] = (rules[type] || []).filter((_, i) => i !== index);
	}
</script>

							{#if tab === 'capture'}
								<div class="rules-description">
									<p>Extract credentials, tokens, and other data from requests and responses.</p>
								</div>
								<div class="rules-container">
									{#each rules.capture || [] as rule, ruleIndex (rule._id)}
										<div class="rule-card">
											<div class="rule-header">
												<span class="rule-name">{rule.name || `Rule ${ruleIndex + 1}`}</span>
												<button
													type="button"
													class="icon-btn small danger"
													onclick={() => removeRule('capture', ruleIndex)}
												>
													<svg
														viewBox="0 0 24 24"
														fill="none"
														stroke="currentColor"
														stroke-width="2"
													>
														<path d="M6 18L18 6M6 6l12 12" />
													</svg>
												</button>
											</div>
											<div class="rule-grid">
												<div class="field-wrapper">
													<TextField
														width="full"
														bind:value={rule.name}
														placeholder="username"
														error={hasError(`${errorPrefix}.capture.${ruleIndex}.name`)}
													>
														Name
													</TextField>
													{#if hasError(`${errorPrefix}.capture.${ruleIndex}.name`)}
														<span class="field-error"
															>{getError(
																`${errorPrefix}.capture.${ruleIndex}.name`
															)}</span
														>
													{/if}
												</div>
												<div class="field-wrapper">
													<TextFieldSelect
														id={`${idPrefix}-capture-${ruleIndex}-method`}
														bind:value={rule.method}
														options={methods}
														size="normal"
													>
														Method
													</TextFieldSelect>
												</div>
												<div class="field-wrapper">
													<TextField
														width="full"
														bind:value={rule.path}
														placeholder="/login"
														error={hasError(`${errorPrefix}.capture.${ruleIndex}.path`)}
													>
														Path (regex)
													</TextField>
													{#if hasError(`${errorPrefix}.capture.${ruleIndex}.path`)}
														<span class="field-error"
															>{getError(
																`${errorPrefix}.capture.${ruleIndex}.path`
															)}</span
														>
													{/if}
												</div>
												<div class="field-wrapper">
													<TextFieldSelect
														id={`${idPrefix}-capture-${ruleIndex}-engine`}
														value={rule.engine}
														options={captureEngines}
														size="normal"
														onSelect={(val) => handleCaptureEngineChange(rule, val)}
													>
														Engine
													</TextFieldSelect>
												</div>
												{#if rule.engine !== 'cookie'}
													<div class="field-wrapper">
														<TextFieldSelect
															id={`${idPrefix}-capture-${ruleIndex}-from`}
															bind:value={rule.from}
															options={getFromOptionsForEngine(rule.engine)}
															size="normal"
														>
															From
														</TextFieldSelect>
													</div>
												{/if}
												<div class="field-wrapper full">
													<TextField
														width="full"
														bind:value={rule.find}
														placeholder={rule.engine === 'regex'
															? 'username=([^&]+)'
															: rule.engine === 'header'
																? 'Authorization'
																: rule.engine === 'cookie'
																	? 'session_id'
																	: rule.engine === 'json'
																		? 'user.email'
																		: 'username'}
														error={hasError(`${errorPrefix}.capture.${ruleIndex}.find`)}
													>
														{#if rule.engine === 'regex'}
															Regex Pattern
														{:else if rule.engine === 'header'}
															Header Name
														{:else if rule.engine === 'cookie'}
															Cookie Name
														{:else if rule.engine === 'json'}
															JSON Path
														{:else}
															Field Name
														{/if}
													</TextField>
													{#if hasError(`${errorPrefix}.capture.${ruleIndex}.find`)}
														<span class="field-error"
															>{getError(
																`${errorPrefix}.capture.${ruleIndex}.find`
															)}</span
														>
													{/if}
												</div>
												<div class="field-wrapper checkbox-wrapper">
													<label class="checkbox-label">
														<input
															type="checkbox"
															checked={rule.required}
															onchange={(e) => {
																rule.required = e.currentTarget.checked;
															}}
															class="checkbox-input"
														/>
														<span class="checkbox-text">Required</span>
													</label>
													<span class="form-hint"
														>Must be captured before session completes and campaign flow progresses</span
													>
												</div>
												<div class="field-wrapper">
													<TextFieldSelect
														id={`${idPrefix}-capture-${ruleIndex}-event`}
														bind:value={rule.event}
														options={captureEventOptions}
														size="normal"
													>
														Event Type
													</TextFieldSelect>
												</div>
											</div>
										</div>
									{/each}
									<button
										type="button"
										class="add-rule-btn"
										onclick={() => addRule('capture')}
									>
										<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
											<path d="M12 4v16m8-8H4" />
										</svg>
										Add Capture Rule
									</button>
								</div>
							{:else if tab === 'rewrite'}
								<div class="rules-description">
									<p>
										Rewrite rules modify content passing through the proxy. Use <strong
											>Regex</strong
										>
										for text replacement or <strong>DOM</strong> for HTML element manipulation.
									</p>
								</div>
								<div class="rules-container">
									{#each rules.rewrite || [] as rule, ruleIndex (rule._id)}
										<div class="rule-card">
											<div class="rule-header">
												<span class="rule-name">{rule.name || `Rule ${ruleIndex + 1}`}</span>
												<button
													type="button"
													class="icon-btn small danger"
													onclick={() => removeRule('rewrite', ruleIndex)}
												>
													<svg
														viewBox="0 0 24 24"
														fill="none"
														stroke="currentColor"
														stroke-width="2"
													>
														<path d="M6 18L18 6M6 6l12 12" />
													</svg>
												</button>
											</div>
											<div class="rule-grid">
												<div class="field-wrapper">
													<TextField width="full" bind:value={rule.name} placeholder="replace_logo">
														Name
													</TextField>
												</div>
												<div class="field-wrapper">
													<TextFieldSelect
														id={`${idPrefix}-rewrite-${ruleIndex}-engine`}
														bind:value={rule.engine}
														options={engines}
														size="normal"
														onchange={() => handleRewriteEngineChange(rule, rule.engine)}
													>
														Engine
													</TextFieldSelect>
												</div>
												<div class="field-wrapper">
													<TextField width="full" bind:value={rule.path} placeholder="^/login">
														Path (regex, optional)
													</TextField>
													<span class="form-hint"
														>Only apply this rule when the request path matches</span
													>
												</div>
												<div class="field-wrapper">
													<TextFieldSelect
														id={`${idPrefix}-rewrite-${ruleIndex}-method`}
														bind:value={rule.method}
														options={[
															{ value: '', label: 'Any' },
															...methods.map((m) => ({ value: m, label: m }))
														]}
														size="normal"
													>
														Method (optional)
													</TextFieldSelect>
												</div>
												{#if rule.engine === 'dom'}
													<div class="field-wrapper">
														<TextFieldSelect
															id={`${idPrefix}-rewrite-${ruleIndex}-action`}
															bind:value={rule.action}
															options={domActions}
															size="normal"
														>
															Action
														</TextFieldSelect>
														{#if hasError(`${errorPrefix}.rewrite.${ruleIndex}.action`)}
															<span class="field-error"
																>{getError(
																	`${errorPrefix}.rewrite.${ruleIndex}.action`
																)}</span
															>
														{/if}
													</div>
													<div class="field-wrapper">
														<TextFieldSelect
															id={`${idPrefix}-rewrite-${ruleIndex}-target`}
															bind:value={rule.target}
															options={targets}
															size="normal"
														>
															Target
														</TextFieldSelect>
														<span class="form-hint"
															>Also supports numeric list (1,3,5) or range (2-4)</span
														>
													</div>
												{:else if rule.engine === 'header'}
													<div class="field-wrapper">
														<TextFieldSelect
															id={`${idPrefix}-rewrite-${ruleIndex}-action`}
															bind:value={rule.action}
															options={headerActions}
															size="normal"
														>
															Action
														</TextFieldSelect>
													</div>
												{/if}
												<div class="field-wrapper">
													<TextFieldSelect
														id={`${idPrefix}-rewrite-${ruleIndex}-from`}
														bind:value={rule.from}
														options={getFromOptionsForRewriteEngine(rule.engine)}
														size="normal"
													>
														From
													</TextFieldSelect>
												</div>
												<div class="field-wrapper full">
													<TextField
														width="full"
														bind:value={rule.find}
														placeholder={rule.engine === 'dom'
															? 'div.logo, #header img'
															: rule.engine === 'header'
																? 'Server'
																: 'target\\.com'}
														error={hasError(`${errorPrefix}.rewrite.${ruleIndex}.find`)}
													>
														{#if rule.engine === 'dom'}
															Selector (CSS)
														{:else if rule.engine === 'header'}
															Header Name
														{:else}
															Find (regex)
														{/if}
													</TextField>
													{#if hasError(`${errorPrefix}.rewrite.${ruleIndex}.find`)}
														<span class="field-error"
															>{getError(
																`${errorPrefix}.rewrite.${ruleIndex}.find`
															)}</span
														>
													{:else}
														<span class="form-hint">
															{#if rule.engine === 'dom'}
																CSS selector to find HTML elements
															{:else if rule.engine === 'header'}
																Exact header name (e.g. Server, X-Powered-By)
															{:else}
																Regex pattern to search for in content
															{/if}
														</span>
													{/if}
												</div>
												{#if rule.engine !== 'header' || rule.action !== 'remove'}
													<div class="field-wrapper full">
														<TextareaField
															fullWidth
															bind:value={rule.replace}
															placeholder={rule.engine === 'dom'
																? rule.action === 'setAttr'
																	? 'href:https://example.com'
																	: rule.action === 'remove'
																		? ''
																		: 'New content'
																: rule.engine === 'header'
																	? 'new-value'
																	: 'phishing.com'}
															height="medium"
														>
															{#if rule.engine === 'dom' && rule.action === 'setAttr'}
																Value (attr:value)
															{:else if rule.engine === 'dom' && rule.action === 'remove'}
																Value (not required)
															{:else if rule.engine === 'header'}
																New Value
															{:else}
																Replace
															{/if}
														</TextareaField>
														{#if hasError(`${errorPrefix}.rewrite.${ruleIndex}.replace`)}
															<span class="field-error"
																>{getError(
																	`${errorPrefix}.rewrite.${ruleIndex}.replace`
																)}</span
															>
														{:else}
															<span class="form-hint">
																{#if rule.engine === 'dom'}
																	{#if rule.action === 'setAttr'}
																		Format: attribute:value (e.g. href:https://example.com)
																	{:else if rule.action === 'remove'}
																		Not required for remove action
																	{:else if rule.action === 'removeAttr'}
																		Attribute name to remove
																	{:else if rule.action === 'addClass' || rule.action === 'removeClass'}
																		CSS class name
																	{:else}
																		New content for matched elements
																	{/if}
																{:else if rule.engine === 'header'}
																	New value for the header
																{:else}
																	Replacement text (use $1, $2 for capture groups)
																{/if}
															</span>
														{/if}
													</div>
												{/if}
											</div>
										</div>
									{/each}
									<button
										type="button"
										class="add-rule-btn"
										onclick={() => addRule('rewrite')}
									>
										<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
											<path d="M12 4v16m8-8H4" />
										</svg>
										Add Rewrite Rule
									</button>
								</div>
							{:else if tab === 'response'}
								<div class="rules-description">
									<p>
										Return custom responses for specific paths instead of proxying to the target.
									</p>
								</div>
								<div class="rules-container">
									{#each rules.response || [] as rule, ruleIndex (rule._id)}
										<div class="rule-card">
											<div class="rule-header">
												<span class="rule-name">{rule.path || `Rule ${ruleIndex + 1}`}</span>
												<button
													type="button"
													class="icon-btn small danger"
													onclick={() => removeRule('response', ruleIndex)}
												>
													<svg
														viewBox="0 0 24 24"
														fill="none"
														stroke="currentColor"
														stroke-width="2"
													>
														<path d="M6 18L18 6M6 6l12 12" />
													</svg>
												</button>
											</div>
											<div class="rule-grid">
												<div class="field-wrapper">
													<TextField
														width="full"
														bind:value={rule.path}
														placeholder="/custom-page"
														error={hasError(
															`${errorPrefix}.response.${ruleIndex}.path`
														)}
													>
														Path
													</TextField>
													{#if hasError(`${errorPrefix}.response.${ruleIndex}.path`)}
														<span class="field-error"
															>{getError(
																`${errorPrefix}.response.${ruleIndex}.path`
															)}</span
														>
													{/if}
												</div>
												<div class="field-wrapper">
													<TextField width="full" bind:value={rule.status} placeholder="200">
														Status
													</TextField>
												</div>
												<div class="field-wrapper full">
													<TextareaField
														fullWidth
														bind:value={rule.body}
														placeholder="<html>...</html>"
														height="medium"
													>
														Body
													</TextareaField>
												</div>
												<div class="field-wrapper full">
													<div class="headers-section">
														<div class="headers-label">
															<span>Headers</span>
															<button
																type="button"
																class="add-btn tiny"
																onclick={() => addResponseHeader(rule)}
																title="Add Header"
															>
																<svg
																	viewBox="0 0 24 24"
																	fill="none"
																	stroke="currentColor"
																	stroke-width="2"
																>
																	<path d="M12 4v16m8-8H4" />
																</svg>
															</button>
														</div>
														{#if rule.headers && Object.keys(rule.headers).length > 0}
															<div class="headers-list">
																{#each Object.entries(rule.headers) as [key, value]}
																	<div class="header-row">
																		<input
																			type="text"
																			value={key}
																			onblur={(e) =>
																				updateResponseHeaderKey(rule, key, e.currentTarget.value)}
																			placeholder="Header-Name"
																			class="header-key-input"
																		/>
																		<input
																			type="text"
																			bind:value={rule.headers[key]}
																			placeholder="Header value"
																			class="header-value-input"
																		/>
																		<button
																			type="button"
																			class="icon-btn tiny danger"
																			onclick={() => removeResponseHeader(rule, key)}
																			title="Remove header"
																		>
																			<svg
																				viewBox="0 0 24 24"
																				fill="none"
																				stroke="currentColor"
																				stroke-width="2"
																			>
																				<path d="M6 18L18 6M6 6l12 12" />
																			</svg>
																		</button>
																	</div>
																{/each}
															</div>
														{/if}
														<span class="form-hint"
															>Use <code>{'{{.Origin}}'}</code> to echo the request's Origin header</span
														>
													</div>
												</div>
												<div class="field-wrapper checkbox-wrapper">
													<label class="checkbox-label">
														<input
															type="checkbox"
															bind:checked={rule.forward}
															class="checkbox-input"
															onchange={(e) => {
																rule.forward = e.currentTarget.checked;
															}}
														/>
														<span class="checkbox-text">Forward to target</span>
													</label>
												</div>
											</div>
										</div>
									{/each}
									<button
										type="button"
										class="add-rule-btn"
										onclick={() => addRule('response')}
									>
										<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
											<path d="M12 4v16m8-8H4" />
										</svg>
										Add Response Rule
									</button>
								</div>
							{:else if tab === 'urlrewrite'}
								<div class="rules-description">
									<p>Transform URL paths to evade detection by masking original target URLs.</p>
								</div>
								<div class="rules-container">
									{#each rules.rewrite_urls || [] as rule, ruleIndex (rule._id)}
										<div class="rule-card">
											<div class="rule-header">
												<span class="rule-name">{rule.find || `Rule ${ruleIndex + 1}`}</span>
												<button
													type="button"
													class="icon-btn small danger"
													onclick={() => removeRule('rewrite_urls', ruleIndex)}
												>
													<svg
														viewBox="0 0 24 24"
														fill="none"
														stroke="currentColor"
														stroke-width="2"
													>
														<path d="M6 18L18 6M6 6l12 12" />
													</svg>
												</button>
											</div>
											<div class="rule-grid">
												<div class="field-wrapper">
													<TextField width="full" bind:value={rule.find} placeholder="/old-path">
														Find
													</TextField>
												</div>
												<div class="field-wrapper">
													<TextField width="full" bind:value={rule.replace} placeholder="/new-path">
														Replace
													</TextField>
												</div>
												<div class="field-wrapper full">
													<div class="headers-section">
														<div class="headers-label">
															<span>Query Parameter Renames</span>
															<button
																type="button"
																class="add-btn tiny"
																onclick={() => addURLRewriteQueryParam(rule)}
																title="Add query parameter rename"
															>
																<svg
																	viewBox="0 0 24 24"
																	fill="none"
																	stroke="currentColor"
																	stroke-width="2"
																>
																	<path d="M12 4v16m8-8H4" />
																</svg>
															</button>
														</div>
														{#if rule.query && rule.query.length > 0}
															<div class="headers-list">
																{#each rule.query as qParam, qIndex}
																	<div class="header-row">
																		<input
																			type="text"
																			bind:value={qParam.find}
																			placeholder="original_param"
																			class="header-key-input"
																		/>
																		<input
																			type="text"
																			bind:value={qParam.replace}
																			placeholder="renamed_param"
																			class="header-value-input"
																		/>
																		<button
																			type="button"
																			class="icon-btn tiny danger"
																			onclick={() => removeURLRewriteQueryParam(rule, qIndex)}
																			title="Remove query param rename"
																		>
																			<svg
																				viewBox="0 0 24 24"
																				fill="none"
																				stroke="currentColor"
																				stroke-width="2"
																			>
																				<path d="M6 18L18 6M6 6l12 12" />
																			</svg>
																		</button>
																	</div>
																{/each}
															</div>
														{/if}
														<span class="form-hint"
															>rename query parameters when rewriting the URL (original → new name)</span
														>
													</div>
												</div>
												<div class="field-wrapper full">
													<div class="headers-section">
														<div class="headers-label">
															<span>Query Parameter Filter</span>
															<button
																type="button"
																class="add-btn tiny"
																onclick={() => addURLRewriteFilter(rule)}
																title="Add parameter to keep"
															>
																<svg
																	viewBox="0 0 24 24"
																	fill="none"
																	stroke="currentColor"
																	stroke-width="2"
																>
																	<path d="M12 4v16m8-8H4" />
																</svg>
															</button>
														</div>
														{#if rule.filter && rule.filter.length > 0}
															<div class="headers-list">
																{#each rule.filter as filterParam, fIndex}
																	<div class="header-row">
																		<input
																			type="text"
																			bind:value={rule.filter[fIndex]}
																			placeholder="param_name"
																			class="header-key-input"
																			style="flex: 1;"
																		/>
																		<button
																			type="button"
																			class="icon-btn tiny danger"
																			onclick={() => removeURLRewriteFilter(rule, fIndex)}
																			title="Remove filter entry"
																		>
																			<svg
																				viewBox="0 0 24 24"
																				fill="none"
																				stroke="currentColor"
																				stroke-width="2"
																			>
																				<path d="M6 18L18 6M6 6l12 12" />
																			</svg>
																		</button>
																	</div>
																{/each}
															</div>
														{/if}
														<span class="form-hint"
															>allowlist of query parameters to keep. If empty, all parameters are
															forwarded</span
														>
													</div>
												</div>
											</div>
										</div>
									{/each}
									<button
										type="button"
										class="add-rule-btn"
										onclick={() => addRule('rewrite_urls')}
									>
										<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
											<path d="M12 4v16m8-8H4" />
										</svg>
										Add URL Rewrite Rule
									</button>
								</div>
							{/if}

<style>
	.field-wrapper {
		display: flex;
		flex-direction: column;
	}

	.field-wrapper.full {
		grid-column: span 2;
	}

	.field-wrapper.checkbox-wrapper {
		padding-top: 0.5rem;
	}

	.form-hint {
		font-size: 0.75rem;
		color: #6b7280;
		margin-top: 0.25rem;
		padding-left: 0.125rem;
	}

	:global(.dark) .form-hint {
		color: #9ca3af;
	}

	.rules-description {
		padding: 0.75rem 1rem;
		margin-bottom: 1rem;
		background: #f9fafb;
		border-radius: 0.5rem;
		border: 1px solid #e5e7eb;
	}

	:global(.dark) .rules-description {
		background: rgba(30, 41, 59, 0.5);
		border-color: #374151;
	}

	.rules-description p {
		font-size: 0.875rem;
		color: #6b7280;
		margin: 0;
		line-height: 1.5;
	}

	:global(.dark) .rules-description p {
		color: #9ca3af;
	}

	.rules-description strong {
		color: #4b5563;
		font-weight: 600;
	}

	:global(.dark) .rules-description strong {
		color: #d1d5db;
	}

	.rules-container {
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}

	.rule-card {
		background: #f9fafb;
		border: 1px solid #e5e7eb;
		border-radius: 0.5rem;
	}

	:global(.dark) .rule-card {
		background: rgb(31 41 55 / 0.4);
		border-color: rgb(55 65 81 / 0.6);
	}

	.rule-header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 0.75rem 1rem;
		background: white;
		border-bottom: 1px solid #e5e7eb;
		border-radius: 0.5rem 0.5rem 0 0;
	}

	:global(.dark) .rule-header {
		background: rgb(17 24 39 / 0.4);
		border-bottom-color: rgb(55 65 81 / 0.6);
	}

	.rule-name {
		font-size: 0.875rem;
		font-weight: 500;
		color: #1f2937;
	}

	:global(.dark) .rule-name {
		color: #f3f4f6;
	}

	.rule-grid {
		display: grid;
		grid-template-columns: repeat(2, 1fr);
		gap: 0.25rem 1rem;
		padding: 1rem;
	}

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

	.add-btn svg {
		width: 1rem;
		height: 1rem;
	}

	.add-btn.tiny {
		width: 1.25rem;
		height: 1.25rem;
		padding: 0.125rem;
	}

	.add-rule-btn {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 0.5rem;
		width: 100%;
		padding: 0.75rem;
		font-size: 0.875rem;
		font-weight: 500;
		color: #6b7280;
		background: transparent;
		border: 2px dashed #e5e7eb;
		border-radius: 0.5rem;
		cursor: pointer;
		transition: all 0.15s ease;
	}

	:global(.dark) .add-rule-btn {
		border-color: rgb(55 65 81 / 0.6);
		color: #9ca3af;
	}

	.add-rule-btn:hover {
		background: #f3f4f6;
		border-color: #9ca3af;
		color: #4b5563;
	}

	:global(.dark) .add-rule-btn:hover {
		background: rgb(55 65 81 / 0.4);
	}

	.add-rule-btn svg {
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

	.icon-btn.small {
		width: 1.5rem;
		height: 1.5rem;
	}

	.icon-btn.tiny {
		width: 1.25rem;
		height: 1.25rem;
		padding: 0.125rem;
	}

	.icon-btn svg {
		width: 1rem;
		height: 1rem;
	}

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

	.field-error {
		display: block;
		font-size: 0.75rem;
		color: #dc2626;
		margin-top: 0.25rem;
	}

	:global(.dark) .field-error {
		color: #f87171;
	}

	.headers-section {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.headers-label {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		font-size: 0.875rem;
		font-weight: 500;
		color: #4b5563;
	}

	:global(.dark) .headers-label {
		color: #9ca3af;
	}

	.headers-list {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.header-row {
		display: flex;
		gap: 0.5rem;
		align-items: center;
	}

	.header-key-input,
	.header-value-input {
		flex: 1;
		padding: 0.375rem 0.5rem;
		font-size: 0.875rem;
		border-radius: 0.375rem;
		border: 1px solid transparent;
		background: #f3f4f6;
		color: #4b5563;
		transition: all 0.2s;
	}

	:global(.dark) .header-key-input,
	:global(.dark) .header-value-input {
		background: rgba(17, 24, 39, 0.6);
		border-color: rgba(55, 65, 81, 0.6);
		color: #d1d5db;
	}

	.header-key-input:focus,
	.header-value-input:focus {
		outline: none;
		border-color: #9ca3af;
		background: #f9fafb;
	}

	:global(.dark) .header-key-input:focus,
	:global(.dark) .header-value-input:focus {
		border-color: rgba(56, 189, 248, 0.5);
		background: rgba(55, 65, 81, 0.6);
	}

	.header-key-input {
		max-width: 180px;
	}
</style>
