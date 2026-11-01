<script>
	import { PREVIEW_ACCEPT, PREVIEW_LIMITS_TEXT, previewFileProblem } from '$lib/utils/previewLimits.js';
	import { onMount } from 'svelte';
	import { beforeNavigate, goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { api } from '$lib/api/api.js';
	import { toast } from '$lib/stores/toast.svelte.js';
	import { askConfirm } from '$lib/stores/confirm.svelte.js';
	import CodeEditor from '$lib/components/CodeEditor.svelte';
	import EditorWorkbench from '$lib/components/EditorWorkbench.svelte';
	import ProxyConfigBuilder from '$lib/components/proxy/ProxyConfigBuilder.svelte';
	import CodeBlock from '$lib/components/CodeBlock.svelte';
	import Help from '$lib/components/Help.svelte';
	import TagEditor from '$lib/components/TagEditor.svelte';
	import { applyPendingTagColors } from '$lib/utils/tagColors.js';
	import Select from '$lib/components/Select.svelte';
	import Button from '$lib/components/Button.svelte';
	import ListInput from '$lib/components/ListInput.svelte';
	import Checkbox from '$lib/components/Checkbox.svelte';
	import Alert from '$lib/components/Alert.svelte';
	import Field from '$lib/components/Field.svelte';
	import AllowDenyRules from '$lib/components/AllowDenyRules.svelte';
	import AssetSettings from '$lib/components/AssetSettings.svelte';
	import { emptyAssetMeta, hasAssetMeta, assetMetaErrors, hasErrors, listYaml, assetsYaml, parseAssetMeta, pickVarName, scalarBool, listKinds, usedListPackages, fetchListPackage, isListPick } from '$lib/utils/assetMeta.js';
	import { fillPreview } from '$lib/utils/pcVariables.js';
	import { compareSemver } from '$lib/utils/semver.js';
	import { bumpPatch, decodeText, mimeFor, yamlStr, unquoteYamlStr, b64text, MAX_FILE_BYTES, assetFolder, assetRef, copyRef, sanitizeAssetPath } from '$lib/utils/authoring.js';

	let editingFrom = $state(''); // ns/name/version this is a new version of

	// Page and email starter content uses the real Phishing Club template variables
	// ({{.BaseURL}} base path, {{.URL}} phishing link, {{.Tracker}}, {{.FirstName}}),
	// filled per recipient at send. @@VAR@@ is the separate install time slot layer,
	// only for genuine environment or secret values (used by the config types below).
	const HTML_DEFAULT =
		'<html>\n  <body>\n    <form method="POST" action="{{.BaseURL}}">\n      <input name="email" value="{{.Email}}" />\n      <input name="password" type="password" />\n      <button type="submit">Sign in</button>\n    </form>\n  </body>\n</html>';
	// the script starter mirrors Phishing Club's own script editor so an author sees the
	// same example and API hints (the goja globals) there and here.
	const JS_DEFAULT = `// Runs when a subscribed campaign event fires.
// Available: event, http.fetch, encode, decode, hash, hmac, jwt, random, log, info, emitEvent, stop
// (encode/decode/hash/hmac/jwt/random are the data transform toolkit)
log('event received', { name: event.name });

// event.data holds the submitted form fields on a submitted_data event.
// Read whatever fields your landing page posts:
var username = event.data && event.data.username;
if (username) {
	info('captured a submission', { username: username });
}

// Example: forward the submitted data to an external service (set a real URL)
// const res = http.fetch('https://your-endpoint.test/hook', {
//   method: 'POST',
//   headers: { 'Content-Type': 'application/json' },
//   body: encode.json({ event: event.name, email: event.email, data: event.data })
// });
// const parsed = decode.json(res.body);
// log('forwarded', { status: res.status, id: parsed.id });
`;
	const PROXY_DEFAULT =
		'version: "0.0"\n"@@TARGET_DOMAIN@@":\n  to: https://login.microsoftonline.com\n';
	const RB_DEFAULT =
		'// Remote browser automation. `page` drives a real Chrome session.\nconst target = "@@TARGET_DOMAIN@@";\nawait page.goto("https://" + target + "/");\n';
	// a domain serves a flat landing page at /, so its starter is a plain site homepage
	// rather than the login form the page type starts with.
	const DOMAIN_DEFAULT =
		'<html>\n  <body>\n    <h1>Welcome</h1>\n    <p>This site is under maintenance.</p>\n  </body>\n</html>';
	const KNOWN_DEFAULTS = [HTML_DEFAULT, JS_DEFAULT, PROXY_DEFAULT, RB_DEFAULT, DOMAIN_DEFAULT];
	function bodyDefaultFor(type) {
		if (type === 'script') return JS_DEFAULT;
		if (type === 'proxy') return PROXY_DEFAULT;
		if (type === 'remotebrowser') return RB_DEFAULT;
		if (type === 'domain') return DOMAIN_DEFAULT;
		return HTML_DEFAULT;
	}

	let namespaces = $state([]);
	// options for the identity bar dropdowns, in the same order the native selects used.
	const nsOptions = $derived(namespaces.map((ns) => ({ value: ns.name, label: ns.name })));
	const typeOptions = [
		{ value: 'page', label: 'Landing page', group: 'Email & web' },
		{ value: 'email', label: 'Email', group: 'Email & web' },
		{ value: 'domain', label: 'Domain site', group: 'Email & web' },
		{ value: 'script', label: 'Script', group: 'Automation & config' },
		{ value: 'proxy', label: 'Proxy', group: 'Automation & config' },
		{ value: 'remotebrowser', label: 'Remote browser', group: 'Automation & config' },
		{ value: 'allowdeny', label: 'Allow / deny list', group: 'Automation & config' },
		{ value: 'smtp', label: 'SMTP configuration', group: 'Automation & config' },
		{ value: 'webhook', label: 'Webhook', group: 'Automation & config' },
		{ value: 'oauthprovider', label: 'OAuth provider', group: 'Automation & config' },
		{ value: 'apisender', label: 'API sender', group: 'Automation & config' },
		{ value: 'asset', label: 'Asset bundle', group: 'Files & templates' },
		{ value: 'attachment', label: 'Attachment', group: 'Files & templates' },
		{ value: 'reporttemplate', label: 'Report template', group: 'Files & templates' }
	];
	let form = $state({
		namespace: '',
		name: '',
		type: 'page',
		version: '1.0.0',
		title: '',
		description: '',
		tags: '',
		subject: '',
		from: '', // the From header the recipient sees
		envelopeFrom: '', // the envelope sender (MAIL FROM); defaults to From when left blank
		addTrackingPixel: true, // email: embed the open tracking pixel
		html: HTML_DEFAULT,
		startURL: 'https://@@TARGET_DOMAIN@@/login', // proxy start URL
		proxyDescription: '', // proxy: operator facing description
		rbMode: 'local', // remote browser mode
		rbRemote: '', // remote browser: DevTools WS endpoint, used when mode is remote
		rbProxy: '', // remote browser (local mode): upstream proxy, e.g. socks5://127.0.0.1:1080
		rbHeadless: true, // remote browser (local mode): run Chrome headless
		rbTimeoutMin: 5, // remote browser: session timeout in minutes (shipped as milliseconds)
		rbLang: '', // remote browser (local mode): BCP-47 locale, e.g. en-US
		rbFlags: '', // remote browser (local mode): extra Chrome flags, one per line
		rbDescription: '', // remote browser: operator facing description
		// domain (flat site): the landing page served at / lives in form.html; the 404 page
		// and the redirect/host-website options live here.
		notFound: '<html>\n  <body>\n    <h1>Not found</h1>\n  </body>\n</html>',
		domainType: 'regular', // domain: regular (hosts content) or proxy (routes to a proxy)
		proxyTargetDomain: '', // domain (proxy type): the real upstream domain
		domainTLS: 'managed', // domain TLS mode: managed | selfsigned | own
		ownTLSKey: '', // domain (own TLS): PEM private key
		ownTLSPem: '', // domain (own TLS): PEM certificate chain
		redirectURL: '', // domain: if set, the domain 301-redirects here instead of serving content
		hostWebsite: true, // domain: serve the landing page and 404, rather than a bare 404
		training: false, // report template: a training template vs a normal report
		// attachment fields
		attDescription: '',
		attEmbedded: false,
		attCalendar: false,
		// allow deny list fields
		allowed: true,
		cidrs: '',
		countryCodes: '',
		asns: '',
		headerRules: [], // [{keyRegex, valueRegex}] header match rules (phishingclub format)
		ja4: '',
		// smtp configuration fields
		smtpHost: '',
		smtpPort: 587,
		smtpUsername: '',
		smtpPassword: '',
		smtpIgnoreCert: false,
		smtpHelo: '',
		smtpHeaders: [], // [{key, value}] custom headers
		// webhook fields
		webhookUrl: '',
		webhookSecret: '',
		// oauth provider fields
		oauthAuthURL: '',
		oauthTokenURL: '',
		oauthScopes: '',
		oauthClientID: '',
		oauthClientSecret: '',
		// api sender fields
		apiRequestMethod: 'POST',
		apiRequestURL: '',
		apiRequestHeaders: [], // [{key, value}] request headers
		apiRequestBody: '',
		apiExpectedStatus: 200,
		apiResponseHeaders: [], // [{key, value}] expected response headers
		apiExpectedBody: '',
		apiKey: '',
		apiOAuthMode: 'none', // none | own | name
		apiOAuthName: '' // referenced provider name or a @@VAR@@ when mode is name
	});
	let assets = $state([]); // {filename, base64, name, description, contentType, headers, allowDeny}
	// the allow / deny packages the assets can use lists from: picked in an asset's
	// settings or loaded from the dependencies of the version being edited. each is
	// { id, namespace, name, title, lists: [{ name, allowed }] }. an allow / deny
	// package edits its own one list in form.
	let listPkgs = $state([]);
	// the installer pick variables named in asset lists, mapped to their pick
	// kind.
	let listPicks = $state({});
	// which assets have their settings panel open, by asset path
	let metaOpen = $state({});
	// email attachments: files shipped under content/<folder>/ and linked to the
	// email on install.
	let emailAttachments = $state([]);
	let previewFilename = $state(''); // an uploaded image marked as the package preview
	let varCfg = $state({}); // name -> {type, required, default}
	let tagColors = $state({}); // tag name -> color token, seeded from api.tags.list()
	let pendingTagColors = $state({}); // colors chosen for tags no package carries yet, stored after publish
	let showSmtpPassword = $state(false); // reveal the SMTP password field in plaintext
	let showOauthClientSecret = $state(false); // reveal the OAuth client secret in plaintext
	let showApiKey = $state(false); // reveal the API sender API key in plaintext

	const isImageName = (fn) => mimeFor(fn).startsWith('image/');
	// toggle an uploaded image as the package preview thumbnail
	function setPreview(fn) {
		previewFilename = previewFilename === fn ? '' : fn;
	}

	let busy = $state(false);
	let nsLoaded = $state(false); // namespaces fetched yet, to gate the empty state notice
	let nsError = $state(''); // set when the namespace load failed (vs genuinely none)
	// when on, the preview replaces @@VAR@@ tokens with a sample value so the author
	// sees roughly what a recipient sees, instead of raw tokens.
	let previewFill = $state(false);

	// unsaved work protection: a snapshot of the form taken once it is ready (after
	// any seed from an existing package) is the baseline. the form is dirty when it
	// no longer matches, and a dirty form warns before the operator navigates away
	// or closes the tab so a half written email or page is never lost.
	let baseline = $state('');
	let published = $state(false);
	let leaving = $state(false);
	function snapshot() {
		// the whole form plus the heavy side state (assets by name+size and the marked
		// preview), so every field is covered without enumerating.
		return JSON.stringify({
			form,
			assets: assets.map((a) => [a.filename, a.base64.length, a.name, a.description, a.contentType, JSON.stringify(a.headers), JSON.stringify(a.allowDeny)].join(':')),
			listPkgs: listPkgs.map((p) => p.id),
			attachments: emailAttachments.map(
				(a) => [a.filename, a.base64.length, a.name, a.description, a.embedded, a.calendar, a.inline].join(':')
			),
			preview: previewFilename
		});
	}
	const dirty = $derived.by(() => baseline !== '' && !published && snapshot() !== baseline);

	// page, email and report template carry an HTML body with a live preview; an
	// asset bundle is just files with no body; a script is a single JS file; an
	// allow deny list is a set of rule fields with no body.
	const isReportTemplate = $derived(form.type === 'reporttemplate');
	const isDomain = $derived(form.type === 'domain');
	const isHtml = $derived(form.type === 'page' || form.type === 'email' || isReportTemplate || isDomain);
	const isAsset = $derived(form.type === 'asset');
	const isScript = $derived(form.type === 'script');
	const isAllowDeny = $derived(form.type === 'allowdeny');
	const isProxy = $derived(form.type === 'proxy');
	const isRemoteBrowser = $derived(form.type === 'remotebrowser');
	const isAttachment = $derived(form.type === 'attachment');
	const isSMTP = $derived(form.type === 'smtp');
	const isWebhook = $derived(form.type === 'webhook');
	const isOauthProvider = $derived(form.type === 'oauthprovider');
	const isApiSender = $derived(form.type === 'apisender');
	// types that carry no body file and no uploaded assets: their whole definition is in
	// data.yaml. (allow/deny is handled separately as it predates this group.)
	const isConfigOnly = $derived(isSMTP || isWebhook || isOauthProvider || isApiSender);
	// types whose shipped assets can carry settings (content type, headers, allow deny
	// lists).
	const supportsAssetMeta = $derived(isAsset || isHtml);
	const listKnown = $derived(listKinds(listPkgs, form.namespace));
	// every list name the assets use, and the variables the content uses as plain
	// values outside the asset lists, which an installer pick may not share.
	const usedListNames = $derived(new Set(assets.flatMap((a) => a.allowDeny)));
	const plainVars = $derived.by(() => {
		const body = usesBodyEditor ? form.html : '';
		const text = isAsset ? entityYaml() : `${body} ${isDomain ? form.notFound : ''} ${entityYaml()} ${form.subject} ${form.from} ${form.envelopeFrom}`;
		return new Set([...text.matchAll(/@@([A-Z_][A-Z0-9_]{0,63})@@/g)].map((m) => m[1]));
	});
	const assetErrs = $derived(supportsAssetMeta ? assets.map((a) => assetMetaErrors(a, listKnown, listPicks, plainVars)) : []);
	const assetMetaValid = $derived(!assetErrs.some(hasErrors));
	// the package depends on every list package its assets use, so Phishing Club
	// installs the lists with it. removing the last use drops the dependency.
	const listDeps = $derived(supportsAssetMeta ? usedListPackages(assets, listPkgs, form.namespace) : []);
	// installer pick variables named in an asset's allow deny lists: each asks the
	// installer to pick one of their own allow deny lists.
	const allowDenyPicks = $derived(
		new Set(supportsAssetMeta ? assets.flatMap((a) => a.allowDeny.map(pickVarName)).filter(Boolean) : [])
	);
	// types whose definition carries content settings beyond the body, shown on the
	// Settings tab. other types have none, so that tab is not rendered for them.
	const hasSettings = $derived(form.type === 'email' || isProxy || isDomain || isRemoteBrowser || isReportTemplate);


	// swap the starter body to the new type's starter, but only while the body is
	// still an untouched starter so a user's work is never discarded.
	let lastType = form.type;
	$effect(() => {
		if (form.type === lastType) return;
		if (KNOWN_DEFAULTS.includes(form.html)) form.html = bodyDefaultFor(form.type);
		lastType = form.type;
	});

	// slugify turns a friendly display name into the lowercase slug used as the
	// package address: lowercase, non slug chars to dashes, collapse and trim dashes.
	function slugify(s) {
		return s
			.toLowerCase()
			.replace(/[^a-z0-9]+/g, '-')
			.replace(/^-+|-+$/g, '');
	}
	// the slug follows the display name until the operator edits it directly.
	let slugLocked = $state(false);
	function onDisplayNameInput() {
		if (!slugLocked) form.name = slugify(form.title);
	}

	// publish guards: a package name is a lowercase slug, the version is semver,
	// and the package must carry content.
	const nameValid = $derived(/^[a-z0-9][a-z0-9-]*$/.test(form.name));
	// assets are foldered under the package namespace and name, so the package must be
	// named before any file is added or the folder would be empty.
	const canAddAssets = $derived(!!form.namespace && nameValid);
	const versionValid = $derived(/^\d+\.\d+\.\d+$/.test(form.version));
	// when the form targets a package that already exists, fetch its versions so the
	// version field can warn before a publish that would be rejected (409) or would
	// not become the latest. the fetch goes straight to the server, debounced while the
	// address is typed: a package that does not exist returns an error and leaves the
	// list empty, so this needs no full package list and works past the list page cap.
	let existingVersions = $state([]);
	$effect(() => {
		const ns = form.namespace;
		const name = form.name;
		if (!ns || !nameValid) {
			existingVersions = [];
			return;
		}
		let cancelled = false;
		const t = setTimeout(() => {
			api.packages.detail(ns, name).then((res) => {
				if (!cancelled) existingVersions = res.ok ? (res.data.versions || []).map((v) => v.version) : [];
			});
		}, 300);
		return () => {
			cancelled = true;
			clearTimeout(t);
		};
	});
	const versionExists = $derived(existingVersions.includes(form.version));
	// the highest existing version, so the form can tell the operator whether the one
	// they typed will become the latest or just sit below it.
	const highestExisting = $derived(
		existingVersions.length ? existingVersions.reduce((a, b) => (compareSemver(a, b) >= 0 ? a : b)) : ''
	);
	// a lower or equal version is allowed to publish (back publishing a patch for an
	// old line is valid), but it will not be served as latest, so warn without blocking.
	const versionNotHigher = $derived(
		versionValid && !versionExists && !!highestExisting && compareSemver(form.version, highestExisting) < 0
	);
	// a fresh new package attempt whose address already exists: publishing adds a
	// version to that package rather than creating a new one. not an error (it is how
	// you add a version by hand), but worth saying so the operator is not surprised.
	const addsToExistingPackage = $derived(!editingFrom && existingVersions.length > 0);
	const hasContent = $derived.by(() => {
		if (isAsset || isAttachment) return assets.length > 0;
		if (isAllowDeny)
			return (
				[form.cidrs, form.countryCodes, form.asns, form.ja4].some((s) => s.trim().length > 0) ||
				form.headerRules.some((h) => h.keyRegex.trim() || h.valueRegex.trim())
			);
		if (isProxy) return form.html.trim().length > 0 && form.startURL.trim().length > 0;
		if (isDomain)
			// a proxy domain just needs its target; a redirect needs the URL; a hosting
			// domain needs a landing page and a 404 page.
			return (
				(form.domainType === 'proxy' && form.proxyTargetDomain.trim().length > 0) ||
				form.redirectURL.trim().length > 0 ||
				(form.hostWebsite && form.html.trim().length > 0 && form.notFound.trim().length > 0)
			);
		if (isSMTP) return form.smtpHost.trim().length > 0 && Number(form.smtpPort) > 0;
		if (isWebhook) return form.webhookUrl.trim().length > 0;
		if (isOauthProvider)
			return (
				form.oauthAuthURL.trim() &&
				form.oauthTokenURL.trim() &&
				form.oauthScopes.trim() &&
				form.oauthClientID.trim() &&
				form.oauthClientSecret.trim()
			);
		if (isApiSender) return form.apiRequestURL.trim() && form.apiRequestMethod && Number(form.apiExpectedStatus) > 0;
		return form.html.trim().length > 0;
	});
	// page/email/report/script/proxy/domain put text in the body editor; the other types
	// use their own fields.
	const usesBodyEditor = $derived(isHtml || isScript || isProxy || isRemoteBrowser);
	const canPublish = $derived(
		!!form.namespace && nameValid && versionValid && hasContent && !busy && !versionExists && assetMetaValid
	);
	// when seeded from an existing package, it stays a new version only while the
	// address is unchanged; changing the namespace or name publishes a separate
	// package seeded from the original (a clone), which is a valid way to start one.
	const isNewVersion = $derived(editingFrom === `${form.namespace}/${form.name}`);

	const heading = $derived(
		!editingFrom
			? 'New package'
			: isNewVersion
				? `New version of ${editingFrom}`
				: `New package from ${editingFrom}`
	);

	// a failed namespace load must not look like "no namespaces exist", which would
	// wrongly tell an operator to create one first. track the error and offer a retry.
	async function loadNamespaces() {
		nsError = '';
		const res = await api.namespaces.list({ perPage: 200 });
		if (res.ok) {
			namespaces = res.data.namespaces;
			if (namespaces.length) form.namespace = namespaces[0].name;
		} else {
			nsError = res.error || 'Could not load namespaces';
		}
		nsLoaded = true;
	}
	onMount(async () => {
		await loadNamespaces();
		const tr = await api.tags.list();
		if (tr.ok) tagColors = Object.fromEntries((tr.data.tags || []).map((t) => [t.name, t.color || '']));
		const draft = $page.url.searchParams.get('draft');
		const from = $page.url.searchParams.get('from');
		if (draft) {
			const [dns, dname] = draft.split('/');
			if (dns && dname) await loadDraft(dns, dname);
		} else if (from) {
			await loadFrom(from);
		}
		baseline = snapshot();
	});

	// warn on a hard unload (tab close or reload) while there is unsaved work; the
	// browser shows its own native prompt once returnValue is set.
	onMount(() => {
		const onBeforeUnload = (e) => {
			if (dirty) {
				e.preventDefault();
				e.returnValue = '';
			}
		};
		window.addEventListener('beforeunload', onBeforeUnload);
		return () => window.removeEventListener('beforeunload', onBeforeUnload);
	});

	// Ctrl/Cmd+S saves a draft, matching the editor's usual save shortcut. Publishing
	// is a separate, explicit action on the Publish button so saving never publishes.
	onMount(() => {
		const onKey = (e) => {
			if ((e.ctrlKey || e.metaKey) && (e.key === 's' || e.key === 'S')) {
				e.preventDefault();
				saveDraft();
			}
		};
		window.addEventListener('keydown', onKey);
		return () => window.removeEventListener('keydown', onKey);
	});

	// warn on an in app navigation away from unsaved work. beforeNavigate is
	// synchronous, so cancel first, ask with the app confirm dialog, and resume the
	// same navigation only if the operator chooses to discard.
	beforeNavigate((nav) => {
		if (leaving || !dirty || nav.willUnload || !nav.to) return;
		nav.cancel();
		askConfirm({
			title: 'Discard unsaved package?',
			body: 'This package has not been published. Leave now and lose your changes?',
			confirmLabel: 'Discard'
		}).then((ok) => {
			if (ok) {
				leaving = true;
				goto(nav.to.url);
			}
		});
	});

	// load an existing version's content into the wizard to publish a new version
	async function loadFrom(from) {
		const [ns, name, version] = from.split('/');
		const res = await api.packages.source(ns, name, version);
		if (!res.ok) {
			toast('Could not load that package to edit', 'error');
			return;
		}
		applySource(ns, name, res.data, { bumpVersion: true, markEditing: true });
		await loadListPackages(res.data.dependencies);
	}

	// loadDraft reopens a saved draft (the same author payload) exactly as saved, so
	// publishing continues from where it was left: the version is kept, not bumped,
	// and the address stays editable since the package may not exist yet.
	async function loadDraft(ns, name) {
		const res = await api.drafts.get(ns, name);
		if (!res.ok) {
			toast('Could not load that draft', 'error');
			return;
		}
		applySource(ns, name, res.data, { bumpVersion: false, markEditing: false });
		await loadListPackages(res.data.dependencies);
	}

	// loadListPackages reads the lists of each allow / deny package a loaded version
	// depends on, so its assets show their lists and keep depending on them. A
	// package that cannot be read is kept with its error, so the asset can say
	// so and offer a retry.
	async function loadListPackages(deps) {
		const found = await Promise.all(
			(deps || []).map(async (d) => {
				const [dns, dname] = String(d.id || '').split('/');
				if (!dns || !dname) return null;
				return { ...(await fetchListPackage(api, d.id)), fromDeps: true };
			})
		);
		listPkgs = found.filter(Boolean);
	}

	// drop list packages no asset uses any more, so they are not kept as
	// dependencies or checked for name clashes. one that could not be read stays,
	// since its lists are not known.
	$effect(() => {
		const next = listPkgs.filter((p) => p.error || (p.lists || []).some((l) => usedListNames.has(l.name)));
		if (next.length !== listPkgs.length) listPkgs = next;
	});

	// applySource populates the form from a published package source or a draft body,
	// which share one shape. bumpVersion bumps the patch for a new version; markEditing
	// fixes the address as an existing package.
	function applySource(ns, name, src, { bumpVersion = true, markEditing = true } = {}) {
		if (markEditing) editingFrom = `${ns}/${name}`;
		form.namespace = ns;
		form.name = name;
		// the address is fixed when continuing an existing package, so the display
		// name must not rewrite the slug.
		slugLocked = true;
		form.type = [
			'email',
			'page',
			'asset',
			'script',
			'reporttemplate',
			'allowdeny',
			'proxy',
			'remotebrowser',
			'attachment',
			'domain',
			'smtp',
			'webhook',
			'oauthprovider',
			'apisender'
		].includes(src.type)
			? src.type
			: 'page';
		lastType = form.type; // do not let the starter swap effect fire on a loaded body
		form.version = bumpVersion ? bumpPatch(src.version) : src.version || form.version;
		let dataYaml = '';
		const imgs = [];
		const pendingAttachments = []; // email: content/ files that are not the body
		for (const f of src.files || []) {
			// data.yaml first so a proxy.yaml config body is not mistaken for it
			if (/\/data\.yaml$/i.test(f.path)) dataYaml = decodeText(f.content);
			else if (form.type === 'attachment' && f.path.startsWith('content/')) {
				// the attachment payload lives under content/<folder>/<filename>
				assets = [{ filename: f.path.split('/').pop(), base64: f.content }];
			} else if (form.type === 'email' && f.path.startsWith('content/') && !/\/email\.html$/i.test(f.path)) {
				// every content/ file other than email.html is an attachment
				pendingAttachments.push({ filename: f.path.split('/').pop(), base64: f.content });
			} else if (form.type === 'domain' && /\/notfound\.html$/i.test(f.path)) {
				// a domain ships two html bodies: the landing page and the 404 page.
				form.notFound = decodeText(f.content);
			} else if (form.type === 'domain' && /\/content\.html$/i.test(f.path)) {
				form.html = decodeText(f.content);
			} else if (f.path.startsWith('assets/')) imgs.push({ filename: f.path.slice(7), base64: f.content });
			// only a content/ file is the body; checked after assets/ so an asset named
			// *.html or *.js is kept as an asset, not dumped into the body.
			else if (/\.(html|js|ya?ml)$/i.test(f.path)) form.html = decodeText(f.content);
		}
		// the per asset settings, read with a YAML parser since their nested headers
		// would clash with the line helpers below.
		const meta = form.type === 'allowdeny' ? { assets: [] } : parseAssetMeta(dataYaml);
		if (form.type !== 'attachment')
			assets = imgs.map((a) => {
				const m = meta.assets.find((x) => x.path === a.filename);
				return { ...a, ...emptyAssetMeta(), ...(m ? { name: m.name, description: m.description, contentType: m.contentType, headers: m.headers, allowDeny: m.allowDeny } : {}) };
			});
		listPkgs = [];
		metaOpen = {};
		previewFilename = (src.preview || '').replace(/^assets\//, '');
		// undo yamlStr: strip a double quoted scalar and its escapes back to plain text.
		const unquote = unquoteYamlStr;
		const grab = (k) => {
			const m = dataYaml.match(new RegExp('^\\s*' + k + ':\\s*(.+)$', 'm'));
			return m ? unquote(m[1].trim()) : '';
		};
		// extract a yaml block scalar (key: |\n      line\n      line) into text
		const grabBlock = (k) => {
			const m = dataYaml.match(new RegExp('^\\s*' + k + ':\\s*\\|\\s*$', 'm'));
			if (!m) return '';
			const rest = dataYaml.slice(m.index + m[0].length).replace(/^\n/, '');
			const lines = [];
			for (const line of rest.split('\n')) {
				if (/^\s{6}\S/.test(line) || /^\s{6,}/.test(line)) lines.push(line.trim());
				else break;
			}
			return lines.join('\n');
		};
		// extract a yaml list (key:\n      - item\n      - item) into newline text
		const grabList = (k) => {
			const m = dataYaml.match(new RegExp('^\\s*' + k + ':\\s*$', 'm'));
			if (!m) return '';
			const rest = dataYaml.slice(m.index + m[0].length).replace(/^\n/, '');
			const lines = [];
			for (const line of rest.split('\n')) {
				const im = line.match(/^\s{6,}-\s*(.+)$/);
				if (im) lines.push(unquote(im[1].trim()));
				else break;
			}
			return lines.join('\n');
		};
		// extract a yaml list of two key objects (key:\n   - ka: va\n     kb: vb) into
		// [{ka, kb}], for the header rule and SMTP header lists.
		const grabPairs = (parent, ka, kb) => {
			const m = dataYaml.match(new RegExp('^\\s*' + parent + ':\\s*$', 'm'));
			if (!m) return [];
			const rest = dataYaml.slice(m.index + m[0].length).replace(/^\n/, '');
			const out = [];
			let cur = null;
			for (const line of rest.split('\n')) {
				const a = line.match(new RegExp('^\\s{6,}-\\s*' + ka + ':\\s*(.*)$'));
				const b = line.match(new RegExp('^\\s{6,}' + kb + ':\\s*(.*)$'));
				if (a) {
					cur = { [ka]: unquote(a[1].trim()), [kb]: '' };
					out.push(cur);
				} else if (b && cur) {
					cur[kb] = unquote(b[1].trim());
				} else if (line.trim() && !/^\s/.test(line)) break;
			}
			return out;
		};
		// extract the nested email attachments block: a list at indent 6 whose items
		// carry name/file/description/embedded/calendar/inline keys at indent 8.
		const grabAttachmentMeta = () => {
			const m = dataYaml.match(/^\s*attachments:\s*$/m);
			if (!m) return [];
			const rest = dataYaml.slice(m.index + m[0].length).replace(/^\n/, '');
			const out = [];
			let cur = null;
			for (const line of rest.split('\n')) {
				if (line.trim() === '') continue;
				if (!/^\s{6}/.test(line)) break;
				const start = line.match(/^\s{6}-\s*name:\s*(.*)$/);
				if (start) {
					cur = { name: unquote(start[1].trim()) };
					out.push(cur);
					continue;
				}
				const kv = line.match(/^\s{8}(\w+):\s*(.*)$/);
				if (!kv || !cur) continue;
				const v = kv[2].trim();
				if (kv[1] === 'file') cur.file = unquote(v);
				else if (kv[1] === 'description') cur.description = unquote(v);
				else if (kv[1] === 'embedded') cur.embedded = v === 'true';
				else if (kv[1] === 'calendar') cur.calendar = v === 'true';
				else if (kv[1] === 'inline') cur.inline = v === 'true';
			}
			return out;
		};
		form.title = grab('name') || name;
		form.description = src.description || '';
		form.tags = (src.tags || []).join(', ');
		if (form.type === 'proxy') {
			form.startURL = grab('startURL') || form.startURL;
			form.proxyDescription = grab('description');
		}
		if (form.type === 'remotebrowser') {
			form.rbMode = grab('mode') || form.rbMode;
			form.rbRemote = grab('remote');
			form.rbDescription = grab('description');
			const t = Number(grab('timeout'));
			if (t > 0) form.rbTimeoutMin = Math.round(t / 60000);
			form.rbProxy = grab('proxy');
			const hl = grab('headless');
			form.rbHeadless = hl === '' ? true : hl === 'true';
			form.rbLang = grab('lang');
			form.rbFlags = grabList('extraFlags');
		}
		if (form.type === 'domain') {
			form.domainType = grab('type') || 'regular';
			form.proxyTargetDomain = grab('proxyTargetDomain');
			const hw = grab('hostWebsite');
			form.hostWebsite = hw === '' ? true : hw === 'true';
			form.redirectURL = grab('redirectURL');
			form.domainTLS = grab('ownManagedTLS') === 'true' ? 'own' : grab('selfSignedTLS') === 'true' ? 'selfsigned' : 'managed';
			form.ownTLSKey = grab('ownManagedTLSKey');
			form.ownTLSPem = grab('ownManagedTLSPem');
		}
		if (form.type === 'reporttemplate') form.training = grab('isTraining') === 'true';
		if (form.type === 'email') {
			form.subject = grab('subject');
			form.from = grab('from');
			form.envelopeFrom = grab('envelope from');
			const tp = grab('addTrackingPixel');
			form.addTrackingPixel = tp === '' ? true : tp === 'true';
			const attMeta = grabAttachmentMeta();
			emailAttachments = pendingAttachments.map((p) => {
				const mm = attMeta.find((x) => x.file === p.filename) || {};
				return {
					filename: p.filename,
					base64: p.base64,
					name: mm.name || p.filename,
					description: mm.description || '',
					embedded: !!mm.embedded,
					calendar: !!mm.calendar,
					inline: !!mm.inline
				};
			});
		}
		if (form.type === 'allowdeny') {
			// read as Phishing Club reads it, so yes, on and the other spellings keep
			// their kind and a missing value is a deny list, as it installs.
			const rawAllowed = dataYaml.match(/^\s*allowed:[ \t]*(.*)$/m);
			form.allowed = (rawAllowed ? scalarBool(rawAllowed[1]) : false) ?? true;
			form.cidrs = grabBlock('cidrs');
			form.countryCodes = grabBlock('countryCodes');
			form.asns = grabBlock('asns');
			form.ja4 = grabBlock('ja4');
			form.headerRules = grabPairs('headers', 'keyRegex', 'valueRegex');
		}
		if (form.type === 'attachment') {
			form.attDescription = grab('description');
			form.attEmbedded = grab('embedded') === 'true';
			form.attCalendar = grab('calendar') === 'true';
		}
		if (form.type === 'smtp') {
			form.smtpHost = grab('host');
			const pt = Number(grab('port'));
			if (pt > 0) form.smtpPort = pt;
			form.smtpUsername = grab('username');
			form.smtpPassword = grab('password');
			form.smtpIgnoreCert = grab('ignoreCertErrors') === 'true';
			form.smtpHelo = grab('helo');
			form.smtpHeaders = grabPairs('headers', 'key', 'value');
		}
		if (form.type === 'webhook') {
			form.webhookUrl = grab('url');
			form.webhookSecret = grab('secret');
		}
		if (form.type === 'oauthprovider') {
			form.oauthAuthURL = grab('authURL');
			form.oauthTokenURL = grab('tokenURL');
			form.oauthScopes = grab('scopes');
			form.oauthClientID = grab('clientID');
			form.oauthClientSecret = grab('clientSecret');
		}
		if (form.type === 'apisender') {
			form.apiRequestMethod = grab('requestMethod') || 'POST';
			form.apiRequestURL = grab('requestURL');
			form.apiRequestHeaders = grabPairs('requestHeaders', 'key', 'value');
			form.apiRequestBody = grab('requestBody');
			form.apiExpectedStatus = Number(grab('expectedResponseStatusCode')) || 200;
			form.apiResponseHeaders = grabPairs('expectedResponseHeaders', 'key', 'value');
			form.apiExpectedBody = grab('expectedResponseBody');
			form.apiKey = grab('apiKey');
			// the oauthProvider field is the sentinel for the installer's own provider, a
			// referenced provider name, or absent.
			const op = grab('oauthProvider');
			if (op === '@@OWN_OAUTH_PROVIDER@@') {
				form.apiOAuthMode = 'own';
			} else if (op) {
				form.apiOAuthMode = 'name';
				form.apiOAuthName = op;
			} else {
				form.apiOAuthMode = 'none';
			}
		}
		const cfg = {};
		const picks = {};
		for (const v of src.variables || []) {
			cfg[v.name] = { type: v.type, required: v.required, default: v.default ?? '', description: v.description ?? '', options: v.options ?? [] };
			if (isListPick(v.pick)) picks[v.name] = v.pick;
		}
		listPicks = picks;
		for (const name in cfg) {
			if (cfg[name].type === 'secret') {
				cfg[name].required = true;
				cfg[name].default = '';
			}
		}
		varCfg = cfg;
	}

	function folder() {
		return (form.name || 'package').trim();
	}
	// dataYaml is the whole content folder data.yaml: the entity block for the type,
	// then the per asset settings.
	function dataYaml() {
		let y = entityYaml();
		if (supportsAssetMeta) y += assetsYaml(assets);
		return y;
	}
	function entityYaml() {
		const rawTitle = form.title || form.name || 'Untitled';
		const title = yamlStr(rawTitle);
		// an asset bundle declares no entity; its data.yaml carries the name and the
		// asset settings only.
		if (form.type === 'asset') return `name: ${title}\n`;
		if (form.type === 'email') {
			let y =
				`name: ${title}\nemails:\n  - name: ${title}\n    file: email.html\n` +
				`    subject: ${yamlStr(form.subject)}\n    from: ${yamlStr(form.from)}\n    envelope from: ${yamlStr(form.envelopeFrom.trim() || form.from)}\n` +
				`    addTrackingPixel: ${form.addTrackingPixel}\n`;
			if (emailAttachments.length) {
				y += `    attachments:\n`;
				for (const a of emailAttachments) {
					y += `      - name: ${yamlStr(a.name || a.filename)}\n        file: ${yamlStr(a.filename)}\n`;
					if (a.description && a.description.trim()) y += `        description: ${yamlStr(a.description.trim())}\n`;
					y += `        embedded: ${!!a.embedded}\n        calendar: ${isIcs(a.filename) && !!a.calendar}\n        inline: ${!!a.inline}\n`;
				}
			}
			return y;
		}
		if (form.type === 'script') {
			return `name: ${title}\nscripts:\n  - name: ${title}\n    file: script.js\n`;
		}
		if (form.type === 'reporttemplate') {
			return `name: ${title}\nreportTemplates:\n  - file: report.html\n    isTraining: ${form.training}\n`;
		}
		if (form.type === 'proxy') {
			let y = `name: ${title}\nproxies:\n  - name: ${title}\n    startURL: ${yamlStr(form.startURL)}\n    file: proxy.yaml\n`;
			if (form.proxyDescription.trim()) y += `    description: ${yamlStr(form.proxyDescription.trim())}\n`;
			return y;
		}
		if (form.type === 'remotebrowser') {
			let y = `name: ${title}\nremoteBrowsers:\n  - name: ${title}\n    file: browser.js\n    mode: ${yamlStr(form.rbMode)}\n`;
			if (form.rbDescription.trim()) y += `    description: ${yamlStr(form.rbDescription.trim())}\n`;
			// timeout ships as milliseconds; the form edits whole minutes.
			const timeoutMs = Math.max(0, Math.round(Number(form.rbTimeoutMin) || 0)) * 60000;
			if (timeoutMs > 0) y += `    timeout: ${timeoutMs}\n`;
			if (form.rbMode === 'remote') {
				// the remote endpoint only applies to remote mode (connect to a Chrome you launched).
				y += `    remote: ${yamlStr(form.rbRemote)}\n`;
			} else {
				// local mode runs Chrome on the server, so these only apply there.
				if (form.rbProxy.trim()) y += `    proxy: ${yamlStr(form.rbProxy.trim())}\n`;
				y += `    headless: ${form.rbHeadless}\n`;
				if (form.rbLang.trim()) y += `    lang: ${yamlStr(form.rbLang.trim())}\n`;
				const flags = form.rbFlags.split('\n').map((f) => f.trim()).filter(Boolean);
				if (flags.length) y += `    extraFlags:\n` + flags.map((f) => `      - ${yamlStr(f)}`).join('\n') + '\n';
			}
			return y;
		}
		if (form.type === 'attachment') {
			const fn = assets[0]?.filename || 'file';
			return (
				`name: ${title}\nattachments:\n  - name: ${title}\n    file: ${yamlStr(fn)}\n` +
				`    description: ${yamlStr(form.attDescription)}\n    embedded: ${form.attEmbedded}\n    calendar: ${form.attCalendar}\n`
			);
		}
		if (form.type === 'allowdeny') {
			// header match rules are phishingclub's keyRegex/valueRegex pairs, not plain lines.
			return `name: ${title}\nallowDenies:\n` + listYaml(rawTitle, form);
		}
		if (form.type === 'domain') {
			// the domain entity name is the real domain, which the installer supplies, so it
			// uses a @@DOMAIN@@ variable rather than the package name. the package keeps its
			// own name as the data.yaml name for display.
			let y = `name: ${title}\ndomains:\n  - name: ${yamlStr('@@DOMAIN@@')}\n    type: ${yamlStr(form.domainType)}\n`;
			if (form.domainType === 'proxy') {
				// a proxy domain routes to a real upstream rather than serving its own content.
				y += `    proxyTargetDomain: ${yamlStr(form.proxyTargetDomain.trim())}\n`;
			} else {
				y += `    hostWebsite: ${form.hostWebsite}\n`;
				// TLS mode, mirroring phishingclub's three booleans (one of them true).
				y += `    managedTLS: ${form.domainTLS === 'managed'}\n`;
				y += `    selfSignedTLS: ${form.domainTLS === 'selfsigned'}\n`;
				y += `    ownManagedTLS: ${form.domainTLS === 'own'}\n`;
				if (form.domainTLS === 'own') {
					if (form.ownTLSKey.trim()) y += `    ownManagedTLSKey: ${yamlStr(form.ownTLSKey.trim())}\n`;
					if (form.ownTLSPem.trim()) y += `    ownManagedTLSPem: ${yamlStr(form.ownTLSPem.trim())}\n`;
				}
				// a redirect takes precedence over served content, so a redirecting domain ships
				// neither the landing page nor the 404 page.
				if (form.redirectURL.trim()) {
					y += `    redirectURL: ${yamlStr(form.redirectURL.trim())}\n`;
				} else if (form.hostWebsite) {
					y += `    content: content.html\n    notFound: notfound.html\n`;
				}
			}
			return y;
		}
		if (form.type === 'smtp') {
			let y =
				`name: ${title}\nsmtpConfigurations:\n  - name: ${title}\n` +
				`    host: ${yamlStr(form.smtpHost.trim())}\n    port: ${Math.max(0, Math.round(Number(form.smtpPort) || 0))}\n` +
				`    username: ${yamlStr(form.smtpUsername)}\n    password: ${yamlStr(form.smtpPassword)}\n` +
				`    ignoreCertErrors: ${form.smtpIgnoreCert}\n`;
			if (form.smtpHelo.trim()) y += `    helo: ${yamlStr(form.smtpHelo.trim())}\n`;
			const hs = form.smtpHeaders.filter((h) => h.key.trim());
			if (hs.length)
				y += `    headers:\n` + hs.map((h) => `      - key: ${yamlStr(h.key)}\n        value: ${yamlStr(h.value)}`).join('\n') + '\n';
			return y;
		}
		if (form.type === 'webhook') {
			let y = `name: ${title}\nwebhooks:\n  - name: ${title}\n    url: ${yamlStr(form.webhookUrl.trim())}\n`;
			if (form.webhookSecret.trim()) y += `    secret: ${yamlStr(form.webhookSecret.trim())}\n`;
			return y;
		}
		if (form.type === 'oauthprovider') {
			return (
				`name: ${title}\noauthProviders:\n  - name: ${title}\n` +
				`    authURL: ${yamlStr(form.oauthAuthURL.trim())}\n` +
				`    tokenURL: ${yamlStr(form.oauthTokenURL.trim())}\n` +
				`    scopes: ${yamlStr(form.oauthScopes.trim())}\n` +
				`    clientID: ${yamlStr(form.oauthClientID.trim())}\n` +
				`    clientSecret: ${yamlStr(form.oauthClientSecret.trim())}\n`
			);
		}
		if (form.type === 'apisender') {
			let y =
				`name: ${title}\napiSenders:\n  - name: ${title}\n` +
				`    requestMethod: ${yamlStr(form.apiRequestMethod)}\n` +
				`    requestURL: ${yamlStr(form.apiRequestURL.trim())}\n`;
			const rh = form.apiRequestHeaders.filter((h) => h.key.trim());
			if (rh.length)
				y += `    requestHeaders:\n` + rh.map((h) => `      - key: ${yamlStr(h.key)}\n        value: ${yamlStr(h.value)}`).join('\n') + '\n';
			if (form.apiRequestBody.trim()) y += `    requestBody: ${yamlStr(form.apiRequestBody)}\n`;
			const code = Math.max(0, Math.round(Number(form.apiExpectedStatus) || 0));
			if (code > 0) y += `    expectedResponseStatusCode: ${code}\n`;
			const eh = form.apiResponseHeaders.filter((h) => h.key.trim());
			if (eh.length)
				y += `    expectedResponseHeaders:\n` + eh.map((h) => `      - key: ${yamlStr(h.key)}\n        value: ${yamlStr(h.value)}`).join('\n') + '\n';
			if (form.apiExpectedBody.trim()) y += `    expectedResponseBody: ${yamlStr(form.apiExpectedBody)}\n`;
			if (form.apiKey.trim()) y += `    apiKey: ${yamlStr(form.apiKey.trim())}\n`;
			if (form.apiOAuthMode === 'own') y += `    oauthProvider: ${yamlStr('@@OWN_OAUTH_PROVIDER@@')}\n`;
			else if (form.apiOAuthMode === 'name' && form.apiOAuthName.trim()) y += `    oauthProvider: ${yamlStr(form.apiOAuthName.trim())}\n`;
			return y;
		}
		return `name: ${title}\npages:\n  - name: ${title}\n    file: index.html\n`;
	}
	function contentFileName() {
		if (form.type === 'script') return 'script.js';
		if (form.type === 'reporttemplate') return 'report.html';
		if (form.type === 'proxy') return 'proxy.yaml';
		if (form.type === 'remotebrowser') return 'browser.js';
		if (form.type === 'domain') return 'content.html';
		return form.type === 'email' ? 'email.html' : 'index.html';
	}

	// change a variable's type; a secret is forced required and loses any default
	function setVarType(name, type) {
		const cfg = varCfg[name];
		if (!cfg) return;
		cfg.type = type;
		if (type === 'secret') {
			cfg.required = true;
			cfg.default = '';
		}
	}

	// a stand in value for a variable in the sample preview: its declared default
	// if set, otherwise something plausible for its type.
	function sampleValue(name) {
		const cfg = varCfg[name] || {};
		if (cfg.type === 'secret') return '********';
		if (cfg.default) return cfg.default;
		if (cfg.type === 'domain') return 'example.com';
		if (cfg.type === 'url') return 'https://example.com';
		if (cfg.type === 'enum') return (cfg.options && cfg.options[0]) || '';
		// a text variable has no declared shape, so guess a readable sample from
		// common name hints, falling back to the humanized name.
		if (/DOMAIN|HOST/.test(name)) return 'example.com';
		if (/URL|LINK/.test(name)) return 'https://example.com';
		if (/EMAIL/.test(name)) return 'user@example.com';
		if (/FIRST.?NAME/.test(name)) return 'Alex';
		if (/LAST.?NAME|SURNAME/.test(name)) return 'Taylor';
		if (/NAME/.test(name)) return 'Alex Taylor';
		return name.toLowerCase().replace(/_/g, ' ');
	}

	// send time Go template variables Phishing Club fills per recipient at send. These
	// are what a recipient actually sees, so the sample preview resolves the common ones
	// to readable stand ins. Unknown vars and function calls like {{base64 .URL}} are
	// left as tokens rather than guessed.
	// send time {{.Var}} tokens and {{func ...}} calls -> sample values for the preview
	// (the full Phishing Club variable set + functions live in the shared catalog).
	const fillSendTime = fillPreview;
	// fill both variable layers in a plain string (a subject or sender) when the sample
	// toggle is on, so the email preview header matches the filled body.
	function fillString(s) {
		if (!previewFill) return s;
		return fillSendTime(String(s || '').replace(/@@([A-Z_][A-Z0-9_]{0,63})@@/g, (_, n) => sampleValue(n)));
	}

	// live preview: inline the uploaded images as data urls so they render, and when the
	// sample toggle is on, fill both variable layers so the preview matches what a
	// recipient sees: install time @@VAR@@ slots and send time {{.Var}} fields.
	function inlinePreview(src) {
		let h = src;
		for (const a of assets) {
			const uri = `data:${mimeFor(a.filename)};base64,${a.base64}`;
			h = h.split(`{{.BaseURL}}/${a.filename}`).join(uri);
		}
		if (previewFill) {
			h = h.replace(/@@([A-Z_][A-Z0-9_]{0,63})@@/g, (_, n) => sampleValue(n));
			h = fillSendTime(h);
		}
		return h;
	}
	const previewHtml = $derived.by(() => inlinePreview(form.html));
	// the domain 404 page preview, same transform on its own body.
	const previewNotFound = $derived.by(() => inlinePreview(form.notFound));

	const detected = $derived.by(() => {
		// an asset bundle has no text body to scan; its files are passed through.
		// only scan the body editor for types that use it. a domain also has a 404 body.
		const body = usesBodyEditor ? form.html : '';
		const text = isAsset ? dataYaml() : `${body} ${isDomain ? form.notFound : ''} ${dataYaml()} ${form.subject} ${form.from} ${form.envelopeFrom}`;
		const re = /@@([A-Z_][A-Z0-9_]{0,63})@@/g;
		const set = new Set();
		let m;
		while ((m = re.exec(text)) !== null) set.add(m[1]);
		return [...set];
	});

	// tokens that look like a variable (@@...@@) but are not a valid name, so they would
	// ship as literal text instead of being substituted at install. a common typo is
	// lowercase or a hyphen; flag them so the operator fixes it before publishing.
	const malformedVars = $derived.by(() => {
		const body = usesBodyEditor ? form.html : '';
		const text = isAsset ? dataYaml() : `${body} ${isDomain ? form.notFound : ''} ${dataYaml()} ${form.subject} ${form.from} ${form.envelopeFrom}`;
		const re = /@@([^@\s]{1,80})@@/g;
		const valid = /^[A-Z_][A-Z0-9_]{0,63}$/;
		const set = new Set();
		let m;
		while ((m = re.exec(text)) !== null) if (!valid.test(m[1])) set.add(m[1]);
		return [...set];
	});

	// for a proxy, the start URL host must appear as a top level host key in the config or
	// the AiTM proxy will not route the victim session. flag a mismatch so it is caught
	// before publish instead of failing silently at runtime.
	const proxyHostMismatch = $derived.by(() => {
		if (!isProxy) return '';
		const hm = String(form.startURL || '').match(/^\s*(?:https?:\/\/)?([^/:\s]+)/i);
		const host = hm ? hm[1] : '';
		if (!host || !form.html.trim()) return '';
		const esc = host.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
		const re = new RegExp(`^\\s*"?${esc}"?\\s*:`, 'm');
		return re.test(form.html) ? '' : host;
	});

	// asset files the content references ({{.BaseURL}}/<file>, the form phishingclub serves)
	// that are not uploaded in this package, so they would ship as a broken reference. a
	// package carries its own files, so an unresolved reference is flagged here.
	// a bare assets/<file> is tolerated so an older template still gets checked.
	const missingAssets = $derived.by(() => {
		if (!usesBodyEditor) return [];
		const refs = new Set();
		const re = /(?:\{\{\s*\.BaseURL\s*\}\}\/|assets\/)([A-Za-z0-9._/-]+\.[A-Za-z0-9]+)/g;
		for (const m of String(form.html || '').matchAll(re)) refs.add(m[1]);
		if (refs.size === 0) return [];
		const have = new Set(assets.map((a) => a.filename));
		return [...refs].filter((r) => !have.has(r));
	});

	$effect(() => {
		// a variable named DOMAIN defaults to the domain type, since a domain package
		// declares @@DOMAIN@@ for the domain the installer supplies.
		for (const v of detected)
			if (!varCfg[v]) varCfg[v] = { type: v === 'DOMAIN' ? 'domain' : 'text', required: true, default: '', description: '', options: [] };
	});

	function addFiles(fileList) {
		if (!canAddAssets) {
			toast('Set the namespace and name above before adding files', 'error');
			return;
		}
		for (const file of fileList) {
			if (file.size > MAX_FILE_BYTES) {
				toast(`${file.name} is ${(file.size / 1048576).toFixed(1)} MB; the per file limit is 25 MB`, 'error');
				continue;
			}
			const reader = new FileReader();
			reader.onload = () => {
				const b64 = String(reader.result).split(',')[1] || '';
				// default a new asset into a per package folder so two packages that both
				// ship, say, logo.png do not collide on the shared asset path. an attachment
				// is not a shared asset, so it keeps its bare name. the author can edit the
				// path afterwards.
				const fn = isAttachment ? file.name : assetFolder(form.namespace, form.name) + file.name;
				// a file added again at the same path keeps the settings it had.
				const prev = assets.find((a) => a.filename === fn);
				const entry = { ...emptyAssetMeta(), ...(prev || {}), filename: fn, base64: b64 };
				// an attachment is a single file; keep only the latest
				if (isAttachment) assets = [entry];
				else assets = [...assets.filter((a) => a.filename !== fn), entry];
			};
			reader.readAsDataURL(file);
		}
	}
	function onFiles(e) {
		addFiles(e.target.files);
		e.target.value = '';
	}
	// an email attachment keeps a bare safe filename: strip any directory and
	// collapse a dotted run so a traversal path cannot reach the packed file name.
	const isIcs = (fn) => /\.ics$/i.test(String(fn || ''));
	function addAttachments(fileList) {
		if (!canAddAssets) {
			toast('Set the namespace and name above before adding files', 'error');
			return;
		}
		const files = [...fileList].filter((file) => {
			if (file.size > MAX_FILE_BYTES) {
				toast(`${file.name} is ${(file.size / 1048576).toFixed(1)} MB; the per file limit is 25 MB`, 'error');
				return false;
			}
			return true;
		});
		// read every selected file before touching the list, so concurrent reads of
		// several files picked at once cannot overwrite each other. the merge keeps
		// existing attachments and replaces one only when a new file reuses its name.
		Promise.all(
			files.map(
				(file) =>
					new Promise((resolve) => {
						const filename = String(file.name).split(/[\\/]/).pop().replace(/\.\.+/g, '.').trim() || 'file';
						const reader = new FileReader();
						reader.onload = () =>
							resolve({ filename, base64: String(reader.result).split(',')[1] || '', name: filename, description: '', embedded: false, calendar: false, inline: false });
						reader.onerror = () => resolve(null);
						reader.readAsDataURL(file);
					})
			)
		).then((entries) => {
			const byName = new Map(emailAttachments.map((a) => [a.filename, a]));
			for (const e of entries) if (e) byName.set(e.filename, e);
			emailAttachments = [...byName.values()];
		});
	}
	function onAttachmentFiles(e) {
		addAttachments(e.target.files);
		e.target.value = '';
	}
	function removeAttachment(filename) {
		emailAttachments = emailAttachments.filter((a) => a.filename !== filename);
	}
	function removeAsset(name) {
		assets = assets.filter((a) => a.filename !== name);
		delete metaOpen[name];
		if (previewFilename === name) previewFilename = '';
	}
	// an asset path is a relative path under assets/, so subfolders like images/logo.png
	// are kept. strip a leading slash and any .. segment so it cannot escape assets/, and
	// drop characters that are not safe in a path.
	// rename an asset's path as the operator edits it, keeping the preview marker in step
	// so a path change does not orphan the chosen thumbnail.
	function onAssetPath(i, value) {
		const next = sanitizeAssetPath(value);
		const old = assets[i].filename;
		if (previewFilename === old) previewFilename = next;
		if (metaOpen[old]) {
			delete metaOpen[old];
			metaOpen[next] = true;
		}
		assets[i] = { ...assets[i], filename: next };
	}

	// a short summary of an asset's settings, shown on its row when the panel is closed.
	function metaSummary(a) {
		const parts = [];
		if (a.contentType.trim()) parts.push(a.contentType.trim());
		const hs = a.headers.filter((h) => h.key.trim()).length;
		if (hs) parts.push(`${hs} header${hs === 1 ? '' : 's'}`);
		if (a.allowDeny.length) parts.push(`${a.allowDeny.length} list${a.allowDeny.length === 1 ? '' : 's'}`);
		return parts.join(' · ');
	}

	// package meta preview images: shown when browsing the package; NOT shipped in the
	// archive and not referenceable from content. Sent alongside the publish and stored
	// as package metadata.
	let previewMeta = $state([]); // {filename, base64, mediaType}
	function addPreviewMeta(fileList) {
		for (const file of fileList) {
			const problem = previewFileProblem(file);
			if (problem) {
				toast(problem, 'error');
				continue;
			}
			const reader = new FileReader();
			reader.onload = () => {
				const b64 = String(reader.result).split(',')[1] || '';
				previewMeta = [
					...previewMeta.filter((p) => p.filename !== file.name),
					{ filename: file.name, base64: b64, mediaType: file.type }
				];
			};
			reader.readAsDataURL(file);
		}
	}
	function onPreviewMeta(e) {
		addPreviewMeta(e.target.files);
		e.target.value = '';
	}
	function removePreviewMeta(name) {
		previewMeta = previewMeta.filter((p) => p.filename !== name);
	}

	// drag and drop files straight onto the assets panel
	let dragging = $state(false);
	function onDrop(e) {
		e.preventDefault();
		dragging = false;
		if (e.dataTransfer?.files?.length) addFiles(e.dataTransfer.files);
	}
	function onDragOver(e) {
		e.preventDefault();
		dragging = true;
	}
	function onDragLeave() {
		dragging = false;
	}
	let showYaml = $state(false);
	// the editor fills the width by default; the live preview opens beside it on demand
	// (like the phishingclub editor), so authoring is not cramped into a permanent split.
	let showPreview = $state(false);
	// a domain has a second editor for its 404 page, with its own preview toggle.
	let showNotFoundPreview = $state(false);
	// the proxy config can be edited as a visual builder or as raw yaml; remember the choice.
	let proxyEditorMode = $state('visual');
	try {
		const saved = localStorage.getItem('bs-proxy-editor');
		if (saved === 'visual' || saved === 'yaml') proxyEditorMode = saved;
	} catch (_) {
		/* ignore */
	}
	function setProxyEditorMode(m) {
		proxyEditorMode = m;
		try {
			localStorage.setItem('bs-proxy-editor', m);
		} catch (_) {
			/* ignore */
		}
	}
	// the authoring area is split into tabs: the editor and live preview get the whole
	// viewport on the content tab; a Settings tab holds the content defining fields for
	// types that have them; a Details tab holds the registry listing metadata.
	let tab = $state('content');
	// the tab set adapts to the type: Settings only appears when the type has fields.
	const tabList = $derived([
		['content', isHtml ? 'Edit & preview' : 'Content'],
		...(hasSettings ? [['settings', 'Settings']] : []),
		...(form.type === 'email' ? [['attachments', 'Attachments']] : []),
		['details', 'Details']
	]);
	// if the type changes so an active tab no longer exists, fall back to the content
	// tab so the page does not show an empty panel. Settings is gone for types without
	// fields, Attachments is email only.
	$effect(() => {
		if (tab === 'settings' && !hasSettings) tab = 'content';
		if (tab === 'attachments' && form.type !== 'email') tab = 'content';
	});

	async function publish() {
		if (!canPublish) {
			if (!nameValid) toast('Name must be a lowercase slug (a-z, 0-9, dashes)', 'error');
			else if (!versionValid) toast('Version must be semver, like 1.0.0', 'error');
			else if (versionExists) toast(`Version ${form.version} already exists; bump it`, 'error');
			else if (!hasContent) toast(isAsset ? 'Add at least one file' : 'Add some content', 'error');
			else if (!assetMetaValid) toast('Fix the asset settings marked in red', 'error');
			else toast('Pick a namespace first', 'error');
			return;
		}
		busy = true;
		const res = await api.packages.author(buildPayload());
		busy = false;
		if (res.ok) {
			published = true;
			toast('Package published', 'success');
			// the version is published even when a preview image is rejected (for
			// example over the pixel limit), so say how many were left out.
			const failed = res.data?.failedPreviews || 0;
			if (failed) toast(`${failed} preview image${failed === 1 ? ' was' : 's were'} rejected. ${PREVIEW_LIMITS_TEXT}`, 'error');
			// a color chosen for a tag no package carried can be stored now the package has it.
			const colorFailed = await applyPendingTagColors(form.namespace, form.name, pendingTagColors);
			pendingTagColors = {};
			if (colorFailed.length) toast(`Could not save the color of ${colorFailed.join(', ')}`, 'error');
			goto(`/packages/${form.namespace}/${form.name}`);
		} else {
			toast(res.error || 'Publish failed', 'error');
		}
	}

	// buildPayload assembles the full author request. Publish sends it to the
	// package endpoint; Save draft stores the same body so publishing a draft
	// later replays it.
	function buildPayload() {
		// a domain that redirects serves no content, so it ships only the data.yaml; a
		// hosting domain ships the landing page (content.html), the 404 page (notfound.html)
		// and any assets they reference. an asset path keeps its subfolders under assets/.
		const domainFiles = () => {
			const out = [{ path: `content/${folder()}/data.yaml`, content: b64text(dataYaml()) }];
			if (form.domainType !== 'proxy' && !form.redirectURL.trim() && form.hostWebsite) {
				out.push({ path: `content/${folder()}/content.html`, content: b64text(form.html) });
				out.push({ path: `content/${folder()}/notfound.html`, content: b64text(form.notFound) });
			}
			for (const a of assets) out.push({ path: `assets/${a.filename}`, content: a.base64 });
			return out;
		};
		const files = isAsset
			? [
					{ path: `content/${folder()}/data.yaml`, content: b64text(dataYaml()) },
					...assets.map((a) => ({ path: `assets/${a.filename}`, content: a.base64 }))
				]
			: isAttachment
				? [
						{ path: `content/${folder()}/data.yaml`, content: b64text(dataYaml()) },
						{ path: `content/${folder()}/${assets[0].filename}`, content: assets[0].base64 }
					]
				: isAllowDeny || isConfigOnly
					? [{ path: `content/${folder()}/data.yaml`, content: b64text(dataYaml()) }]
					: isDomain
						? domainFiles()
						: [
							{ path: `content/${folder()}/data.yaml`, content: b64text(dataYaml()) },
							{ path: `content/${folder()}/${contentFileName()}`, content: b64text(form.html) },
							...assets.map((a) => ({ path: `assets/${a.filename}`, content: a.base64 })),
							...emailAttachments.map((a) => ({ path: `content/${folder()}/${a.filename}`, content: a.base64 }))
						];
		const variables = detected.map((name) => {
			const cfg = varCfg[name] || { type: 'text', required: true, default: '', description: '' };
			// a secret is always required and never carries a default
			const isSecret = cfg.type === 'secret';
			const v = { name, type: cfg.type, required: isSecret || cfg.required };
			if (cfg.description) v.description = cfg.description;
			if (!isSecret && !cfg.required && cfg.default !== '') v.default = cfg.default;
			// an enum ships its allowed values; other types carry none.
			if (cfg.type === 'enum') v.options = cfg.options || [];
			// an api sender set to use the installer's own OAuth provider ships the
			// @@OWN_OAUTH_PROVIDER@@ sentinel; declare it a required text variable that
			// picks an OAuth provider so Phishing Club renders a provider picker at install.
			if (name === 'OWN_OAUTH_PROVIDER') {
				v.type = 'text';
				v.required = true;
				v.pick = 'oauthProvider';
			}
			// a variable named in an asset's allow deny lists asks the installer to pick
			// one of their own lists, so it is a required pick with no default.
			if (allowDenyPicks.has(name) && isListPick(listPicks[name])) {
				v.type = 'text';
				v.required = true;
				v.pick = listPicks[name];
				delete v.default;
				delete v.options;
			}
			return v;
		});
		// the package preview: a bundled image shipped under assets/, so skip it for an
		// attachment (its file lives under content/) or when the marked file is gone.
		const previewPath =
			previewFilename && !isAttachment && assets.some((a) => a.filename === previewFilename)
				? `assets/${previewFilename}`
				: '';
		return {
			namespace: form.namespace,
			name: form.name,
			title: form.title.trim(),
			type: form.type,
			version: form.version,
			...(previewPath ? { preview: previewPath } : {}),
			description: form.description,
			tags: form.tags.split(',').map((t) => t.trim()).filter(Boolean),
			variables,
			...(listDeps.length ? { dependencies: listDeps.map((p) => ({ id: p.id, range: '*' })) } : {}),
			files,
			previewImages: previewMeta.map((p) => ({ content: p.base64 }))
		};
	}

	// saveDraft stores the current work without publishing a version. The address
	// (namespace and name) must be set; everything else can be incomplete.
	async function saveDraft() {
		if (!form.namespace || !form.name || !nameValid) {
			toast('Pick a namespace and a name before saving a draft', 'error');
			return;
		}
		busy = true;
		const res = await api.drafts.save(buildPayload());
		busy = false;
		if (res.ok) {
			baseline = snapshot();
			toast('Draft saved', 'success');
		} else {
			toast(res.error || 'Could not save draft', 'error');
		}
	}
</script>

<div class="flex items-center gap-2">
	<!-- when the heading embeds a package address (editing an existing one), use the
	     body font so the address keeps its casing instead of the all caps display font. -->
	<h1 class="pc-h1 {editingFrom ? 'font-body' : ''}">{heading}</h1>
	<Help title="Authoring a package">
		<p>Pick a type, author its content, and publish a version. Phishing Club installs the result.</p>
		<p><strong>Install time slots</strong> use <code>@@VARIABLE@@</code> tokens anywhere; the installer fills them in on install. A name is UPPERCASE letters, digits and underscores (for example <code>@@TARGET_DOMAIN@@</code>). Mark a variable <strong>secret</strong> to make it required and keep it out of the shipped package.</p>
		<p><strong>Send time variables</strong> like <code>{`{{.BaseURL}}`}</code>, <code>{`{{.URL}}`}</code> and <code>{`{{.FirstName}}`}</code> are left untouched and filled by Phishing Club per recipient at send.</p>
		<p><strong>Assets</strong> install as shared files. Reference them in content as <code>{`{{.BaseURL}}`}/&lt;file&gt;</code> so they resolve for the sending domain.</p>
		<p><strong>Types</strong></p>
		<ul>
			<li><strong>page</strong>: a landing page the target sees after clicking.</li>
			<li><strong>email</strong>: a phishing email body with subject and sender.</li>
			<li><strong>domain site</strong>: a flat site a domain serves itself, with its own landing page and 404 page, or a redirect.</li>
			<li><strong>script</strong>: JavaScript run in a sandbox when a campaign event fires.</li>
			<li><strong>report template</strong>: HTML used to render the campaign report.</li>
			<li><strong>proxy</strong>: an adversary in the middle proxy config that relays a real login through your domain.</li>
			<li><strong>remote browser</strong>: automation that drives a real Chrome session.</li>
			<li><strong>attachment</strong>: a file attached to phishing emails.</li>
			<li><strong>allow / deny</strong>: a list by CIDR, country, ASN or header.</li>
			<li><strong>asset</strong>: a bundle of images or files reused by pages and emails.</li>
			<li><strong>SMTP configuration</strong>: a mail server to send through, with optional custom headers.</li>
			<li><strong>webhook</strong>: a callback that campaign events are posted to.</li>
			<li><strong>OAuth provider</strong>: an OAuth app Phishing Club authorizes after install to get access tokens for an API sender.</li>
			<li><strong>API sender</strong>: an HTTP API Phishing Club sends email through, with request and expected response settings.</li>
		</ul>
	</Help>
</div>
{#if editingFrom && !isNewVersion}
	<Alert variant="warning" class="mt-2">
		The name differs from <code>{editingFrom}</code>, so this publishes a separate package seeded from it, not a new version.
	</Alert>
{:else if addsToExistingPackage}
	<p class="mt-2 rounded-md bg-pc-lightblue/60 dark:bg-pc-darkblue/40 px-3 py-2 text-xs text-cta-blue dark:text-highlight-blue">
		<code>{form.namespace}/{form.name}</code> already exists, so publishing here adds a new version to it. Change the name to create a separate package.
	</p>
{/if}

{#if nsLoaded && nsError}
	<div class="mt-6 pc-card p-8 text-center">
		<p class="text-sm text-red-600 dark:text-red-400">{nsError}</p>
		<button onclick={loadNamespaces} class="mt-3 inline-block rounded-md border border-gray-300 dark:border-gray-700 px-4 py-2 text-sm font-semibold hover:bg-gray-50 dark:hover:bg-gray-900">Retry</button>
	</div>
{:else if nsLoaded && namespaces.length === 0}
	<div class="mt-6 pc-card p-8 text-center">
		<p class="text-sm text-gray-800 dark:text-gray-100">
			A package needs a namespace to live under (a package is addressed as <code>namespace/name</code>).
			Create one first, then come back here to author a package.
		</p>
		<Button href="/namespaces" variant="primary" class="mt-4 inline-block">Create a namespace</Button>
	</div>
{:else}
<div class="mt-6">
	<!-- identity + publish: always visible so the essentials are one glance away -->
	<div class="pc-card p-4">
		<div class="flex flex-wrap items-start gap-3">
			<div class="text-sm w-44">
				<span class="pc-label">Namespace</span>
				<Select bind:value={form.namespace} options={nsOptions} ariaLabel="Namespace" class="mt-1" />
			</div>
			<label class="text-sm min-w-[12rem] flex-1">
				<span class="pc-label">Name</span>
				<input bind:value={form.title} oninput={onDisplayNameInput} placeholder="Welcome Email" class="mt-1 pc-control" />
				<span class="mt-1 block text-xs text-gray-700 dark:text-gray-200">
					Address:
					<input
						bind:value={form.name}
						oninput={() => (slugLocked = true)}
						placeholder="welcome-email"
						title={form.name}
						class="ml-1 w-40 overflow-hidden text-ellipsis rounded border-0 bg-transparent p-0 font-mono text-gray-700 focus:outline-none dark:text-gray-200 {form.name && !nameValid ? 'text-red-600 dark:text-red-400' : ''}" />
				</span>
			</label>
			<div class="text-sm w-56">
				<span class="pc-label">Type</span>
				<Select bind:value={form.type} options={typeOptions} ariaLabel="Type" class="mt-1" />
			</div>
			<label class="text-sm w-28">
				<span class="pc-label">Version</span>
				<input bind:value={form.version} class="mt-1 pc-control {(form.version && !versionValid) || versionExists ? 'border-red-400 dark:border-red-700' : ''}" />
			</label>
			<div class="ml-auto flex flex-col">
				<span class="pc-label invisible" aria-hidden="true">Actions</span>
				<div class="mt-1 flex gap-2">
					<Button variant="secondary" onclick={saveDraft} disabled={busy}>
						{busy ? 'Saving…' : 'Save draft'}
					</Button>
					<Button variant="primary" onclick={publish} disabled={!canPublish}>
						{busy ? 'Publishing…' : 'Publish package'}
					</Button>
				</div>
			</div>
		</div>
		{#if (form.name && !nameValid) || (form.version && !versionValid) || versionExists || versionNotHigher}
			<div class="mt-2 space-y-1 text-xs">
				{#if form.name && !nameValid}<p class="text-red-600 dark:text-red-400">Name must be lowercase letters, numbers and dashes.</p>{/if}
				{#if form.version && !versionValid}<p class="text-red-600 dark:text-red-400">Version must be semver, like 1.0.0.</p>{:else if versionExists}<p class="text-red-600 dark:text-red-400">Version {form.version} already exists; bump it (latest is {highestExisting}).</p>{:else if versionNotHigher}<p class="text-amber-700 dark:text-amber-300">Version is lower than the current latest ({highestExisting}); it publishes but will not become the latest.</p>{/if}
			</div>
		{/if}
	</div>

	<!-- tabs: the editor and preview get the whole viewport; Settings holds the content
	     fields for types that have them; Details holds the registry listing metadata -->
	<div class="mt-4 flex items-center gap-1 overflow-x-auto overflow-y-hidden border-b border-gray-200 dark:border-gray-800">
		{#each tabList as [key, lbl]}
			<button type="button" onclick={() => (tab = key)} aria-current={tab === key ? 'page' : undefined} class="-mb-px shrink-0 whitespace-nowrap border-b-2 px-4 py-2 text-sm font-semibold transition-colors {tab === key ? 'border-cta-blue text-cta-blue dark:border-highlight-blue dark:text-highlight-blue' : 'border-transparent text-gray-700 hover:text-gray-700 dark:text-gray-200 dark:hover:text-gray-200'}">{lbl}</button>
		{/each}
	</div>

	<!-- CONTENT TAB (kept in the DOM with hidden so the editor is not torn down on tab switch) -->
	<div class="mt-4 space-y-4 {tab === 'content' ? '' : 'hidden'}">
		{#if isDomain}
			{#if form.domainType === 'proxy'}
				<div class="pc-card p-5">
					<h2 class="text-sm font-semibold text-gray-900 dark:text-white">Proxy domain</h2>
					<p class="mt-1 pc-desc">This domain routes to a proxy ({form.proxyTargetDomain || 'set the target under Settings'}) instead of serving its own content, so there is no landing page or 404 page to author.</p>
				</div>
			{:else if form.redirectURL.trim()}
				<div class="pc-card p-5">
					<h2 class="text-sm font-semibold text-gray-900 dark:text-white">Redirect</h2>
					<p class="mt-1 pc-desc">This domain redirects to <code>{form.redirectURL}</code>, so it serves no landing page or 404 page. Clear the redirect under <strong>Settings</strong> to host content instead.</p>
				</div>
			{:else}
				<div>
					<h2 class="mb-2 text-sm font-semibold text-gray-900 dark:text-white">Landing page <span class="font-normal text-gray-700 dark:text-gray-200">(served at /)</span></h2>
					<EditorWorkbench
						bind:value={form.html}
						lang="html"
						srcdoc={previewHtml}
						filename="content.html"
						type="domain"
						bind:showPreview
					>
						{#snippet previewHeader()}
							<label class="mb-2 flex items-center gap-2 text-sm text-gray-800 dark:text-gray-100">
								<input type="checkbox" bind:checked={previewFill} class="rounded border-gray-300 dark:border-gray-700" />
								Sample values
							</label>
						{/snippet}
					</EditorWorkbench>
				</div>
				<div>
					<h2 class="mb-2 text-sm font-semibold text-gray-900 dark:text-white">Not found page <span class="font-normal text-gray-700 dark:text-gray-200">(served with a 404 for any other path)</span></h2>
					<EditorWorkbench
						bind:value={form.notFound}
						lang="html"
						srcdoc={previewNotFound}
						filename="notfound.html"
						type="domain"
						bind:showPreview={showNotFoundPreview}
					/>
				</div>
			{/if}
		{:else if isHtml}
			<EditorWorkbench
				bind:value={form.html}
				lang="html"
				srcdoc={previewHtml}
				filename={contentFileName()}
				type={form.type}
				bind:showPreview
			>
				{#snippet previewHeader()}
					<label class="mb-2 flex items-center gap-2 text-sm text-gray-800 dark:text-gray-100">
						<input type="checkbox" bind:checked={previewFill} class="rounded border-gray-300 dark:border-gray-700" />
						Sample values
					</label>
					{#if form.type === 'email'}
						<div class="mb-2 rounded border border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-gray-900 px-3 py-2 text-xs">
							<div><span class="pc-label">Subject:</span> {fillString(form.subject) || '(none)'}</div>
							<div><span class="pc-label">From:</span> {fillString(form.from) || '(none)'}</div>
						</div>
					{/if}
				{/snippet}
			</EditorWorkbench>
		{:else if isScript}
			<div class="flex flex-col pc-card p-5 lg:h-[calc(100vh-14rem)]">
				<h2 class="text-sm font-semibold text-gray-700 dark:text-gray-200 mb-2">script.js</h2>
				<div class="min-h-0 flex-1"><CodeEditor bind:value={form.html} lang="javascript" type="script" fill /></div>
			</div>
		{:else if isProxy}
			<div class="flex flex-col pc-card p-5 lg:min-h-[calc(100vh-14rem)]">
				<div class="mb-2 flex items-center justify-between">
					<h2 class="text-sm font-semibold text-gray-700 dark:text-gray-200">proxy.yaml</h2>
					<div class="flex overflow-hidden rounded-md border border-gray-300 dark:border-gray-700 text-xs">
						<button type="button" onclick={() => setProxyEditorMode('visual')} class="px-3 py-1 font-medium {proxyEditorMode === 'visual' ? 'bg-cta-blue text-white' : 'text-gray-800 hover:bg-gray-100 dark:text-gray-100 dark:hover:bg-gray-800'}">Visual</button>
						<button type="button" onclick={() => setProxyEditorMode('yaml')} class="px-3 py-1 font-medium {proxyEditorMode === 'yaml' ? 'bg-cta-blue text-white' : 'text-gray-800 hover:bg-gray-100 dark:text-gray-100 dark:hover:bg-gray-800'}">YAML</button>
					</div>
				</div>
				{#if proxyEditorMode === 'visual'}
					<ProxyConfigBuilder config={form.html} startURL={form.startURL} onChange={(yaml) => (form.html = yaml)} />
				{:else}
					<!-- the YAML editor needs a definite height (the card uses min-h for the
					     variable height visual builder), so give it its own fixed box. -->
					<div class="h-[calc(100vh-22rem)] min-h-[20rem]"><CodeEditor bind:value={form.html} lang="yaml" type="proxy" fill /></div>
				{/if}
				<p class="mt-2 text-xs text-gray-700 dark:text-gray-200">The proxy config. Each top level host key maps a victim facing domain to its real upstream via <code>to:</code>. Use <code>@@VARIABLES@@</code> for the domains the installer fills in.</p>
			</div>
		{:else if isRemoteBrowser}
			<div class="flex flex-col pc-card p-5 lg:h-[calc(100vh-14rem)]">
				<h2 class="text-sm font-semibold text-gray-700 dark:text-gray-200 mb-2">browser.js</h2>
				<div class="min-h-0 flex-1"><CodeEditor bind:value={form.html} lang="javascript" type="remotebrowser" fill /></div>
				<p class="mt-2 text-xs text-gray-700 dark:text-gray-200">Automation that drives a real Chrome session (the <code>page</code> object). Use <code>@@VARIABLES@@</code> for values the installer fills in; secrets never ship.</p>
			</div>
		{:else if isAllowDeny}
			<div class="pc-card p-5 space-y-3">
				<h2 class="text-sm font-semibold text-gray-700 dark:text-gray-200">Allow / deny rules</h2>
				<AllowDenyRules bind:list={form} />
				<p class="text-xs text-gray-700 dark:text-gray-200">Provide at least one rule set. Use <code>@@VARIABLES@@</code> for values the installer fills in.</p>
			</div>
		{:else if isAttachment}
			<div class="pc-card p-5 space-y-3">
				<h2 class="text-sm font-semibold text-gray-700 dark:text-gray-200">Attachment settings</h2>
				<label class="block text-sm">
					<span class="pc-label">Description</span> <span class="pc-optional">optional</span>
					<input bind:value={form.attDescription} class="mt-1 pc-control" />
				</label>
				<Checkbox bind:checked={form.attEmbedded} label="Embed the file content in the email" />
				<Checkbox bind:checked={form.attCalendar} label="Send as a calendar invite" />
				<p class="text-xs text-gray-700 dark:text-gray-200">Phishing Club installs this as an email attachment. Choose the file below.</p>
			</div>
		{:else if isAsset}
			<div class="pc-card p-5">
				<h2 class="text-sm font-semibold text-gray-700 dark:text-gray-200 mb-2">Asset bundle</h2>
				{#if assets.length}
					<ul class="mt-1 space-y-1 text-sm">{#each assets as a (a.filename)}<li><code>{assetRef(a.filename)}</code></li>{/each}</ul>
				{/if}
			</div>
		{:else if isSMTP}
			<div class="pc-card p-5 space-y-3">
				<h2 class="text-sm font-semibold text-gray-700 dark:text-gray-200">SMTP configuration</h2>
				<div class="grid gap-3 sm:grid-cols-2">
					<Field label="Host"><input bind:value={form.smtpHost} placeholder="smtp.@@MAIL_DOMAIN@@" class="pc-control" /></Field>
					<Field label="Port"><input type="number" min="1" max="65535" bind:value={form.smtpPort} class="pc-control" /></Field>
					<Field label="Username" optional><input bind:value={form.smtpUsername} autocomplete="off" class="pc-control" /></Field>
					<label class="block text-sm"><span class="pc-label">Password</span> <span class="pc-optional">optional</span>
						<span class="relative mt-1 block">
							{#if showSmtpPassword}
								<input type="text" bind:value={form.smtpPassword} autocomplete="off" placeholder="@@SMTP_PASSWORD@@" class="pc-control pr-16" />
							{:else}
								<input type="password" bind:value={form.smtpPassword} autocomplete="off" placeholder="@@SMTP_PASSWORD@@" class="pc-control pr-16" />
							{/if}
							<Button variant="neutral" size="xs" onclick={() => (showSmtpPassword = !showSmtpPassword)} ariaLabel={showSmtpPassword ? 'Hide password' : 'Show password'} class="absolute right-1 top-1/2 -translate-y-1/2">{showSmtpPassword ? 'Hide' : 'Show'}</Button>
						</span>
					</label>
					<Field label="HELO" optional><input bind:value={form.smtpHelo} class="pc-control" /></Field>
					<label class="flex items-end gap-2 text-sm text-gray-800 dark:text-gray-100"><input type="checkbox" bind:checked={form.smtpIgnoreCert} class="mb-2.5 rounded border-gray-300 dark:border-gray-700" /> Ignore TLS certificate errors</label>
				</div>
				<div>
					<div class="flex items-center justify-between">
						<span class="flex items-center gap-2"><span class="pc-label">Custom headers</span> <span class="pc-optional">optional</span></span>
						<Button variant="blue" size="xs" onclick={() => (form.smtpHeaders = [...form.smtpHeaders, { key: '', value: '' }])}>+ Add header</Button>
					</div>
					<p class="pc-hint">Added to every message. Values are Go template rendered per recipient.</p>
					{#each form.smtpHeaders as h, hi (hi)}
						<div class="mt-2 flex flex-wrap items-center gap-2">
							<input bind:value={h.key} placeholder="X-Mailer" class="pc-control flex-1 min-w-[8rem] text-xs" />
							<input bind:value={h.value} placeholder="Outlook" class="pc-control flex-1 min-w-[8rem] text-xs" />
							<Button variant="danger" size="xs" onclick={() => (form.smtpHeaders = form.smtpHeaders.filter((_, i) => i !== hi))}>Remove</Button>
						</div>
					{/each}
				</div>
			</div>
		{:else if isWebhook}
			<div class="pc-card p-5 space-y-3">
				<h2 class="text-sm font-semibold text-gray-700 dark:text-gray-200">Webhook</h2>
				<Field label="URL"><input bind:value={form.webhookUrl} placeholder="https://@@WEBHOOK_HOST@@/events" class="pc-control" /></Field>
				<Field label="Secret" optional hint="Signs the webhook payloads so the receiver can verify them."><input bind:value={form.webhookSecret} placeholder="@@WEBHOOK_SECRET@@" class="pc-control" /></Field>
			</div>
		{:else if isOauthProvider}
			<div class="pc-card p-5 space-y-3">
				<h2 class="text-sm font-semibold text-gray-700 dark:text-gray-200">OAuth provider</h2>
				<Alert variant="info">
					The provider installs unauthorized. After install the operator completes the OAuth authorization in Phishing Club. Put the provider setup steps (create the OAuth app, set the redirect URI, copy the client ID and secret) in the package Description.
				</Alert>
				<div class="grid gap-3 sm:grid-cols-2">
					<Field label="Auth URL"><input bind:value={form.oauthAuthURL} placeholder="https://accounts.google.com/o/oauth2/auth" class="pc-control" /></Field>
					<Field label="Token URL"><input bind:value={form.oauthTokenURL} placeholder="https://oauth2.googleapis.com/token" class="pc-control" /></Field>
					<Field label="Scopes"><input bind:value={form.oauthScopes} placeholder="https://www.googleapis.com/auth/gmail.send" class="pc-control" /></Field>
					<Field label="Client ID"><input bind:value={form.oauthClientID} placeholder="@@GOOGLE_CLIENT_ID@@" class="pc-control" /></Field>
					<label class="block text-sm"><span class="pc-label">Client secret</span>
						<span class="relative mt-1 block">
							{#if showOauthClientSecret}
								<input type="text" bind:value={form.oauthClientSecret} autocomplete="off" placeholder="@@GOOGLE_CLIENT_SECRET@@" class="pc-control pr-16" />
							{:else}
								<input type="password" bind:value={form.oauthClientSecret} autocomplete="off" placeholder="@@GOOGLE_CLIENT_SECRET@@" class="pc-control pr-16" />
							{/if}
							<Button variant="neutral" size="xs" onclick={() => (showOauthClientSecret = !showOauthClientSecret)} ariaLabel={showOauthClientSecret ? 'Hide client secret' : 'Show client secret'} class="absolute right-1 top-1/2 -translate-y-1/2">{showOauthClientSecret ? 'Hide' : 'Show'}</Button>
						</span>
					</label>
				</div>
			</div>
		{:else if isApiSender}
			<div class="pc-card p-5 space-y-3">
				<h2 class="text-sm font-semibold text-gray-700 dark:text-gray-200">API sender</h2>
				<div class="grid gap-3 sm:grid-cols-2">
					<Field label="Request method">
						<Select bind:value={form.apiRequestMethod} options={[{ value: 'GET', label: 'GET' }, { value: 'POST', label: 'POST' }, { value: 'PUT', label: 'PUT' }, { value: 'PATCH', label: 'PATCH' }, { value: 'DELETE', label: 'DELETE' }]} ariaLabel="Request method" />
					</Field>
					<Field label="Request URL"><input bind:value={form.apiRequestURL} placeholder="https://api.example.com/send" class="pc-control" /></Field>
				</div>
				<div>
					<div class="flex items-center justify-between">
						<span class="flex items-center gap-2"><span class="pc-label">Request headers</span> <span class="pc-optional">optional</span></span>
						<Button variant="blue" size="xs" onclick={() => (form.apiRequestHeaders = [...form.apiRequestHeaders, { key: '', value: '' }])}>+ Add header</Button>
					</div>
					<p class="pc-hint">For example <code>Authorization</code> with <code>Bearer {'{{.OAuthAccessToken}}'}</code>.</p>
					{#each form.apiRequestHeaders as h, hi (hi)}
						<div class="mt-2 flex flex-wrap items-center gap-2">
							<input bind:value={h.key} placeholder="Authorization" class="pc-control flex-1 min-w-[8rem] text-xs" />
							<input bind:value={h.value} placeholder="Bearer {'{{.OAuthAccessToken}}'}" class="pc-control flex-1 min-w-[8rem] text-xs" />
							<Button variant="danger" size="xs" onclick={() => (form.apiRequestHeaders = form.apiRequestHeaders.filter((_, i) => i !== hi))}>Remove</Button>
						</div>
					{/each}
				</div>
				<label class="block text-sm"><span class="pc-label">Request body</span> <span class="pc-optional">optional</span>
					<textarea bind:value={form.apiRequestBody} rows="4" placeholder={'{\n  "to": "{{.To}}",\n  "subject": "{{.Subject}}"\n}'} class="mt-1 pc-control font-mono text-xs"></textarea>
				</label>
				<p class="pc-hint">Send time template variables such as <code>{'{{.To}}'}</code>, <code>{'{{.Subject}}'}</code> and <code>{'{{.ContentRaw}}'}</code> ship verbatim and are filled per recipient at send.</p>
				<div class="grid gap-3 sm:grid-cols-2">
					<Field label="Expected response status code"><input type="number" min="1" max="599" bind:value={form.apiExpectedStatus} class="pc-control" /></Field>
				</div>
				<div>
					<div class="flex items-center justify-between">
						<span class="flex items-center gap-2"><span class="pc-label">Expected response headers</span> <span class="pc-optional">optional</span></span>
						<Button variant="blue" size="xs" onclick={() => (form.apiResponseHeaders = [...form.apiResponseHeaders, { key: '', value: '' }])}>+ Add header</Button>
					</div>
					{#each form.apiResponseHeaders as h, hi (hi)}
						<div class="mt-2 flex flex-wrap items-center gap-2">
							<input bind:value={h.key} placeholder="Content-Type" class="pc-control flex-1 min-w-[8rem] text-xs" />
							<input bind:value={h.value} placeholder="application/json" class="pc-control flex-1 min-w-[8rem] text-xs" />
							<Button variant="danger" size="xs" onclick={() => (form.apiResponseHeaders = form.apiResponseHeaders.filter((_, i) => i !== hi))}>Remove</Button>
						</div>
					{/each}
				</div>
				<label class="block text-sm"><span class="pc-label">Expected response body</span> <span class="pc-optional">optional</span>
					<textarea bind:value={form.apiExpectedBody} rows="2" class="mt-1 pc-control font-mono text-xs"></textarea>
				</label>
				<label class="block text-sm"><span class="pc-label">API key</span> <span class="pc-optional">optional</span>
					<span class="relative mt-1 block">
						{#if showApiKey}
							<input type="text" bind:value={form.apiKey} autocomplete="off" placeholder="@@API_KEY@@" class="pc-control pr-16" />
						{:else}
							<input type="password" bind:value={form.apiKey} autocomplete="off" placeholder="@@API_KEY@@" class="pc-control pr-16" />
						{/if}
						<Button variant="neutral" size="xs" onclick={() => (showApiKey = !showApiKey)} ariaLabel={showApiKey ? 'Hide API key' : 'Show API key'} class="absolute right-1 top-1/2 -translate-y-1/2">{showApiKey ? 'Hide' : 'Show'}</Button>
					</span>
				</label>
				<div class="grid gap-3 sm:grid-cols-2">
					<Field label="OAuth provider" optional hint="Use an OAuth provider to obtain an access token for the request.">
						<Select bind:value={form.apiOAuthMode} options={[{ value: 'none', label: 'None' }, { value: 'own', label: 'Installer provides their own OAuth provider' }, { value: 'name', label: 'Reference a provider by name' }]} ariaLabel="OAuth provider" />
					</Field>
					{#if form.apiOAuthMode === 'name'}
						<Field label="Provider name"><input bind:value={form.apiOAuthName} placeholder="@@OAUTH_PROVIDER@@" class="pc-control" /></Field>
					{/if}
				</div>
			</div>
		{/if}

		{#if !isScript && !isAllowDeny && !isProxy && !isRemoteBrowser && !isConfigOnly}
			<div
				class="rounded-xl border bg-white dark:bg-gray-950 p-5 transition-colors {dragging ? 'border-pc-dusty-light-blue ring-2 ring-highlight-blue dark:border-cta-blue dark:ring-pc-darkblue' : 'border-gray-200 dark:border-gray-800'}"
				role="group"
				ondrop={onDrop}
				ondragover={onDragOver}
				ondragleave={onDragLeave}
			>
				<div class="flex items-center justify-between">
					<h2 class="text-sm font-semibold text-gray-700 dark:text-gray-200">{isAttachment ? 'Attachment file' : isAsset ? 'Files' : 'Images / assets'}</h2>
					{#if canAddAssets}
						<label class="pc-btn-xs-blue cursor-pointer">
							{isAttachment ? 'Choose file' : isAsset ? 'Add files' : 'Add images'}
							<input type="file" accept={isAsset || isAttachment ? undefined : 'image/*'} multiple={!isAttachment} class="hidden" onchange={onFiles} />
						</label>
					{:else}
						<span class="pc-btn-xs-neutral cursor-not-allowed opacity-50" title="Set the namespace and name above first">{isAttachment ? 'Choose file' : isAsset ? 'Add files' : 'Add images'}</span>
					{/if}
				</div>
				{#if !canAddAssets}
					<p class="mt-2 text-xs text-amber-700 dark:text-amber-300">Set the namespace and name above first.</p>
				{/if}
				{#if assets.length === 0}
					<p class="mt-2 text-xs text-gray-700 dark:text-gray-200">{#if isAttachment}Choose the file to attach to emails (a document, calendar invite, …).{:else if isAsset}Drag files here or use Add files. They install as shared assets in Phishing Club, available to every domain.{:else}Drag images here or use Add images. They install as shared assets; reference them in your HTML as <code>{'{{.BaseURL}}'}/&lt;file&gt;</code> so they resolve for the sending domain.{/if}</p>
				{:else}
					<ul class="mt-3 space-y-2">
						{#each assets as a, i (i)}
							<li class="flex flex-wrap items-center gap-3 rounded-md border border-gray-100 p-2 dark:border-gray-800">
								{#if isAttachment}
									<code class="min-w-0 flex-1 truncate text-sm">{a.filename}</code>
								{:else}
									<div class="flex min-w-0 flex-1 items-center gap-1.5">
										<span class="shrink-0 font-mono text-xs text-gray-500 dark:text-gray-400">{'{{.BaseURL}}'}/</span>
										<input
											value={a.filename}
											oninput={(e) => onAssetPath(i, e.currentTarget.value)}
											placeholder="images/logo.png"
											class="pc-control px-2 py-1 font-mono text-xs" />
									</div>
								{/if}
								<span class="w-20 shrink-0 text-right text-xs tabular-nums text-gray-600 dark:text-gray-300">{(Math.floor((a.base64.length * 3) / 4) / 1024).toFixed(1)} KB</span>
								{#if !isAttachment && isImageName(a.filename)}
									<Button variant={previewFilename === a.filename ? 'blue' : 'neutral'} size="xs" onclick={() => setPreview(a.filename)} title="Show this image as the package thumbnail">{previewFilename === a.filename ? 'Preview ✓' : 'Set preview'}</Button>
								{/if}
								{#if !isAttachment}<Button variant="neutral" size="xs" onclick={() => copyRef(assetRef(a.filename))}>Copy ref</Button>{/if}
								{#if supportsAssetMeta}
									<Button
										variant={metaOpen[a.filename] ? 'blue' : 'neutral'}
										size="xs"
										onclick={() => (metaOpen[a.filename] = !metaOpen[a.filename])}
										aria-expanded={!!metaOpen[a.filename]}
										title="Name, content type, response headers and allow / deny lists">Settings</Button>
								{/if}
								<Button variant="danger" size="xs" onclick={() => removeAsset(a.filename)}>Remove</Button>
								{#if supportsAssetMeta && !metaOpen[a.filename] && (hasAssetMeta(a) || hasErrors(assetErrs[i]))}
									<p class="basis-full text-xs {hasErrors(assetErrs[i]) ? 'text-red-600 dark:text-red-400' : 'text-gray-600 dark:text-gray-300'}">
										{hasErrors(assetErrs[i]) ? 'Settings have a problem. Open Settings to fix it.' : [a.name.trim(), metaSummary(a)].filter(Boolean).join(' · ')}
									</p>
								{/if}
								{#if supportsAssetMeta && metaOpen[a.filename]}
									<div class="basis-full"><AssetSettings bind:asset={assets[i]} bind:listPkgs bind:listPicks usedNames={usedListNames} {plainVars} errors={assetErrs[i]} namespace={form.namespace} /></div>
								{/if}
							</li>
						{/each}
					</ul>
				{/if}
			</div>
		{/if}

		{#if malformedVars.length}
			<Alert variant="warning">
				<p class="font-semibold text-gray-900 dark:text-white">These look like variables but will ship as literal text:</p>
				<p class="mt-1.5 flex flex-wrap gap-1.5">{#each malformedVars as v}<code class="rounded bg-gray-100 px-1.5 py-0.5 dark:bg-gray-800">@@{v}@@</code>{/each}</p>
				<p class="mt-1.5 text-xs pc-muted">A variable name is UPPERCASE letters, digits and underscores, starting with a letter or underscore (for example <code>@@TARGET_DOMAIN@@</code>). Fix the spelling or they are not substituted on install.</p>
			</Alert>
		{/if}
		{#if missingAssets.length}
			<Alert variant="warning">
				<p class="font-semibold text-gray-900 dark:text-white">Your content references assets that are not included:</p>
				<p class="mt-1.5 flex flex-wrap gap-1.5">{#each missingAssets as a}<code class="rounded bg-gray-100 px-1.5 py-0.5 dark:bg-gray-800">{assetRef(a)}</code>{/each}</p>
				<p class="mt-1.5 text-xs pc-muted">Add the file under Images / assets, or reuse a package that provides it. Otherwise it is a broken reference once installed.</p>
			</Alert>
		{/if}
		{#if proxyHostMismatch}
			<Alert variant="warning">
				<p class="font-semibold text-gray-900 dark:text-white">The start URL host is not a host key in the config:</p>
				<p class="mt-1.5"><code class="rounded bg-gray-100 px-1.5 py-0.5 dark:bg-gray-800">{proxyHostMismatch}</code></p>
				<p class="mt-1.5 text-xs pc-muted">The AiTM proxy routes a victim session by matching its host to a top level key in <code>proxy.yaml</code>. Add a <code>{proxyHostMismatch}:</code> block, or fix the start URL, or the session will not be proxied.</p>
			</Alert>
		{/if}

		{#if detected.length}
			<div class="pc-card p-5">
				<h2 class="text-sm font-semibold text-gray-700 dark:text-gray-200">Variables (detected)</h2>
				<p class="mt-1 text-xs text-gray-700 dark:text-gray-200">Detected from your content. Choose a type; secrets are required and never ship.</p>
				<div class="mt-3 space-y-2">
					{#each detected as v (v)}
						{#if varCfg[v]}
							<div class="rounded-md border border-gray-100 dark:border-gray-800 p-2 space-y-2">
								<div class="flex flex-wrap items-center gap-2 text-sm">
									<code class="min-w-[10rem] shrink-0 whitespace-nowrap">@@{v}@@</code>
									{#if allowDenyPicks.has(v) && isListPick(listPicks[v])}
										<span class="text-gray-700 dark:text-gray-200">The installer picks one of their allow / deny lists. Always required.</span>
									{:else}
									<select value={varCfg[v].type} onchange={(e) => setVarType(v, e.currentTarget.value)} class="pc-control w-auto px-2 py-1">
										<option value="text">text</option>
										<option value="domain">domain</option>
										<option value="url">url</option>
										<option value="secret">secret</option>
										<option value="enum">enum</option>
									</select>
									{#if varCfg[v].type === 'enum'}
										<ListInput value={varCfg[v].options || []} onChange={(next) => { varCfg[v].options = next; if (varCfg[v].default && !next.includes(varCfg[v].default)) varCfg[v].default = ''; }} placeholder="Add a value, press Enter" />
									{/if}
									{#if varCfg[v].type === 'secret'}
										<label class="flex items-center gap-1 text-gray-700 dark:text-gray-200" title="A secret is always required"><input type="checkbox" checked disabled /> required</label>
									{:else}
										<label class="flex items-center gap-1 text-gray-700 dark:text-gray-200"><input type="checkbox" bind:checked={varCfg[v].required} /> required</label>
									{/if}
									{#if !varCfg[v].required && varCfg[v].type !== 'secret'}
										{#if varCfg[v].type === 'enum'}
											<select bind:value={varCfg[v].default} class="pc-control w-auto px-2 py-1">
												<option value="">no default</option>
												{#each varCfg[v].options || [] as opt}<option value={opt}>{opt}</option>{/each}
											</select>
										{:else}
											<input bind:value={varCfg[v].default} placeholder="default" class="pc-control w-auto px-2 py-1" />
										{/if}
									{/if}
									{/if}
								</div>
								<input bind:value={varCfg[v].description} placeholder="Describe this variable so the installer knows what to enter" class="pc-control px-2 py-1 text-xs" />
							</div>
						{/if}
					{/each}
				</div>
			</div>
		{/if}

		<div class="pc-card p-5">
			<button type="button" onclick={() => (showYaml = !showYaml)} class="flex w-full items-center justify-between text-sm font-semibold text-gray-700 dark:text-gray-200">
				<span>Generated data.yaml</span><span class="text-gray-700 dark:text-gray-200">{showYaml ? '−' : '+'}</span>
			</button>
			{#if showYaml}
				<p class="mt-1 text-xs text-gray-700 dark:text-gray-200">The manifest Phishing Club reads to import this package. Built from the fields here.</p>
				<div class="mt-2"><CodeBlock code={dataYaml()} /></div>
			{/if}
		</div>
	</div>

	<!-- DETAILS TAB: registry listing metadata -->
	<div class="mt-4 pc-card p-5 space-y-3 {tab === 'details' ? '' : 'hidden'}">
				<h2 class="text-sm font-semibold text-gray-900 dark:text-white">Registry metadata</h2>
				<p class="pc-hint">How this package is listed and installed. Not part of the package content.</p>
				<p class="pc-hint">Visibility is set on the namespace and applies to every package in it.</p>
				<Field label="Description" optional><textarea bind:value={form.description} rows="2" placeholder="What this package is, shown when browsing the Library in Phishing Club" class="pc-control"></textarea></Field>
				<div class="block text-sm">
					<span class="pc-label">Tags</span> <span class="pc-optional">optional</span>
					<TagEditor bind:value={form.tags} bind:colors={tagColors} bind:pending={pendingTagColors} />
				</div>
			</div>
			<!-- SETTINGS TAB: the content defining fields for this type -->
			{#if form.type === 'email' || isProxy || isDomain || isRemoteBrowser || isReportTemplate}
			<div class="mt-4 pc-card p-5 space-y-3 {tab === 'settings' ? '' : 'hidden'}">
				<h2 class="text-sm font-semibold text-gray-900 dark:text-white">Settings</h2>
				<p class="pc-hint">The content settings that define this package.</p>
				{#if form.type === 'email'}
					<Field label="Subject"><input bind:value={form.subject} class="pc-control" /></Field>
					<div class="grid grid-cols-2 gap-3">
						<label class="text-sm">
							<span class="pc-label">From</span>
							<input bind:value={form.from} placeholder="Support <support@@@TARGET_DOMAIN@@>" class="mt-1 pc-control" />
							<span class="pc-hint">The From header the recipient sees.</span>
						</label>
						<label class="text-sm">
							<span class="pc-label">Envelope from</span> <span class="text-gray-700 dark:text-gray-200 text-xs font-normal">(MAIL FROM)</span> <span class="pc-optional">optional</span>
							<input bind:value={form.envelopeFrom} placeholder="bounce@@@TARGET_DOMAIN@@" class="mt-1 pc-control" />
							<span class="pc-hint">The SMTP envelope sender used for delivery and bounces. Defaults to From when blank.</span>
						</label>
					</div>
					<Checkbox bind:checked={form.addTrackingPixel} label="Add the open tracking pixel" />
				{/if}
				{#if isProxy}
					<label class="block text-sm">
						<span class="pc-label">Start URL</span>
						<input bind:value={form.startURL} placeholder="https://@@TARGET_DOMAIN@@/login" class="mt-1 pc-control" />
						<span class="pc-hint">Where the victim session begins. Its domain must appear as a host key in the config.</span>
					</label>
					<label class="block text-sm">
						<span class="pc-label">Description</span> <span class="pc-optional">optional</span>
						<input bind:value={form.proxyDescription} class="mt-1 pc-control" />
					</label>
				{/if}
				{#if isDomain}
					<label class="block text-sm">
						<span class="pc-label">Domain type</span>
						<select bind:value={form.domainType} class="mt-1 pc-control">
							<option value="regular">regular (serves its own content)</option>
							<option value="proxy">proxy (routes to a proxy target)</option>
						</select>
					</label>
					{#if form.domainType === 'proxy'}
						<label class="block text-sm">
							<span class="pc-label">Proxy target domain</span>
							<input bind:value={form.proxyTargetDomain} placeholder="login.microsoftonline.com" class="mt-1 pc-control" />
							<span class="pc-hint">The real upstream the proxy relays to. Use <code>@@VARIABLES@@</code> for values the installer fills in.</span>
						</label>
					{:else}
						<label class="block text-sm">
							<span class="pc-label">TLS</span>
							<select bind:value={form.domainTLS} class="mt-1 pc-control">
								<option value="managed">managed (Phishing Club obtains a certificate)</option>
								<option value="selfsigned">self signed</option>
								<option value="own">own certificate</option>
							</select>
						</label>
						{#if form.domainTLS === 'own'}
							<label class="block text-sm">
								<span class="pc-label">Certificate (PEM)</span>
								<textarea bind:value={form.ownTLSPem} rows="3" placeholder={'-----BEGIN CERTIFICATE-----'} class="mt-1 pc-control font-mono text-xs"></textarea>
							</label>
							<label class="block text-sm">
								<span class="pc-label">Private key (PEM)</span>
								<textarea bind:value={form.ownTLSKey} rows="3" placeholder={'-----BEGIN PRIVATE KEY-----'} class="mt-1 pc-control font-mono text-xs"></textarea>
							</label>
						{/if}
						<Checkbox bind:checked={form.hostWebsite} label="Host a website (serve the landing page and 404 page)" />
						<label class="block text-sm">
							<span class="pc-label">Redirect URL</span> <span class="pc-optional">optional</span>
							<input bind:value={form.redirectURL} placeholder="https://example.com" class="mt-1 pc-control" />
							<span class="pc-hint">If set, the domain 301-redirects here and serves no content. Use <code>@@VARIABLES@@</code> for values the installer fills in.</span>
						</label>
					{/if}
				{/if}
				{#if isRemoteBrowser}
					<label class="block text-sm">
						<span class="pc-label">Mode</span>
						<select bind:value={form.rbMode} class="mt-1 pc-control">
							<option value="local">local (run Chrome on the server)</option>
							<option value="remote">remote (connect to a DevTools endpoint)</option>
						</select>
					</label>
					{#if form.rbMode === 'remote'}
						<label class="block text-sm">
							<span class="pc-label">Remote endpoint</span>
							<input bind:value={form.rbRemote} placeholder="ws://@@RB_HOST@@:9222/" class="mt-1 pc-control" />
							<span class="pc-hint">The DevTools WebSocket URL to connect to. Use <code>@@VARIABLES@@</code> for the host the installer fills in.</span>
						</label>
					{:else}
						<label class="block text-sm">
							<span class="pc-label">Proxy</span> <span class="pc-optional">optional</span>
							<input bind:value={form.rbProxy} placeholder="socks5://127.0.0.1:1080" class="mt-1 pc-control" />
							<span class="pc-hint">Route the browser through an upstream proxy. <code>socks5://</code> or <code>http://</code>.</span>
						</label>
						<Checkbox bind:checked={form.rbHeadless} label="Run Chrome headless" />
						<label class="block text-sm">
							<span class="pc-label">Language</span> <span class="pc-optional">optional</span>
							<input bind:value={form.rbLang} placeholder="en-US" class="mt-1 pc-control" />
							<span class="pc-hint">A BCP-47 locale for the browser, for example <code>en-US</code>.</span>
						</label>
						<label class="block text-sm">
							<span class="pc-label">Extra Chrome flags</span> <span class="text-gray-700 dark:text-gray-200 text-xs font-normal">(one per line)</span> <span class="pc-optional">optional</span>
							<textarea bind:value={form.rbFlags} rows="3" placeholder={'--disable-gpu\n--window-size=1440,900'} class="mt-1 pc-control font-mono text-xs"></textarea>
							<span class="pc-hint">Passed to the launched Chrome. A <code>!--flag</code> line removes a default flag.</span>
						</label>
					{/if}
					<label class="block text-sm">
						<span class="pc-label">Session timeout</span> <span class="text-gray-700 dark:text-gray-200 text-xs font-normal">(minutes)</span>
						<input type="number" min="0" bind:value={form.rbTimeoutMin} class="mt-1 pc-control" />
						<span class="pc-hint">How long a session may run before it is closed. Shipped as milliseconds.</span>
					</label>
					<label class="block text-sm">
						<span class="pc-label">Description</span> <span class="pc-optional">optional</span>
						<input bind:value={form.rbDescription} class="mt-1 pc-control" />
					</label>
				{/if}
				{#if isReportTemplate}
					<div class="text-sm">
						<span class="pc-label">Report kind</span>
						<div class="mt-1 flex flex-col gap-1.5">
							<label class="flex items-center gap-2 text-gray-800 dark:text-gray-100"><input type="radio" bind:group={form.training} value={false} /> Phishing simulation report</label>
							<label class="flex items-center gap-2 text-gray-800 dark:text-gray-100"><input type="radio" bind:group={form.training} value={true} /> Awareness training report</label>
						</div>
						<span class="pc-hint">Phishing Club keeps one report template per kind and picks it by the campaign's training flag.</span>
					</div>
				{/if}
			</div>
			{/if}

		<!-- ATTACHMENTS TAB: files attached to the email, email type only -->
		{#if form.type === 'email'}
		<div class="mt-4 pc-card p-5 space-y-3 {tab === 'attachments' ? '' : 'hidden'}">
			<div class="flex items-center justify-between">
				<h2 class="text-sm font-semibold text-gray-900 dark:text-white">Attachments</h2>
				{#if canAddAssets}
					<label class="pc-btn-xs-neutral cursor-pointer">
						Add files
						<input type="file" multiple class="hidden" onchange={onAttachmentFiles} />
					</label>
				{:else}
					<span class="pc-btn-xs-neutral cursor-not-allowed opacity-50" title="Set the namespace and name above first">Add files</span>
				{/if}
			</div>
			{#if emailAttachments.length === 0}
				<p class="text-xs text-gray-700 dark:text-gray-200">Files to attach to the email. On install they are added to the email in Phishing Club.</p>
			{:else}
				<ul class="space-y-2">
					{#each emailAttachments as a (a.filename)}
						<li class="rounded-lg border border-gray-200 dark:border-gray-800 p-3 space-y-2">
							<div class="flex items-center justify-between gap-2">
								<span class="truncate font-mono text-xs text-gray-700 dark:text-gray-200">{a.filename}</span>
								<Button variant="danger" size="xs" onclick={() => removeAttachment(a.filename)}>Remove</Button>
							</div>
							<div class="grid grid-cols-2 gap-2">
								<label class="text-sm"><span class="pc-label">Name</span><input bind:value={a.name} class="mt-1 pc-control" /></label>
								<label class="text-sm"><span class="pc-label">Description</span> <span class="pc-optional">optional</span><input bind:value={a.description} class="mt-1 pc-control" /></label>
							</div>
							<div class="flex flex-wrap gap-4">
								<Checkbox bind:checked={a.embedded} label="Embedded" />
								<Checkbox bind:checked={a.inline} label="Inline" />
								{#if isIcs(a.filename)}
									<Checkbox bind:checked={a.calendar} label="Send as calendar" />
								{/if}
							</div>
							{#if a.inline}
								<p class="pc-hint">Reference it in the email HTML as <code>cid:{a.filename}</code>.</p>
							{/if}
						</li>
					{/each}
				</ul>
			{/if}
		</div>
		{/if}

		<!-- DETAILS TAB: library preview images (listing) -->
		<div class="mt-4 pc-card p-5 {tab === 'details' ? '' : 'hidden'}">
			<div class="flex items-center justify-between">
				<div class="flex items-center gap-2">
					<h2 class="text-sm font-semibold text-gray-900 dark:text-white">Preview images</h2>
					<Help title="Preview images">
						<p>Images shown when browsing this package in the Library and on its page.</p>
						<p>They are <strong>package metadata</strong>, not shipped inside the package and not referenceable from your content. Use them to show what the package looks like. You can add or remove them later on the package page.</p>
						<p>{PREVIEW_LIMITS_TEXT}</p>
					</Help>
				</div>
				<label class="pc-btn-xs-neutral cursor-pointer">
					Add images
					<input type="file" accept={PREVIEW_ACCEPT} multiple class="hidden" onchange={onPreviewMeta} />
				</label>
			</div>
			{#if previewMeta.length}
				<div class="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4">
					{#each previewMeta as p (p.filename)}
						<div class="relative overflow-hidden rounded-lg border border-gray-200 dark:border-gray-800">
							<img src={`data:${p.mediaType};base64,${p.base64}`} alt={p.filename} class="h-28 w-full object-cover" />
							<Button variant="danger" size="xs" onclick={() => removePreviewMeta(p.filename)} class="absolute right-1 top-1 bg-white/90 dark:bg-gray-950/90">Remove</Button>
							<div class="truncate px-2 py-1 text-xs text-gray-700 dark:text-gray-200" title={p.filename}>{p.filename}</div>
						</div>
					{/each}
				</div>
			{:else}
				<p class="mt-3 text-xs text-gray-700 dark:text-gray-200">No preview images yet. These help operators recognize the package when browsing the Library.</p>
			{/if}
		</div>
</div>
{/if}
