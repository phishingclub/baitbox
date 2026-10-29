// Friendly display names for package types. The stored type stays the raw slug
// (page, reporttemplate, ...); this is only for showing it to an operator.
const LABELS = {
	page: 'Landing page',
	email: 'Email',
	script: 'Script',
	proxy: 'Proxy',
	remotebrowser: 'Remote browser',
	allowdeny: 'Allow / deny list',
	asset: 'Asset bundle',
	attachment: 'Attachment',
	reporttemplate: 'Report template',
	smtp: 'SMTP configuration',
	apisender: 'API sender',
	oauthprovider: 'OAuth provider',
	webhook: 'Webhook',
	template: 'Campaign template',
	domain: 'Domain site',
	bundle: 'Bundle'
};

export function typeLabel(type) {
	return LABELS[type] || type || '';
}
