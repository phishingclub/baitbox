// Phishing Club send time template variables and functions. Phishing Club fills these
// per recipient when a campaign sends; here they power the editor Insert menu and the
// live preview. Preview values are samples only, so authors see realistic output.

const RECIPIENT = [
	{ label: 'First name', text: '{{.FirstName}}' },
	{ label: 'Last name', text: '{{.LastName}}' },
	{ label: 'Email', text: '{{.Email}}' },
	{ label: 'Phone', text: '{{.Phone}}' },
	{ label: 'Position', text: '{{.Position}}' },
	{ label: 'Department', text: '{{.Department}}' },
	{ label: 'City', text: '{{.City}}' },
	{ label: 'Country', text: '{{.Country}}' },
	{ label: 'Misc', text: '{{.Misc}}' }
];

const URLS = [
	{ label: 'Base URL', text: '{{.BaseURL}}' },
	{ label: 'Phishing URL', text: '{{.URL}}' },
	{ label: 'Before landing page URL', text: '{{.BeforeLandingPageURL}}' },
	{ label: 'Landing page URL', text: '{{.LandingPageURL}}' },
	{ label: 'After landing page URL', text: '{{.AfterLandingPageURL}}' }
];

const EMAIL_HEADER = [
	{ label: 'To', text: '{{.To}}' },
	{ label: 'From', text: '{{.From}}' }
];

const EMAIL_TRACKING = [
	{ label: 'Tracker (open pixel)', text: '{{.Tracker}}' },
	{ label: 'Tracking URL', text: '{{.TrackingURL}}' }
];

const FUNCTIONS = [
	{ label: 'URL as QR code', text: '{{qr .URL 4}}' },
	{ label: 'URL escape', text: '{{urlEscape "content"}}' },
	{ label: 'Random letters', text: '{{randAlpha 8}}' },
	{ label: 'Random number', text: '{{randInt 1 4}}' },
	{ label: 'Date', text: '{{date "Y-m-d H:i:s" 0}}' },
	{ label: 'Base64', text: '{{base64 "text"}}' },
	{ label: 'Multiply', text: '{{mul 1.0 1.0}}' }
];

// Microsoft device code flow variables. In phishingclub these are red team
// (blackbox) content on emails and landing pages, filled per recipient when the
// device code campaign runs. Not applicable to reports.
const DEVICE_CODE = [
	{ label: 'User code', text: '{{MicrosoftDeviceCode}}' },
	{ label: 'Verification URL', text: '{{MicrosoftDeviceCodeURL}}' },
	{ label: 'Captured', text: '{{DeviceCodeCaptured}}' }
];

// Remote browser injected script, landing pages only. RemoteBrowserScript names
// the remote browser the page drives; phishingclub swaps in the obfuscated JS.
const REMOTE_BROWSER = [
	{ label: 'Script', text: '{{RemoteBrowserScript "remote_browser_name"}}' }
];

const REPORT_CAMPAIGN = [
	{ label: 'Campaign name', text: '{{.CampaignName}}' },
	{ label: 'Company name', text: '{{.CompanyName}}' },
	{ label: 'Report date', text: '{{.ReportDate}}' },
	{ label: 'Start date', text: '{{.CampaignStartDate}}' },
	{ label: 'End date', text: '{{.CampaignEndDate}}' },
	{ label: 'Total targets', text: '{{.TotalTargets}}' }
];

const REPORT_RESULTS = [
	{ label: 'Emails sent', text: '{{.EmailsSent}}' },
	{ label: 'Emails opened', text: '{{.EmailsOpened}}' },
	{ label: 'Clicked (count)', text: '{{.ResultClicked}}' },
	{ label: 'Clicked (%)', text: '{{.ResultClickedPercent}}' },
	{ label: 'Submitted (count)', text: '{{.ResultSubmitted}}' },
	{ label: 'Submitted (%)', text: '{{.ResultSubmittedPercent}}' },
	{ label: 'Reported (count)', text: '{{.ResultReported}}' },
	{ label: 'Reported (%)', text: '{{.ResultReportedPercent}}' }
];

// grouped variables offered for a given package type (null = no send time variables,
// so the type has no Insert menu, e.g. proxy/script which only use install time @@VAR@@ slots)
export function variableGroups(type) {
	if (type === 'email') {
		return {
			Recipient: RECIPIENT,
			Email: EMAIL_HEADER,
			'URLs & tracking': [...URLS, ...EMAIL_TRACKING],
			'Device Code': DEVICE_CODE,
			Functions: FUNCTIONS
		};
	}
	if (type === 'page') {
		return {
			Recipient: RECIPIENT,
			'URLs & tracking': URLS,
			'Device Code': DEVICE_CODE,
			'Remote Browser': REMOTE_BROWSER,
			Functions: FUNCTIONS
		};
	}
	if (type === 'reporttemplate') {
		return { Campaign: REPORT_CAMPAIGN, Results: REPORT_RESULTS, Functions: FUNCTIONS };
	}
	// a domain serves its own flat content, so recipient and tracking variables do not
	// apply, but the template functions still do (like phishingclub's domain editor).
	if (type === 'domain') {
		return { Functions: FUNCTIONS };
	}
	return null;
}

// sample values for the live preview only
const SAMPLES = {
	FirstName: 'Alex',
	LastName: 'Taylor',
	Name: 'Alex Taylor',
	Email: 'alex.taylor@example.com',
	To: 'Alex Taylor <alex.taylor@example.com>',
	From: 'IT Support <it@example.com>',
	FromName: 'IT Support',
	Phone: '+1 555 0100',
	Position: 'Analyst',
	Department: 'Finance',
	City: 'Austin',
	Country: 'United States',
	Misc: 'VIP',
	Company: 'Example Inc',
	BaseURL: 'https://example.com',
	URL: 'https://example.com/s/aX9k2',
	BeforeLandingPageURL: 'https://example.com/s/aX9k2?state=before',
	LandingPageURL: 'https://example.com/s/aX9k2?state=landing',
	AfterLandingPageURL: 'https://example.com/s/aX9k2?state=after',
	DenyURL: 'https://example.com/report',
	TrackingURL: 'https://example.com/wf/open?upn=sample',
	Tracker:
		'<img src="https://example.com/wf/open?upn=sample" alt="" width="1" height="1" style="width:1px;height:1px" />',
	CampaignName: 'Q1 Phishing Simulation',
	CompanyName: 'Example Inc',
	ReportDate: new Date().toLocaleDateString(),
	CampaignStartDate: '2026-01-01',
	CampaignEndDate: '2026-01-31',
	TotalTargets: '120',
	EmailsSent: '118',
	EmailsOpened: '74',
	ResultClicked: '32',
	ResultClickedPercent: '27.1',
	ResultSubmitted: '14',
	ResultSubmittedPercent: '11.9',
	ResultReported: '8',
	ResultReportedPercent: '6.8'
};

function randAlpha(n) {
	const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
	let out = '';
	for (let i = 0; i < Math.min(n, 32); i++) out += chars[Math.floor(Math.random() * chars.length)];
	return out;
}

// format a date the way Go's date filter does (Y m d H i s ...), for preview only
function formatDate(fmt, offsetSeconds) {
	const d = new Date(Date.now() + (offsetSeconds || 0) * 1000);
	const pad = (x) => String(x).padStart(2, '0');
	const map = {
		Y: d.getFullYear(),
		y: String(d.getFullYear()).slice(-2),
		m: pad(d.getMonth() + 1),
		n: d.getMonth() + 1,
		d: pad(d.getDate()),
		j: d.getDate(),
		H: pad(d.getHours()),
		G: d.getHours(),
		h: pad(d.getHours() % 12 || 12),
		g: d.getHours() % 12 || 12,
		i: pad(d.getMinutes()),
		s: pad(d.getSeconds()),
		A: d.getHours() >= 12 ? 'PM' : 'AM',
		a: d.getHours() >= 12 ? 'pm' : 'am'
	};
	let out = fmt;
	for (const [k, v] of Object.entries(map)) out = out.replaceAll(k, String(v));
	return out;
}

const QR_PLACEHOLDER =
	'<span style="display:inline-flex;align-items:center;justify-content:center;width:96px;height:96px;border:1px solid #888;color:#888;font:12px monospace">QR</span>';

// substitute send time {{.Var}} tokens and {{func ...}} calls with sample values, for the
// live preview. install time @@VAR@@ slots are handled by the caller; unknown tokens are
// left untouched so authors still see them.
export function fillPreview(html) {
	let h = String(html ?? '');
	h = h.replace(/\{\{\s*qr\s+[^}]*\}\}/g, QR_PLACEHOLDER);
	h = h.replace(/\{\{\s*urlEscape\s+"([^"]*)"\s*\}\}/g, (_, s) => encodeURIComponent(s));
	h = h.replace(/\{\{\s*randAlpha\s+(\d+)\s*\}\}/g, (_, n) => randAlpha(Number(n)));
	h = h.replace(/\{\{\s*randInt\s+(\d+)\s+(\d+)\s*\}\}/g, (_, a, b) => {
		const lo = Number(a);
		const hi = Number(b);
		return String(Math.floor(Math.random() * (hi - lo + 1)) + lo);
	});
	h = h.replace(/\{\{\s*base64\s+"([^"]*)"\s*\}\}/g, (_, s) => {
		try {
			return btoa(s);
		} catch (_e) {
			return s;
		}
	});
	h = h.replace(/\{\{\s*date\s+"([^"]+)"\s*(-?\d+)?\s*\}\}/g, (_, fmt, off) =>
		formatDate(fmt, off ? Number(off) : 0)
	);
	h = h.replace(/\{\{\s*mul\s+([\d.]+)\s+([\d.]+)\s*\}\}/g, (_, a, b) => String(Number(a) * Number(b)));
	// device code and remote browser tokens (no leading dot): show representative
	// sample output so the preview is not littered with raw tokens.
	h = h.replace(/\{\{\s*MicrosoftDeviceCodeURL\s*\}\}/g, 'https://microsoft.com/devicelogin');
	h = h.replace(/\{\{\s*MicrosoftDeviceCode\s*\}\}/g, 'ABCD-1234');
	h = h.replace(/\{\{\s*DeviceCodeCaptured\s*\}\}/g, 'false');
	h = h.replace(/\{\{\s*RemoteBrowserScript\s+"[^"]*"\s*\}\}/g, '');
	h = h.replace(/\{\{\s*\.(\w+)\s*\}\}/g, (m, n) => (n in SAMPLES ? SAMPLES[n] : m));
	return h;
}
