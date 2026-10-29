// Type declarations the script editor feeds Monaco for autocomplete on campaign
// event scripts. It mirrors the bindings Phishing Club's script engine exposes
// (a goja sandbox run when a subscribed campaign event fires), so a baitbox author
// gets the same completion the native Phishing Club script editor gives.

export const scriptDTS = `
/** The event that triggered this script. Already filtered for the
 * campaign's anonymity and the configured data level, so fields may be empty. */
declare const event: {
	/** event name, e.g. "campaign_recipient_submitted_data" */
	name: string;
	/** the campaign id */
	campaignId: string;
	/** the recipient id, empty for campaign level events */
	recipientId: string;
	/** the campaign name, empty at the "none" data level */
	campaignName: string;
	/** the recipient email, only at "full" level on a non anonymous campaign */
	email: string;
	/** captured data, only at "full" level */
	data: Record<string, any>;
};

/**
 * input is the data object passed when this script is run in callable mode,
 * e.g. from a remote browser script via runScript('name', data). It is an empty
 * object for campaign event triggered runs. Return an object to send data back
 * to the caller (callable mode only).
 */
declare const input: Record<string, any>;

interface FetchOptions {
	/** HTTP method: GET (default), POST, PUT, PATCH, DELETE, ... */
	method?: string;
	/** request headers, e.g. { 'Content-Type': 'application/json' } */
	headers?: Record<string, string>;
	/** request body (a string; use encode.json(obj) for JSON) */
	body?: string;
	/** route this request through a proxy: http://, https:// or socks5:// */
	proxy?: string;
	/** per request timeout in milliseconds (max 30000) */
	timeoutMs?: number;
}

interface FetchResponse {
	/** HTTP status code, e.g. 200 */
	status: number;
	/** response headers */
	headers: Record<string, string>;
	/** response body as a string (use decode.json(res.body) to parse JSON) */
	body: string;
}

declare const http: {
	/**
	 * Send a synchronous HTTP request and return the response. Any method is
	 * supported. Blocks until the response arrives or the timeout fires; throws
	 * on a network error, so wrap it in try/catch if you want to handle failures.
	 *
	 * @example
	 * const res = http.fetch('https://api.example.test/users/42');
	 * if (res.status === 200) {
	 *   const user = decode.json(res.body);
	 *   log('got user', { name: user.name });
	 * }
	 *
	 * @example
	 * const res = http.fetch('https://api.example.test/hook', {
	 *   method: 'POST',
	 *   headers: { 'Content-Type': 'application/json' },
	 *   body: encode.json({ event: event.name, email: event.email })
	 * });
	 */
	fetch(url: string, options?: FetchOptions): FetchResponse;
};

/** Output encoding for hash / hmac / random. Defaults to "hex". */
type OutputEncoding = 'hex' | 'base64' | 'base64url' | 'base32';

declare const encode: {
	base64(s: string): string;
	/** URL safe base64, no padding (JWT / OAuth) */
	base64url(s: string): string;
	base32(s: string): string;
	hex(s: string): string;
	/** query escape (space as +) */
	url(s: string): string;
	/** path segment escape */
	urlPath(s: string): string;
	html(s: string): string;
	/** JSON stringify any value */
	json(value: any): string;
	/** object -> application/x-www-form-urlencoded */
	form(obj: Record<string, any>): string;
	/** gzip then base64 */
	gzip(s: string): string;
	/** raw deflate then base64 */
	deflate(s: string): string;
};

declare const decode: {
	base64(s: string): string;
	base64url(s: string): string;
	base32(s: string): string;
	hex(s: string): string;
	url(s: string): string;
	urlPath(s: string): string;
	html(s: string): string;
	/** JSON parse a string into a value */
	json(s: string): any;
	/** form encoded string -> object (repeated key -> array) */
	form(s: string): Record<string, any>;
	/** base64 of gzip -> string */
	gzip(s: string): string;
	/** base64 of deflate -> string */
	deflate(s: string): string;
};

/** Hashing. hash.sha256(input) -> hex; pass an encoding for base64 etc. */
declare const hash: {
	md5(input: string, encoding?: OutputEncoding): string;
	sha1(input: string, encoding?: OutputEncoding): string;
	sha256(input: string, encoding?: OutputEncoding): string;
	sha384(input: string, encoding?: OutputEncoding): string;
	sha512(input: string, encoding?: OutputEncoding): string;
};

/** Keyed HMAC signing, e.g. for request or webhook signatures. */
declare const hmac: {
	sha1(key: string, message: string, encoding?: OutputEncoding): string;
	sha256(key: string, message: string, encoding?: OutputEncoding): string;
	sha384(key: string, message: string, encoding?: OutputEncoding): string;
	sha512(key: string, message: string, encoding?: OutputEncoding): string;
};

declare const jwt: {
	/** Split and JSON parse a JWT. Does NOT verify the signature. */
	decode(token: string): { header: any; payload: any; signature: string };
};

/** Secure random for nonces, PKCE verifiers, OAuth state. */
declare const random: {
	/** n random bytes (1..4096) in the given encoding, default hex */
	bytes(n: number, encoding?: OutputEncoding): string;
	uuid(): string;
};

/** Write a line to the server logs (for debugging). Not visible in the app. */
declare function log(message: string, data?: any): void;

/** Record a campaign_recipient_info event, visible in the campaign timeline.
 * The detail follows the campaign's data retention and anonymity rules.
 * Uncaught exceptions and timeouts are recorded automatically the same way. */
declare function info(message: string, data?: Record<string, any>): void;

/** The events a script may create with emitEvent. Server detected outcomes
 * (opens, clicks, reports, delivery, training) cannot be forged. */
type EmittableEvent = 'campaign_recipient_submitted_data' | 'campaign_recipient_info';

/** Create a new campaign event in this same campaign and recipient context, for
 * data the script itself authored (e.g. a token obtained via http.fetch). Goes
 * through the same storage and anonymization rules as native capture: data is
 * stored only when the campaign keeps submitted data, and stripped on anonymous
 * campaigns.
 *
 * @example
 * emitEvent('campaign_recipient_submitted_data', { accessToken: token }); */
declare function emitEvent(name: EmittableEvent, data?: Record<string, any>): void;

/** End the script early. */
declare function stop(): void;
`;
