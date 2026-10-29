// Browser helpers for the WebAuthn ceremonies. The server (go-webauthn)
// sends challenge / id fields as base64url strings and expects the credential
// response fields back the same way; navigator.credentials works in ArrayBuffers,
// so we decode on the way in and encode on the way out.

function b64urlToBuf(s) {
	s = String(s).replace(/-/g, '+').replace(/_/g, '/');
	const pad = s.length % 4;
	if (pad) s += '='.repeat(4 - pad);
	const bin = atob(s);
	const u = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
	return u.buffer;
}

function bufToB64url(buf) {
	const u = new Uint8Array(buf);
	let s = '';
	for (const b of u) s += String.fromCharCode(b);
	return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function supported() {
	return typeof window !== 'undefined' && !!window.PublicKeyCredential && !!navigator.credentials;
}

// run a registration ceremony from the server's CredentialCreation options and
// return the attestation response ready to send back.
export async function createCredential(options) {
	const pk = options.publicKey || options;
	pk.challenge = b64urlToBuf(pk.challenge);
	pk.user.id = b64urlToBuf(pk.user.id);
	if (Array.isArray(pk.excludeCredentials)) {
		pk.excludeCredentials = pk.excludeCredentials.map((c) => ({ ...c, id: b64urlToBuf(c.id) }));
	}
	const cred = await navigator.credentials.create({ publicKey: pk });
	const transports =
		cred.response.getTransports && typeof cred.response.getTransports === 'function'
			? cred.response.getTransports()
			: undefined;
	return {
		id: cred.id,
		rawId: bufToB64url(cred.rawId),
		type: cred.type,
		response: {
			attestationObject: bufToB64url(cred.response.attestationObject),
			clientDataJSON: bufToB64url(cred.response.clientDataJSON)
		},
		clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
		transports
	};
}

// run an assertion ceremony from the server's CredentialAssertion options and
// return the assertion response ready to send back.
export async function getCredential(options) {
	const pk = options.publicKey || options;
	pk.challenge = b64urlToBuf(pk.challenge);
	if (Array.isArray(pk.allowCredentials)) {
		pk.allowCredentials = pk.allowCredentials.map((c) => ({ ...c, id: b64urlToBuf(c.id) }));
	}
	const cred = await navigator.credentials.get({ publicKey: pk });
	return {
		id: cred.id,
		rawId: bufToB64url(cred.rawId),
		type: cred.type,
		response: {
			authenticatorData: bufToB64url(cred.response.authenticatorData),
			clientDataJSON: bufToB64url(cred.response.clientDataJSON),
			signature: bufToB64url(cred.response.signature),
			userHandle: cred.response.userHandle ? bufToB64url(cred.response.userHandle) : ''
		},
		clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {}
	};
}
