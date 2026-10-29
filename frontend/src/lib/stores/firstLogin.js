// holds the password typed at login, in memory only, so the first login
// password change does not ask for it again. It is read once and gone after a
// page reload, when the setup page asks for it instead.
let pending = '';

export function holdLoginPassword(password) {
	pending = password;
}

export function takeLoginPassword() {
	const p = pending;
	pending = '';
	return p;
}
