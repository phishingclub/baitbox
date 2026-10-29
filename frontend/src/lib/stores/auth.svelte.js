function createAuth() {
	let operator = $state(null);
	return {
		get operator() {
			return operator;
		},
		set(op) {
			operator = op;
		},
		clear() {
			operator = null;
		}
	};
}

export const auth = createAuth();
