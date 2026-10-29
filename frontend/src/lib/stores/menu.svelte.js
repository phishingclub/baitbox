// Tracks which row action menu is open so only one is ever open at a time. Each
// RowMenu has a unique id and asks this store to toggle or close it.
let openId = $state(null);

export const menu = {
	get openId() {
		return openId;
	},
	toggle(id) {
		openId = openId === id ? null : id;
	},
	close() {
		openId = null;
	}
};
