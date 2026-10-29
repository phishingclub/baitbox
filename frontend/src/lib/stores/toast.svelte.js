// Toast store using Svelte 5 runes. Components read toastStore.items in markup.
function createToasts() {
	let items = $state([]);
	return {
		get items() {
			return items;
		},
		add(message, type = 'info') {
			const id = Date.now() + Math.random();
			items.push({ id, message, type });
			// errors linger so a longer message can be read; others clear sooner
			setTimeout(() => this.remove(id), type === 'error' ? 8000 : 4500);
		},
		remove(id) {
			const i = items.findIndex((t) => t.id === id);
			if (i >= 0) items.splice(i, 1);
		}
	};
}

export const toastStore = createToasts();
export const toast = (m, t) => toastStore.add(m, t);
