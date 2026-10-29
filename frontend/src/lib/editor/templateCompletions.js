// Monaco completion for Phishing Club send time template variables and functions.
// The catalog is the same one that powers the Insert menu and the live preview
// (variableGroups in lib/utils/pcVariables.js), so typing in the HTML editor offers
// the recipient fields, URLs, tracking tokens and template functions for the package
// type without opening the menu.

import { variableGroups } from '$lib/utils/pcVariables.js';

// one live registration per package type, so switching types or remounting the editor
// does not stack duplicate providers. keyed by type, so registering again replaces cleanly.
const registered = new Map();

const NOOP = { dispose() {} };

export function registerTemplateCompletions(monaco, type) {
	// drop any earlier provider for this type before adding a fresh one
	const prev = registered.get(type);
	if (prev) {
		prev.dispose();
		registered.delete(type);
	}

	const groups = variableGroups(type);
	if (!groups) return NOOP;

	// flatten the grouped catalog into Monaco suggestions once; the group name is the
	// detail shown beside each entry, and the Functions group reads as a function.
	const items = [];
	for (const [group, entries] of Object.entries(groups)) {
		const isFn = group === 'Functions';
		for (const entry of entries) {
			items.push({
				label: entry.label,
				detail: group,
				insertText: entry.text,
				kind: isFn
					? monaco.languages.CompletionItemKind.Function
					: monaco.languages.CompletionItemKind.Variable,
				// show the token itself so an author can scan what each entry inserts
				documentation: entry.text
			});
		}
	}

	const disposable = monaco.languages.registerCompletionItemProvider('html', {
		triggerCharacters: ['{', '.'],
		provideCompletionItems(model, position) {
			const word = model.getWordUntilPosition(position);
			const range = {
				startLineNumber: position.lineNumber,
				endLineNumber: position.lineNumber,
				startColumn: word.startColumn,
				endColumn: word.endColumn
			};
			return { suggestions: items.map((it) => ({ ...it, range })) };
		}
	});

	registered.set(type, disposable);
	return disposable;
}
