// Shared wording for the result of a registry or package bundle import.

// importSummary says what an import added. Nothing new means everything in the
// bundle was already present or was refused.
export function importSummary(data) {
	const n = data?.namespaces || 0;
	const p = data?.packages || 0;
	const v = data?.versions || 0;
	const refused = data?.refused?.length || 0;
	let text;
	if (n + p + v === 0) {
		text = refused ? 'Imported: nothing new' : 'Imported: nothing new (everything was already present)';
	} else {
		const parts = [];
		if (p) parts.push(`${p} package${p === 1 ? '' : 's'}`);
		if (v) parts.push(`${v} version${v === 1 ? '' : 's'}`);
		if (n) parts.push(`${n} namespace${n === 1 ? '' : 's'}`);
		text = 'Imported ' + parts.join(', ');
	}
	if (refused) text += `; ${refused} package${refused === 1 ? '' : 's'} refused`;
	return text;
}

// importNeedsDetail reports whether the result has more to show than the one line
// summary: refused, upgraded or skipped packages, or a warning.
export function importNeedsDetail(data) {
	return !!(data?.refused?.length || data?.warnings?.length || data?.upgraded?.length || data?.skipped?.length);
}
