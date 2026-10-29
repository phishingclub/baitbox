// Namespace color labels. The key is what the backend stores (an allowlisted
// token); the class strings are written out in full so Tailwind generates them.
// An unknown or empty key falls back to a neutral dot, so nothing free form is
// ever turned into a style.
export const NS_COLORS = [
	{ key: 'slate', dot: 'bg-slate-500' },
	{ key: 'red', dot: 'bg-red-500' },
	{ key: 'orange', dot: 'bg-orange-500' },
	{ key: 'amber', dot: 'bg-amber-500' },
	{ key: 'green', dot: 'bg-green-500' },
	{ key: 'teal', dot: 'bg-teal-500' },
	{ key: 'sky', dot: 'bg-sky-500' },
	{ key: 'blue', dot: 'bg-blue-500' },
	{ key: 'violet', dot: 'bg-violet-500' },
	{ key: 'pink', dot: 'bg-pink-500' }
];

const MAP = Object.fromEntries(NS_COLORS.map((c) => [c.key, c.dot]));

// isHex reports whether a stored color is a custom #rrggbb value rather than a named
// token. A custom color is applied as an inline style; a token maps to a class.
export function isHex(key) {
	return typeof key === 'string' && /^#[0-9a-f]{6}$/i.test(key);
}

// the dot class for a namespace color key, or a neutral default for none/unknown. A
// custom hex has no class (nsDotStyle supplies its color).
// hasOwnProperty guards against a token resolving an inherited prototype member.
export function nsDotClass(key) {
	if (isHex(key)) return '';
	return Object.prototype.hasOwnProperty.call(MAP, key) ? MAP[key] : 'bg-gray-300 dark:bg-gray-600';
}

// nsDotStyle is the inline style for a custom hex dot (a solid fill), empty for a
// named token or none.
export function nsDotStyle(key) {
	return isHex(key) ? `background-color: ${key};` : '';
}

// full chip classes per tag color token: a tinted background, readable text and a
// subtle ring, in light and dark. written out in full so Tailwind generates each,
// never built from fragments. an empty or unknown key falls back to neutral gray.
const TAG_CHIP = {
	slate: 'bg-slate-100 text-slate-700 ring-1 ring-slate-500/20 dark:bg-slate-400/15 dark:text-slate-200 dark:ring-slate-300/25',
	red: 'bg-red-100 text-red-700 ring-1 ring-red-500/20 dark:bg-red-400/15 dark:text-red-200 dark:ring-red-300/25',
	orange: 'bg-orange-100 text-orange-700 ring-1 ring-orange-500/20 dark:bg-orange-400/15 dark:text-orange-200 dark:ring-orange-300/25',
	amber: 'bg-amber-100 text-amber-800 ring-1 ring-amber-500/20 dark:bg-amber-400/15 dark:text-amber-200 dark:ring-amber-300/25',
	green: 'bg-green-100 text-green-700 ring-1 ring-green-500/20 dark:bg-green-400/15 dark:text-green-200 dark:ring-green-300/25',
	teal: 'bg-teal-100 text-teal-700 ring-1 ring-teal-500/20 dark:bg-teal-400/15 dark:text-teal-200 dark:ring-teal-300/25',
	sky: 'bg-sky-100 text-sky-700 ring-1 ring-sky-500/20 dark:bg-sky-400/15 dark:text-sky-200 dark:ring-sky-300/25',
	blue: 'bg-blue-100 text-blue-700 ring-1 ring-blue-500/20 dark:bg-blue-400/15 dark:text-blue-200 dark:ring-blue-300/25',
	violet: 'bg-violet-100 text-violet-700 ring-1 ring-violet-500/20 dark:bg-violet-400/15 dark:text-violet-200 dark:ring-violet-300/25',
	pink: 'bg-pink-100 text-pink-700 ring-1 ring-pink-500/20 dark:bg-pink-400/15 dark:text-pink-200 dark:ring-pink-300/25'
};
const TAG_CHIP_NEUTRAL = 'bg-gray-100 text-gray-800 ring-1 ring-gray-500/15 dark:bg-gray-800 dark:text-gray-100 dark:ring-gray-400/20';

// neutral text and ring for a custom hex chip. It carries no background class so the
// hex tint from tagChipStyle shows through, and the text stays readable in both
// modes regardless of the chosen color.
const TAG_CHIP_HEX = 'text-gray-800 ring-1 ring-gray-500/15 dark:text-gray-100 dark:ring-gray-400/20';

// the chip classes for a tag color key, or a neutral default for none/unknown. A
// custom hex gets the neutral text/ring (no background class) so tagChipStyle's tint
// is visible.
export function tagChipClass(key) {
	if (isHex(key)) return TAG_CHIP_HEX;
	return Object.prototype.hasOwnProperty.call(TAG_CHIP, key) ? TAG_CHIP[key] : TAG_CHIP_NEUTRAL;
}

// tagChipStyle is the inline style for a custom hex chip: a faint tint of the chosen
// color as the background. Empty for a named token or none.
export function tagChipStyle(key) {
	return isHex(key) ? `background-color: ${key}2e;` : '';
}
