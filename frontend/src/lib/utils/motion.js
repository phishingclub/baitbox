// Svelte transitions are JS driven, so the CSS prefers-reduced-motion rule does not reach
// them. motionDuration returns 0 when the operator prefers reduced motion, making the
// transition instant, otherwise the given duration. Read at transition time (element
// mount), which is enough; a mid session preference change is rare.
export function motionDuration(ms) {
	try {
		return window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 0 : ms;
	} catch (_) {
		return ms;
	}
}
