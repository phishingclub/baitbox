<script>
	import { isHex } from '$lib/utils/nsColor.js';

	// value is the current color: a '#rrggbb', a named token, or ''. onpick is called
	// with the chosen '#rrggbb' when the popover closes, not during a drag, so a save
	// tied to onpick fires once per edit.
	let { value = '', onpick } = $props();

	let open = $state(false);
	let alignRight = $state(false); // open leftward when the trigger sits near the right edge
	let hue = $state(260); // 0..359
	let sat = $state(70); // 0..100
	let val = $state(80); // 0..100
	let hex = $state(''); // live edited color
	let btnEl;
	let svEl;
	let dragging = false;

	// the trigger swatch shows the live edit while open, the stored hex when set, or a
	// rainbow as the "pick any color" affordance.
	const innerStyle = $derived.by(() => {
		if (open && isHex(hex)) return `background-color: ${hex};`;
		if (isHex(value)) return `background-color: ${value};`;
		return 'background: conic-gradient(from 0deg, #ef4444, #f59e0b, #10b981, #3b82f6, #8b5cf6, #ec4899, #ef4444);';
	});

	function seed() {
		const hsv = hexToHsv(value);
		if (hsv) {
			hue = hsv.h;
			sat = hsv.s;
			val = hsv.v;
		} else {
			hue = 260;
			sat = 70;
			val = 80;
		}
		hex = hsvToHex(hue, sat, val);
	}

	function openPopover() {
		const r = btnEl.getBoundingClientRect();
		alignRight = r.left > window.innerWidth * 0.55;
		seed();
		open = true;
	}

	function close() {
		if (!open) return;
		const final = isHex(hex) ? hex.toLowerCase() : hsvToHex(hue, sat, val);
		open = false;
		onpick?.(final);
	}

	function toggle() {
		if (open) close();
		else openPopover();
	}

	// the saturation value square: x is saturation, y is value (top is brightest).
	function svFromEvent(e) {
		const r = svEl.getBoundingClientRect();
		const x = Math.max(0, Math.min(1, (e.clientX - r.left) / r.width));
		const y = Math.max(0, Math.min(1, (e.clientY - r.top) / r.height));
		sat = Math.round(x * 100);
		val = Math.round((1 - y) * 100);
		hex = hsvToHex(hue, sat, val);
	}
	function svDown(e) {
		dragging = true;
		svEl.setPointerCapture(e.pointerId);
		svFromEvent(e);
	}
	function svMove(e) {
		if (dragging) svFromEvent(e);
	}
	function svUp(e) {
		dragging = false;
		try {
			svEl.releasePointerCapture(e.pointerId);
		} catch (_) {}
	}

	function onHue() {
		hex = hsvToHex(hue, sat, val);
	}
	function onHexInput(e) {
		hex = e.target.value;
		const hsv = hexToHsv(hex);
		if (hsv) {
			hue = hsv.h;
			sat = hsv.s;
			val = hsv.v;
		}
	}

	function hsvToHex(h, s, v) {
		s /= 100;
		v /= 100;
		const c = v * s;
		const x = c * (1 - Math.abs(((h / 60) % 2) - 1));
		const m = v - c;
		let r, g, b;
		if (h < 60) [r, g, b] = [c, x, 0];
		else if (h < 120) [r, g, b] = [x, c, 0];
		else if (h < 180) [r, g, b] = [0, c, x];
		else if (h < 240) [r, g, b] = [0, x, c];
		else if (h < 300) [r, g, b] = [x, 0, c];
		else [r, g, b] = [c, 0, x];
		const to2 = (n) => Math.round((n + m) * 255).toString(16).padStart(2, '0');
		return ('#' + to2(r) + to2(g) + to2(b)).toLowerCase();
	}
	function hexToHsv(hx) {
		const mm = /^#?([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(hx || '');
		if (!mm) return null;
		const r = parseInt(mm[1], 16) / 255;
		const g = parseInt(mm[2], 16) / 255;
		const b = parseInt(mm[3], 16) / 255;
		const mx = Math.max(r, g, b);
		const mn = Math.min(r, g, b);
		const d = mx - mn;
		let h = 0;
		if (d) {
			if (mx === r) h = ((g - b) / d) % 6;
			else if (mx === g) h = (b - r) / d + 2;
			else h = (r - g) / d + 4;
			h *= 60;
			if (h < 0) h += 360;
		}
		return { h: Math.round(h), s: Math.round(mx === 0 ? 0 : (d / mx) * 100), v: Math.round(mx * 100) };
	}
</script>

<svelte:window onkeydown={(e) => { if (open && e.key === 'Escape') { e.preventDefault(); close(); } }} />

<span class="relative inline-flex">
	<button
		bind:this={btnEl}
		type="button"
		onclick={toggle}
		title="Custom color"
		aria-label="Custom color"
		class="flex h-6 w-6 items-center justify-center rounded-full border {isHex(value)
			? 'border-active-blue ring-2 ring-active-blue/40'
			: 'border-transparent'}"
	>
		<span class="h-3.5 w-3.5 rounded-full" style={innerStyle}></span>
	</button>

	{#if open}
		<!-- catch an outside click so the popover closes and commits. -->
		<button type="button" class="fixed inset-0 z-20 cursor-default" aria-label="Close color picker" onclick={close}></button>
		<div
			class="absolute top-full z-30 mt-1 w-48 rounded-md border border-gray-200 bg-white p-2 shadow-lg dark:border-gray-800 dark:bg-gray-950 {alignRight
				? 'right-0'
				: 'left-0'}"
		>
			<!-- saturation value square: drag to pick. -->
			<div
				bind:this={svEl}
				onpointerdown={svDown}
				onpointermove={svMove}
				onpointerup={svUp}
				role="slider"
				tabindex="-1"
				aria-label="Saturation and brightness"
				aria-valuenow={val}
				class="relative h-28 w-full cursor-crosshair touch-none rounded"
				style="background: linear-gradient(to top, #000, rgba(0,0,0,0)), linear-gradient(to right, #fff, hsl({hue} 100% 50%));"
			>
				<span
					class="pointer-events-none absolute h-3 w-3 -translate-x-1/2 -translate-y-1/2 rounded-full border-2 border-white shadow"
					style="left: {sat}%; top: {100 - val}%; background-color: {hex};"
				></span>
			</div>

			<!-- hue strip -->
			<input
				type="range"
				min="0"
				max="359"
				bind:value={hue}
				oninput={onHue}
				aria-label="Hue"
				class="hue mt-2 h-3 w-full cursor-pointer rounded-full"
				style="background: linear-gradient(to right, red, yellow, lime, cyan, blue, magenta, red);"
			/>

			<input
				type="text"
				maxlength="7"
				placeholder="#rrggbb"
				value={hex}
				oninput={onHexInput}
				aria-label="Hex color"
				class="mt-2 w-full rounded border border-gray-300 bg-white px-2 py-1 font-mono text-xs dark:border-gray-700 dark:bg-gray-900 dark:text-gray-100"
			/>
		</div>
	{/if}
</span>

<style>
	/* a visible round thumb riding on the hue gradient, in both engines. */
	input.hue {
		-webkit-appearance: none;
		appearance: none;
	}
	input.hue::-webkit-slider-thumb {
		-webkit-appearance: none;
		height: 14px;
		width: 14px;
		border-radius: 9999px;
		background: #fff;
		border: 1px solid rgba(0, 0, 0, 0.35);
		box-shadow: 0 0 2px rgba(0, 0, 0, 0.4);
		cursor: pointer;
	}
	input.hue::-moz-range-thumb {
		height: 14px;
		width: 14px;
		border-radius: 9999px;
		background: #fff;
		border: 1px solid rgba(0, 0, 0, 0.35);
		cursor: pointer;
	}
</style>
