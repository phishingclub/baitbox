<script>
	// A single KPI tile: a big value over a muted caption, on a card surface. Used for
	// the dashboard and package stat rows so both read the same. value is pre formatted
	// by the caller (e.g. toLocaleString or a date string).
	let { value, label, class: cls = '' } = $props();
</script>

<div class="pc-card p-5 {cls}">
	<div class="text-2xl font-bold text-gray-900 dark:text-white">{value}</div>
	<div class="mt-1 text-sm pc-muted">{label}</div>
</div>
