<script>
	// The intent is an attribute, not a copied class string, so a destructive action
	// looks the same everywhere. The classes map to the button tiers in app.css.
	let {
		variant = 'secondary',
		size = 'md',
		type = 'button',
		href = null,
		disabled = false,
		title = undefined,
		ariaLabel = undefined,
		class: cls = '',
		onclick = undefined,
		children,
		...rest
	} = $props();

	const CLASSES = {
		md: {
			primary: 'pc-btn-primary',
			secondary: 'pc-btn-secondary',
			neutral: 'pc-btn-secondary',
			danger: 'pc-btn-danger',
			warn: 'pc-btn-warn',
			blue: 'pc-btn-primary'
		},
		xs: {
			primary: 'pc-btn-xs-blue',
			secondary: 'pc-btn-xs-neutral',
			neutral: 'pc-btn-xs-neutral',
			danger: 'pc-btn-xs-danger',
			warn: 'pc-btn-xs-warn',
			blue: 'pc-btn-xs-blue'
		}
	};
	const base = $derived((CLASSES[size] || CLASSES.md)[variant] || (CLASSES[size] || CLASSES.md).secondary);
	const klass = $derived(`${base} ${cls}`.trim());
</script>

{#if href}
	<a
		{href}
		title={title}
		aria-label={ariaLabel}
		aria-disabled={disabled ? 'true' : undefined}
		class="{klass}{disabled ? ' pointer-events-none opacity-40' : ''}"
		{onclick}
		{...rest}
	>{@render children?.()}</a>
{:else}
	<button {type} {disabled} {title} aria-label={ariaLabel} class={klass} {onclick} {...rest}>{@render children?.()}</button>
{/if}
