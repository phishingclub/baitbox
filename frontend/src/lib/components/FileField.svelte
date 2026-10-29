<script>
	import ToolTip from './ToolTip.svelte';

	// bind a element to this component input field
	// use like <FileField bind:bindTo={varYouWantToBindTheInputFieldTo} />
	let {
		bindTo = $bindable(null),
		placeholder = '',
		resets = true, // reset value on parent form reset
		toolTipText = '',
		optional = false,
		required = false,
		multiple = false,
		name = 'files',
		accept = '*',
		disabled = false,
		onchange = undefined,
		children
	} = $props();

	// keep a parent form from clearing the selection on reset
	$effect(() => {
		if (!bindTo || !resets) {
			return;
		}
		const parentForm = bindTo.closest('form');
		if (!parentForm) {
			return;
		}
		const onReset = (event) => {
			event.preventDefault();
		};
		parentForm.addEventListener('reset', onReset);
		return () => parentForm.removeEventListener('reset', onReset);
	});
</script>

<label class="flex flex-col py-2 w-56">
	{#if children || toolTipText.length > 0 || optional === true}
		<div class="flex items-center">
			<p
				class="font-semibold text-gray-600 dark:text-gray-300 py-2 transition-colors duration-200"
			>
				{@render children?.()}
			</p>
			{#if toolTipText.length > 0}
				<ToolTip>
					{toolTipText}
				</ToolTip>
			{/if}
			{#if optional === true}
				<div
					class="bg-gray-100 dark:bg-gray-700 ml-2 px-2 rounded-md transition-colors duration-200 h-6 flex items-center"
				>
					<p class="text-gray-600 dark:text-gray-300 text-xs">optional</p>
				</div>
			{/if}
		</div>
	{/if}
	<input
		id="files"
		type="file"
		{name}
		{accept}
		bind:this={bindTo}
		{onchange}
		autocomplete="off"
		{multiple}
		{required}
		{placeholder}
		{disabled}
		class="border-solid border-2 border-gray-300 dark:border-gray-600 py-2 px-2 rounded-md file:px-4 file:py-2 file:text-white file:cursor-pointer file:text-sm file:font-semibold bg-white dark:bg-gray-700 file:bg-cta-blue hover:cursor-pointer file:hover:bg-active-blue dark:file:bg-cta-blue dark:file:hover:bg-active-blue file:border-hidden file:rounded-md text-gray-900 dark:text-white transition-colors duration-200 disabled:opacity-50 disabled:cursor-not-allowed file:disabled:cursor-not-allowed"
	/>
</label>
