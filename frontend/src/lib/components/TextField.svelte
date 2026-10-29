<script>
	import { onMount } from 'svelte';
	import ToolTip from './ToolTip.svelte';

	// bind a element to this component input field
	// use like <TextField bind:bindTo={varYouWantToBindTheInputFieldTo} />
	let {
		bindTo = $bindable(null),
		placeholder = '',
		defaultValue = '',
		value = $bindable(defaultValue),
		resets = true, // reset value on parent form reset
		toolTipText = '',
		optional = false,
		readonly = false,
		required = false,
		disabled = false,
		min = null,
		max = null,
		minLength = null,
		maxLength = null,
		width = 'medium',
		pattern = null,
		id = null,
		onBlur = () => {},
		error = false,
		// type can only be set initially
		type = 'text',
		children,
		...rest
	} = $props();

	let inputType = $state('text');

	onMount(() => {
		value = value ?? defaultValue;
		inputType = type;
	});

	// listen to a parent form reset, if one exists, and restore the default value
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
			value = defaultValue;
		};
		parentForm.addEventListener('reset', onReset);
		return () => parentForm.removeEventListener('reset', onReset);
	});
</script>

<label class="flex flex-col py-2">
	<div class="flex items-center">
		<p class="font-semibold text-gray-600 dark:text-gray-400 py-2 transition-colors duration-200">
			{@render children?.()}
		</p>
		{#if toolTipText.length > 0}
			<ToolTip>
				{toolTipText}
			</ToolTip>
		{/if}
		{#if optional === true}
			<div
				class="bg-gray-100 dark:bg-gray-800/60 ml-2 px-2 rounded-md transition-colors duration-200 h-6 flex items-center"
			>
				<p class="text-gray-600 dark:text-gray-400 text-xs transition-colors duration-200">
					optional
				</p>
			</div>
		{/if}
	</div>
	<input
		{...{ type: inputType }}
		{id}
		bind:this={bindTo}
		bind:value
		autocomplete="off"
		title={value}
		onblur={onBlur}
		{min}
		{max}
		minlength={minLength}
		maxlength={maxLength}
		{disabled}
		{readonly}
		{required}
		{placeholder}
		{pattern}
		{...rest}
		class="text-ellipsis row-start-1 row-span-3 justify-self-center rounded-md py-2 pl-2 text-gray-600 dark:text-gray-300 border focus:outline-none focus:border-solid focus:bg-gray-100 dark:focus:bg-gray-700/60 bg-grayblue-light dark:bg-gray-900/60 font-normal transition-colors duration-200 {error
			? 'border-red-500 dark:border-red-400'
			: 'border-transparent dark:border-gray-700/60 focus:border-gray-400 dark:focus:border-highlight-blue/80'}"
		class:w-24={width === 'small'}
		class:w-60={width === 'medium'}
		class:w-95={width === 'large'}
		class:w-full={width === 'full'}
		class:readonly
		class:cursor-not-allowed={readonly}
		class:bg-gray-200={readonly}
		class:dark:bg-gray-800={readonly}
		class:text-gray-500={readonly}
		class:dark:text-gray-500={readonly}
	/>
</label>
