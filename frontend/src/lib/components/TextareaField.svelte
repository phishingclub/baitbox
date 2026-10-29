<script>
	import { onMount } from 'svelte';
	import ToolTip from './ToolTip.svelte';

	// bind a element to this component input field
	// use like <Textarea bind:bindTo={varYouWantToBindTheInputFieldTo} />
	let {
		bindTo = $bindable(null),
		placeholder = '',
		defaultValue = '',
		value = $bindable(defaultValue),
		toolTipText = '',
		readonly = false,
		resize = true,
		required = false,
		minLength = null,
		maxLength = null,
		id = null,
		fullWidth = false,
		height = 'small',
		optional = false,
		children
	} = $props();

	onMount(() => {
		value = value ?? defaultValue;
	});

	// listen to a parent form reset, if one exists, and restore the default value
	$effect(() => {
		if (!bindTo) {
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

<label class="flex flex-col py-2 w-60" class:w-full={fullWidth}>
	<div class="flex items-center">
		<p class="font-bold text-gray-600 dark:text-gray-400 py-2 transition-colors duration-200">
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

	<textarea
		{id}
		bind:this={bindTo}
		bind:value
		{required}
		minlength={minLength}
		maxlength={maxLength}
		{readonly}
		{placeholder}
		class=" focus:outline-none pl-2 border border-transparent dark:border-gray-700/60 rounded-md focus:border-solid text-gray-600 dark:text-gray-300 focus:bg-gray-100 dark:focus:bg-gray-700/60 font-light focus:border-gray-400 dark:focus:border-highlight-blue/80 bg-grayblue-light dark:bg-gray-900/60 transition-colors duration-200"
		class:h-16={height === 'small'}
		class:h-28={height === 'medium'}
		class:h-48={height === 'large'}
		class:resize-none={!resize}
	></textarea>
</label>
