<script>
	import { onMount } from 'svelte';
	import ToolTip from './ToolTip.svelte';
	import { activeFormElement, activeFormElementSubscribe } from '$lib/store/activeFormElement';

	let {
		_id = Symbol(),
		id,
		bindTo = $bindable(null),
		defaultValue = '',
		value = $bindable(defaultValue),
		placeholder = 'Select...',
		required = false,
		options = [],
		toolTipText = '',
		optional = false,
		hidden = false,
		size = 'normal',
		inline = false,
		onSelect = (value) => {},
		children
	} = $props();

	const optionsArray = $derived(Array.isArray(options) ? options : Array.from(options));

	// an option is either a string or a {value, label} object
	const getOptionLabel = (opt) => {
		if (opt && typeof opt === 'object' && 'label' in opt) {
			return opt.label;
		}
		return opt;
	};

	const getOptionValue = (opt) => {
		if (opt && typeof opt === 'object' && 'value' in opt) {
			return opt.value;
		}
		return opt;
	};

	const getDisplayLabel = (val) => {
		const found = optionsArray.find((opt) => getOptionValue(opt) === val);
		if (found) {
			return getOptionLabel(found);
		}
		return val;
	};

	let showDropdown = $state(false);
	let inputElement = $state();
	let dropdownElement = $state();
	let justSelected = false;
	let dropdownPosition = $state({ top: 0, left: 0, width: 0 });

	const filterOptions = (searchValue) => {
		if (!searchValue) {
			return [...optionsArray];
		}
		return optionsArray.filter((opt) => {
			const label = getOptionLabel(opt);
			return label && label.toLowerCase && label.toLowerCase().includes(searchValue.toLowerCase());
		});
	};

	// show every option on focus, filter only once the user has typed
	let hasTyped = $state(false);

	const allOptions = $derived(hasTyped ? filterOptions(value) : [...optionsArray]);

	const handleFocus = () => {
		activeFormElement.set(id);
		// Don't open dropdown if we just selected something
		if (!justSelected) {
			showDropdown = true;
			hasTyped = false; // Reset typing flag to show all options
			updateDropdownPosition();
		}
		justSelected = false; // Reset the flag
	};

	const handleInput = (e) => {
		value = e.target.value;
		showDropdown = true;
		hasTyped = true; // User has typed, enable filtering
		updateDropdownPosition();
	};

	const selectOption = (option) => {
		value = getOptionValue(option);
		showDropdown = false;
		hasTyped = false; // Reset typing flag after selection
		justSelected = true; // Set flag to prevent dropdown reopening
		onSelect(value);
		// Focus the input field after selection without reopening dropdown
		setTimeout(() => {
			if (inputElement) {
				inputElement.focus();
			}
		}, 0);
	};

	const closeDropdown = () => {
		showDropdown = false;
		hasTyped = false; // Reset typing flag when closing
		// only clear activeFormElement if it was set by this component
		activeFormElement.update((current) => (current === id ? null : current));
	};

	// the dropdown is fixed positioned, so place it under the input
	const updateDropdownPosition = () => {
		if (inputElement) {
			const rect = inputElement.getBoundingClientRect();
			dropdownPosition = {
				top: rect.bottom + 4,
				left: rect.left,
				width: rect.width
			};
		}
	};

	const handleBlur = (e) => {
		// wait so a click on an option completes first
		setTimeout(() => {
			const focusedElement = document.activeElement;
			const container = inputElement?.closest('.textfield-select-container');

			if (!container?.contains(focusedElement)) {
				closeDropdown();
			}
		}, 100);
	};

	const handleKeyDown = (e) => {
		if (!showDropdown) return;

		if (e.key === 'Escape') {
			e.preventDefault();
			closeDropdown();
			return;
		}

		if (e.key === 'Enter') {
			e.preventDefault();
			if (allOptions.length === 1) {
				selectOption(allOptions[0]);
			}
			return;
		}

		if (e.key === 'ArrowDown') {
			e.preventDefault();
			const firstOption = dropdownElement?.querySelector('button');
			firstOption?.focus();
			return;
		}
	};

	const handleOptionKeyDown = (e, option) => {
		if (e.key === 'Tab') {
			// Let tab work normally but close dropdown
			closeDropdown();
			return;
		}

		if (e.key === 'Enter' || e.key === ' ') {
			e.preventDefault();
			selectOption(option);
			return;
		}

		if (e.key === 'Escape') {
			e.preventDefault();
			closeDropdown();
			inputElement?.focus();
			return;
		}

		if (e.key === 'ArrowUp') {
			e.preventDefault();
			const currentButton = e.target;
			const prevButton =
				currentButton.parentElement?.previousElementSibling?.querySelector('button');
			if (prevButton) {
				prevButton.focus();
			} else {
				inputElement?.focus();
			}
			return;
		}

		if (e.key === 'ArrowDown') {
			e.preventDefault();
			const currentButton = e.target;
			const nextButton = currentButton.parentElement?.nextElementSibling?.querySelector('button');
			if (nextButton) {
				nextButton.focus();
			}
			return;
		}
	};

	const handleOutsideClick = (e) => {
		if (!showDropdown) return;

		const container = inputElement?.closest('.textfield-select-container');
		if (container && !container.contains(e.target)) {
			closeDropdown();
		}
	};

	onMount(() => {
		value = value || defaultValue;
		const unsubscribe = activeFormElementSubscribe(_id, closeDropdown);
		document.addEventListener('click', handleOutsideClick);
		window.addEventListener('scroll', updateDropdownPosition, true);
		window.addEventListener('resize', updateDropdownPosition);

		return () => {
			unsubscribe();
			document.removeEventListener('click', handleOutsideClick);
			window.removeEventListener('scroll', updateDropdownPosition, true);
			window.removeEventListener('resize', updateDropdownPosition);
		};
	});

	// expose the input element through the bindable prop
	$effect(() => {
		if (inputElement) {
			bindTo = inputElement;
		}
	});

	// restore the default value on a parent form reset, if there is a form
	$effect(() => {
		if (!inputElement) {
			return;
		}
		const parentForm = inputElement.closest('form');
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

	const comboboxId = $derived(id || `textfield-select-${_id.toString()}`);
	const listboxId = $derived(`${comboboxId}-listbox`);
	const labelId = $derived(`${comboboxId}-label`);

	const displayValue = $derived(getDisplayLabel(value));
	const hasValue = $derived(value && value !== '');
	const ariaExpanded = $derived(showDropdown);
</script>

<div
	class="flex justify-start textfield-select-container"
	class:hidden
	class:flex-col={!inline}
	class:flex-row={inline}
>
	<label class="flex flex-col py-2 relative" class:py-2={!inline} class:pr-2={inline}>
		<div class="flex items-center">
			<p
				id={labelId}
				class="font-semibold text-gray-600 dark:text-gray-400 py-1 transition-colors duration-200"
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
					class="bg-gray-100 dark:bg-gray-800/60 ml-2 px-2 rounded-md transition-colors duration-200 h-6 flex items-center"
				>
					<p class="text-gray-600 dark:text-gray-400 text-xs">optional</p>
				</div>
			{/if}
		</div>
	</label>
	<div class="relative">
		<div
			class="flex items-center relative"
			class:w-28={size == 'small'}
			class:w-60={size == 'normal'}
			class:w-full={size == 'full'}
		>
			<input
				bind:this={inputElement}
				type="text"
				role="combobox"
				id={comboboxId}
				aria-labelledby={labelId}
				aria-expanded={ariaExpanded}
				aria-controls={listboxId}
				aria-autocomplete="list"
				aria-haspopup="listbox"
				value={showDropdown ? value : displayValue}
				title={displayValue}
				onfocus={handleFocus}
				onblur={handleBlur}
				oninput={handleInput}
				onkeydown={handleKeyDown}
				onclick={handleFocus}
				autocomplete="off"
				style={optional && hasValue ? 'padding-right: 4rem;' : 'padding-right: 2.5rem;'}
				class="w-full relative rounded-md py-2 text-gray-600 dark:text-gray-300 border border-transparent focus:outline-none focus:border-solid focus:border focus:border-gray-400 dark:focus:border-highlight-blue/80 focus:bg-gray-100 dark:focus:bg-gray-700/60 bg-grayblue-light dark:bg-gray-900/60 font-normal cursor-pointer focus:cursor-text transition-colors duration-200 overflow-hidden text-ellipsis whitespace-nowrap"
				class:pl-10={showDropdown}
				class:pl-4={!showDropdown}
				placeholder={!hasValue && !showDropdown ? placeholder : ''}
				{required}
			/>
			{#if showDropdown}
				<img
					class="absolute w-4 left-3 select-none pointer-events-none z-10"
					src="/search-icon.svg"
					alt=""
					aria-hidden="true"
				/>
			{/if}
			<!-- Clear button for optional fields -->
			{#if optional === true && hasValue}
				<button
					class="absolute right-8 z-10 hover:opacity-70 transition-opacity"
					type="button"
					aria-label="Clear selection"
					onclick={(e) => {
						e.stopPropagation();
						value = '';
						onSelect('');
						inputElement?.focus();
					}}
				>
					<img class="w-4" src="/remove-value.svg" alt="" />
				</button>
			{/if}
			<!-- Dropdown arrow -->
			<img
				class="absolute pointer-events-none w-4 right-3"
				src="/arrow.svg"
				alt=""
				aria-hidden="true"
			/>
		</div>
		<!-- Dropdown list -->
		{#if showDropdown}
			<div
				bind:this={dropdownElement}
				class="fixed z-[9999]"
				style="top: {dropdownPosition.top}px; left: {dropdownPosition.left}px; width: {dropdownPosition.width}px;"
			>
				<ul
					id={listboxId}
					role="listbox"
					aria-labelledby={labelId}
					class="bg-gray-100 dark:bg-gray-900 list-none mt-4 z-[9999] rounded-md min-w-fit shadow-lg border border-gray-200 dark:border-gray-700/60 max-h-40 overflow-y-scroll transition-colors duration-200"
				>
					{#if allOptions.length}
						{#each allOptions as option, index}
							<li role="none">
								<button
									id="{listboxId}-option-{index}"
									role="option"
									aria-selected={value === getOptionValue(option)}
									class="w-full text-left bg-gray-100 dark:bg-gray-900 rounded-md text-gray-600 dark:text-gray-300 hover:bg-grayblue-dark dark:hover:bg-highlight-blue/40 hover:text-white py-2 px-2 cursor-pointer focus:bg-grayblue-dark dark:focus:bg-highlight-blue/40 focus:text-white focus:outline-none transition-colors duration-200"
									onclick={(e) => {
										e.preventDefault();
										e.stopPropagation();
										selectOption(option);
									}}
									onkeydown={(e) => handleOptionKeyDown(e, option)}
									onblur={handleBlur}
								>
									{getOptionLabel(option)}
								</button>
							</li>
						{/each}
					{:else}
						<li
							role="none"
							class="w-full bg-gray-100 dark:bg-gray-900 text-gray-600 dark:text-gray-400 py-2 px-2 transition-colors duration-200"
						>
							No options available
						</li>
					{/if}
				</ul>
			</div>
		{/if}
	</div>
</div>
