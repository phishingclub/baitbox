/** @type {import('tailwindcss').Config} */
export default {
	content: ['./src/**/*.{html,js,svelte}'],
	darkMode: 'class',
	theme: {
		extend: {
			fontFamily: {
				// Phudu for headings and the wordmark, Titillium Web for body text.
				phudu: ['Phudu', 'system-ui', 'sans-serif'],
				sans: ['Titillium Web', 'system-ui', 'sans-serif']
			},
			colors: {
				// Phishing Club brand palette (borrowed, not the stock Tailwind sky/gray).
				'pc-pink': '#ff00ff',
				'pc-pink-hover': '#fa48ff',
				'pc-purple': '#9622fc',
				'pc-red': '#f6287b',
				'cta-blue': '#445ecc',
				'active-blue': '#1e3fa8',
				'highlight-blue': '#6887ea',
				'cta-green': '#5dd8c4',
				'pc-darkblue': '#0b2063',
				'pc-lightblue': '#ddddff',
				'pc-dusty-light-blue': '#819efb',
				'grayblue-light': '#ebeaf9',
				'grayblue-dark': '#9a9ab7',
				'pleasant-gray': '#f8f8ff'
			}
		}
	},
	plugins: []
};
