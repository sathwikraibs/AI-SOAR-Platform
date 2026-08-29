/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'monospace'],
      },
      colors: {
        // Flat charcoal/slate — no navy tint, no gradients
        base: {
          950: '#0b0f14',
          900: '#0f1419',
          850: '#141a21',
          800: '#1a2128',
          750: '#1e252e',
          700: '#252d36',
          650: '#2c3540',
          600: '#364049',
        },
        line: {
          DEFAULT: '#222b36',
          strong: '#303b48',
        },
        // Single muted slate-blue accent for interactive elements
        accent: {
          300: '#7c9ab8',
          400: '#5e83a3',
          500: '#4a7290',
          600: '#3d5f7a',
          700: '#324e63',
        },
        // Desaturated severity palette — muted, not neon
        sev: {
          critical: '#c2675a',        // muted brick red
          criticalBg: '#2a1815',
          criticalBorder: '#5e352d',
          high: '#c79a5c',            // muted amber
          highBg: '#292014',
          highBorder: '#5c4527',
          medium: '#b5a44e',          // muted gold
          mediumBg: '#252314',
          mediumBorder: '#524d2a',
          low: '#5a9472',             // muted sage green
          lowBg: '#16271d',
          lowBorder: '#2c4a38',
        },
      },
      fontSize: {
        '2xs': ['0.6875rem', { lineHeight: '1rem' }],
      },
      borderRadius: {
        DEFAULT: '3px',
        sm: '3px',
        md: '4px',
        lg: '4px',
      },
    },
  },
  plugins: [],
};
