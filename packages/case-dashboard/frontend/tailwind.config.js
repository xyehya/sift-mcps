/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        'bg-void':    '#07090e',
        'bg-base':    '#0a0d14',
        'bg-surface': '#0f1320',
        'bg-raised':  '#141928',
        'bg-overlay': '#1a2035',
        'border-faint': '#1c2338',
        'border-soft':  '#232d45',
        'border-hard':  '#2e3d5f',
        'text-bright':  '#eef2ff',
        'text-primary': '#c8d4f0',
        'text-muted':   '#6b7fa3',
        'text-ghost':   '#4e5e80',
        cyan:    '#00d4ff',
        amber:   '#ffb347',
        crimson: '#ff3864',
        jade:    '#00ff94',
        violet:  '#a78bfa',
      },
      fontFamily: {
        sans: ['DM Sans', 'system-ui', 'sans-serif'],
        mono: ['DM Mono', 'monospace'],
        display: ['Syne', 'system-ui', 'sans-serif'],
      },
      fontWeight: {
        medium: '500',
        semibold: '600',
        bold: '700',
        extrabold: '800',
      },
      transitionTimingFunction: {
        snap:   'cubic-bezier(0.16, 1, 0.3, 1)',
        smooth: 'cubic-bezier(0.4, 0, 0.2, 1)',
      },
    },
  },
  plugins: [],
}

