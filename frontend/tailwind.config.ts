import type { Config } from 'tailwindcss'

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // SOC terminal palette
        bg: {
          primary:   '#0a0c0e',
          secondary: '#0f1215',
          panel:     '#131619',
          border:    '#1e2328',
          hover:     '#1a1f24',
        },
        accent: {
          green:  '#00ff88',
          dim:    '#00cc6a',
          red:    '#ff3b5c',
          yellow: '#ffcc00',
          blue:   '#00aaff',
          muted:  '#1a3d2e',
        },
        text: {
          primary:   '#e8edf2',
          secondary: '#7a8999',
          muted:     '#4a5568',
          green:     '#00ff88',
        },
      },
      fontFamily: {
        mono:    ['IBM Plex Mono', 'Fira Code', 'monospace'],
        display: ['Syne', 'sans-serif'],
        body:    ['DM Sans', 'sans-serif'],
      },
      fontSize: {
        '2xs': ['0.65rem', { lineHeight: '1rem' }],
      },
      borderColor: {
        DEFAULT: '#1e2328',
      },
      animation: {
        'pulse-green': 'pulse-green 2s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'scan-line':   'scan-line 3s linear infinite',
        'fade-in':     'fade-in 0.4s ease-out forwards',
        'slide-up':    'slide-up 0.3s ease-out forwards',
      },
      keyframes: {
        'pulse-green': {
          '0%, 100%': { opacity: '1' },
          '50%':       { opacity: '0.4' },
        },
        'scan-line': {
          '0%':   { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
        'fade-in': {
          from: { opacity: '0' },
          to:   { opacity: '1' },
        },
        'slide-up': {
          from: { opacity: '0', transform: 'translateY(8px)' },
          to:   { opacity: '1', transform: 'translateY(0)' },
        },
      },
    },
  },
  plugins: [],
} satisfies Config
