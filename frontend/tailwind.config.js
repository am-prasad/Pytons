/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        navy: {
          950: '#050b18',
          900: '#080f1e',
          850: '#0a1525',
          800: '#0d1b2e',
          700: '#102240',
          600: '#1a3356',
        },
        cyber: {
          blue: '#00d4ff',
          'blue-dim': '#0098cc',
          cyan: '#00f5d4',
          'cyan-dim': '#00b89e',
          purple: '#7c3aed',
          green: '#10b981',
          amber: '#f59e0b',
          red: '#ef4444',
          orange: '#f97316',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      boxShadow: {
        'cyber': '0 0 20px rgba(0, 212, 255, 0.15)',
        'cyber-sm': '0 0 10px rgba(0, 212, 255, 0.1)',
        'glow-green': '0 0 20px rgba(16, 185, 129, 0.2)',
        'glow-red': '0 0 20px rgba(239, 68, 68, 0.2)',
        'glow-amber': '0 0 20px rgba(245, 158, 11, 0.2)',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
        'slide-in': 'slideIn 0.3s ease-out',
        'fade-in': 'fadeIn 0.4s ease-out',
        'scan': 'scan 2s linear infinite',
      },
      keyframes: {
        glow: {
          '0%': { boxShadow: '0 0 5px rgba(0, 212, 255, 0.2)' },
          '100%': { boxShadow: '0 0 20px rgba(0, 212, 255, 0.5)' },
        },
        slideIn: {
          '0%': { transform: 'translateY(10px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        scan: {
          '0%': { backgroundPosition: '0% 0%' },
          '100%': { backgroundPosition: '0% 100%' },
        },
      },
    },
  },
  plugins: [],
}
