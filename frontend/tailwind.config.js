export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      fontFamily: {
        mono: ['JetBrains Mono', 'monospace'],
        sans: ['Inter', 'sans-serif'],
      },
      colors: {
        surface: '#020611',
        elevated: '#050a16',
        border: '#0d283c',
        cyber: {
          cyan: '#00d4ff',
          green: '#00e676',
          red: '#ff1744',
          purple: '#b300ff',
          black: '#010409',
        }
      },
      boxShadow: {
        glow: '0 0 0 1px rgba(0, 212, 255, 0.4), 0 0 20px rgba(0, 212, 255, 0.15)',
        'glow-red': '0 0 0 1px rgba(255, 23, 68, 0.4), 0 0 20px rgba(255, 23, 68, 0.15)',
        'glow-green': '0 0 0 1px rgba(0, 230, 118, 0.4), 0 0 20px rgba(0, 230, 118, 0.15)',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        radar: 'radar 2s linear infinite',
        glitch: 'glitch 3s infinite',
        scanline: 'scanline 8s linear infinite',
        'data-flow': 'data-flow 2s linear infinite',
      },
      keyframes: {
        radar: {
          '0%': { transform: 'scale(1)', opacity: '0.8' },
          '100%': { transform: 'scale(2)', opacity: '0' },
        },
        glitch: {
          '0%, 100%': { transform: 'translate(0)' },
          '2%': { transform: 'translate(-2px, 1px)' },
          '4%': { transform: 'translate(-1px, -1px)' },
          '6%': { transform: 'translate(2px, 1px)' },
          '8%': { transform: 'translate(1px, -2px)' },
          '10%': { transform: 'translate(-2px, 2px)' },
          '12%': { transform: 'translate(0)' },
        },
        scanline: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
        'data-flow': {
          '0%': { backgroundPosition: '0% 0%' },
          '100%': { backgroundPosition: '200% 0%' },
        }
      },
    },
  },
  plugins: [],
}
