import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: "var(--color-bg)",
        surface: "var(--color-surface)",
        panel: "var(--color-panel)",
        accent: "var(--color-accent)",
        success: "var(--color-success)",
        warning: "var(--color-warning)",
        danger: "var(--color-danger)",
        muted: "var(--color-muted)",
        line: "var(--color-line)",
      },
      boxShadow: {
        "cyan-glow": "0 0 24px rgba(0, 212, 255, 0.18)",
        "green-glow": "0 0 22px rgba(0, 255, 136, 0.18)",
      },
      backgroundImage: {
        "panel-grid": "radial-gradient(circle at top, rgba(0,212,255,0.08), transparent 38%), linear-gradient(180deg, rgba(255,255,255,0.02), transparent)",
      },
      keyframes: {
        blink: {
          "0%, 45%, 100%": { opacity: "1" },
          "50%, 95%": { opacity: "0.35" }
        },
        dash: {
          "0%": { backgroundPosition: "0 0" },
          "100%": { backgroundPosition: "120px 0" }
        },
        shimmer: {
          "0%": { transform: "translateX(-140%)" },
          "100%": { transform: "translateX(140%)" }
        },
        scanline: {
          "0%": { backgroundPosition: "0 0" },
          "100%": { backgroundPosition: "0 24px" }
        }
      },
      animation: {
        blink: "blink 1.2s steps(2, end) infinite",
        dash: "dash 3s linear infinite",
        shimmer: "shimmer 1.6s ease-out forwards",
        scanline: "scanline 6s linear infinite"
      },
      fontFamily: {
        data: "var(--font-jetbrains)",
        heading: "var(--font-rajdhani)",
      },
    },
  },
  plugins: [],
};

export default config;
