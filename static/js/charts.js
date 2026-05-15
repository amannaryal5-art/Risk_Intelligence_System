import { severityTone } from "./utils.js";

export function drawSparkline(canvas, values = [], color = "#3b82f6") {
  if (!canvas) return;
  const context = canvas.getContext("2d");
  const width = canvas.width;
  const height = canvas.height;
  context.clearRect(0, 0, width, height);
  if (!values.length) {
    context.strokeStyle = "rgba(148, 163, 184, 0.35)";
    context.beginPath();
    context.moveTo(0, height / 2);
    context.lineTo(width, height / 2);
    context.stroke();
    return;
  }
  const min = Math.min(...values);
  const max = Math.max(...values);
  const spread = Math.max(1, max - min);
  context.lineWidth = 2;
  context.strokeStyle = color;
  context.beginPath();
  values.forEach((value, index) => {
    const x = (index / Math.max(values.length - 1, 1)) * width;
    const y = height - ((value - min) / spread) * (height - 6) - 3;
    if (index === 0) context.moveTo(x, y);
    else context.lineTo(x, y);
  });
  context.stroke();
}

export function gaugeSvg(value = 0, tone = "low") {
  const normalized = Math.max(0, Math.min(100, Number(value) || 0));
  const palette = {
    critical: "#ef4444",
    high: "#f59e0b",
    medium: "#eab308",
    low: "#3b82f6",
    clean: "#10b981",
    neutral: "#64748b",
  };
  const stroke = palette[tone] || palette.neutral;
  const dash = `${normalized} 100`;
  return `
    <svg viewBox="0 0 36 36" class="mini-gauge" aria-hidden="true">
      <path d="M18 2.5 a 15.5 15.5 0 0 1 0 31 a 15.5 15.5 0 0 1 0 -31" fill="none" stroke="rgba(100,116,139,0.16)" stroke-width="3.5"></path>
      <path d="M18 2.5 a 15.5 15.5 0 0 1 0 31 a 15.5 15.5 0 0 1 0 -31" fill="none" stroke="${stroke}" stroke-linecap="round" stroke-width="3.5" stroke-dasharray="${dash}"></path>
      <text x="18" y="21" text-anchor="middle" font-size="10" fill="#f8fafc">${normalized}</text>
    </svg>
  `;
}

export function toneColor(tone) {
  const normalized = severityTone(tone);
  const palette = {
    critical: "#ef4444",
    high: "#f59e0b",
    medium: "#eab308",
    low: "#3b82f6",
    clean: "#10b981",
    neutral: "#64748b",
  };
  return palette[normalized] || palette.neutral;
}
