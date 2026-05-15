import { escapeHtml, formatTimestamp, severityTone } from "./utils.js";

const palette = {
  critical: "#ef4444",
  high: "#f59e0b",
  medium: "#eab308",
  low: "#3b82f6",
  clean: "#10b981",
  neutral: "#64748b",
};

function project(lat, lon, width, height) {
  const x = ((Number(lon) + 180) / 360) * width;
  const y = ((90 - Number(lat)) / 180) * height;
  return { x, y };
}

export function createThreatMap(container) {
  if (!container) return { setPoints() {}, destroy() {} };
  container.innerHTML = `
    <svg viewBox="0 0 1000 460" class="world-map" role="img" aria-label="Threat landscape map">
      <defs>
        <linearGradient id="gridGlow" x1="0" x2="1">
          <stop offset="0%" stop-color="rgba(6,182,212,0.06)"></stop>
          <stop offset="100%" stop-color="rgba(59,130,246,0.2)"></stop>
        </linearGradient>
      </defs>
      <rect x="0" y="0" width="1000" height="460" fill="url(#gridGlow)"></rect>
      <g class="map-grid"></g>
      <g class="map-points"></g>
    </svg>
    <div class="map-tooltip" hidden></div>
  `;
  const svg = container.querySelector("svg");
  const pointsGroup = container.querySelector(".map-points");
  const grid = container.querySelector(".map-grid");
  const tooltip = container.querySelector(".map-tooltip");

  for (let line = 0; line <= 10; line += 1) {
    const y = line * 46;
    const horizontal = document.createElementNS("http://www.w3.org/2000/svg", "line");
    horizontal.setAttribute("x1", "0");
    horizontal.setAttribute("x2", "1000");
    horizontal.setAttribute("y1", String(y));
    horizontal.setAttribute("y2", String(y));
    horizontal.setAttribute("stroke", "rgba(148,163,184,0.12)");
    grid.append(horizontal);
  }
  for (let line = 0; line <= 12; line += 1) {
    const x = line * 83;
    const vertical = document.createElementNS("http://www.w3.org/2000/svg", "line");
    vertical.setAttribute("x1", String(x));
    vertical.setAttribute("x2", String(x));
    vertical.setAttribute("y1", "0");
    vertical.setAttribute("y2", "460");
    vertical.setAttribute("stroke", "rgba(148,163,184,0.12)");
    grid.append(vertical);
  }

  function setPoints(points = []) {
    pointsGroup.innerHTML = "";
    points.forEach((point) => {
      const tone = severityTone(point.severity || point.score_level || "low");
      const { x, y } = project(point.lat ?? point.latitude ?? 0, point.lon ?? point.longitude ?? 0, 1000, 460);
      const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
      circle.setAttribute("cx", String(x));
      circle.setAttribute("cy", String(y));
      circle.setAttribute("r", String(Math.max(4, Number(point.score || 40) / 15)));
      circle.setAttribute("fill", palette[tone] || palette.neutral);
      circle.setAttribute("class", "map-point");
      circle.addEventListener("mouseenter", () => {
        tooltip.hidden = false;
        tooltip.innerHTML = `
          <strong>${escapeHtml(point.value || point.ip || "IOC")}</strong>
          <span>${escapeHtml(point.country || "Unknown origin")} • score ${escapeHtml(point.score || "--")}</span>
          <span>${escapeHtml(point.actor || point.threat_actor || "Unattributed")} • ${escapeHtml(formatTimestamp(point.detected_at || point.timestamp))}</span>
        `;
      });
      circle.addEventListener("mousemove", (event) => {
        tooltip.style.left = `${event.offsetX + 18}px`;
        tooltip.style.top = `${event.offsetY + 18}px`;
      });
      circle.addEventListener("mouseleave", () => {
        tooltip.hidden = true;
      });
      pointsGroup.append(circle);
    });
  }

  return {
    setPoints,
    destroy() {
      svg?.remove();
      tooltip?.remove();
    },
  };
}
