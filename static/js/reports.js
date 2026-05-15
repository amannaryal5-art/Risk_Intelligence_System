import { createJsonBlock, openModal, renderEmpty, renderSkeleton } from "./components.js";
import { escapeHtml, pick, request, toArray } from "./utils.js";

const templates = [
  "Daily Threat Summary",
  "Weekly Executive Briefing",
  "Incident Response Report",
  "Threat Actor Profile",
  "Campaign Analysis",
];

export async function initReportsView() {
  const cards = document.getElementById("reportTemplates");
  const viewer = document.getElementById("reportViewer");
  cards.innerHTML = templates.map((template) => `
    <button type="button" class="info-card" data-template="${escapeHtml(template)}">
      <div class="eyebrow">Template</div>
      <h3>${escapeHtml(template)}</h3>
      <p>Generate using live backend artifacts only.</p>
    </button>
  `).join("");

  const caseData = await request("/api/v1/cases?limit=12", {}, { allow404: true });
  const cases = toArray(pick(caseData, ["results"], caseData));
  if (!cases.length) {
    renderEmpty(viewer, "No report source cases", "Open cases are required for case-specific report generation.");
    return;
  }
  viewer.innerHTML = `
    <div class="report-shell">
      <h2>${escapeHtml(cases[0].title || "Incident Report Preview")}</h2>
      <p>Use the backend report endpoint to retrieve export-ready artifacts.</p>
      <button id="openCaseReport" class="button" type="button">Fetch Case Report</button>
    </div>
  `;
  document.getElementById("openCaseReport")?.addEventListener("click", async () => {
    const report = await request(`/api/v1/cases/${cases[0].id}/report`, {}, { allow404: true });
    if (!report) {
      openModal({ title: "Report endpoint unavailable", content: createJsonBlock(cases[0]) });
      return;
    }
    openModal({ title: `Report for Case #${cases[0].id}`, content: createJsonBlock(report), mode: "slide-over" });
  });
}
