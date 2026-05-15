import { renderEmpty, renderSkeleton, renderTable } from "./components.js";
import { escapeHtml, formatTimestamp, pick, request, severityTone, toArray } from "./utils.js";

export async function initAssetsView() {
  const table = document.getElementById("assetTable");
  renderSkeleton(table, 8);
  const data = await request("/api/v1/assets", {}, { allow404: true });
  if (!data) {
    renderEmpty(table, "Asset inventory unavailable", "The monitored asset API is not currently exposed by the backend.");
    return;
  }
  const rows = toArray(pick(data, ["results"], data));
  renderTable(table, [
    { label: "Asset Name", key: "name" },
    { label: "Type", key: "type" },
    { label: "Risk Score", render: (row) => `<span class="pill ${escapeHtml(severityTone(row.risk_score > 70 ? "critical" : "low"))}">${escapeHtml(row.risk_score || 0)}</span>` },
    { label: "Exposed IOCs", render: (row) => escapeHtml(row.exposed_iocs || row.ioc_count || 0) },
    { label: "Last Scan", render: (row) => escapeHtml(formatTimestamp(row.last_scan || row.updated_at)) },
    { label: "Status", render: (row) => escapeHtml(row.status || "Protected") },
  ], rows, {
    emptyTitle: "No assets",
    emptyDetail: "The backend returned an empty asset inventory.",
  });
}
