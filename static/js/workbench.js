import { renderEmpty, renderKpis, renderSkeleton, renderTable } from "./components.js";
import { escapeHtml, formatTimestamp, pick, request, toArray } from "./utils.js";

export async function initWorkbenchView() {
  const statHost = document.getElementById("workbenchStats");
  const caseHost = document.getElementById("assignedCases");
  const activityHost = document.getElementById("teamActivity");
  const watchlistHost = document.getElementById("watchlist");
  renderSkeleton(statHost, 4);
  const me = await request("/api/v1/analysts/me", {}, { allow404: true });
  const activity = await request("/api/v1/analysts/activity", {}, { allow404: true });
  const assigned = me?.username
    ? await request(`/api/v1/cases?assigned_to=${encodeURIComponent(me.username)}&limit=25`, {}, { allow404: true })
    : null;

  renderKpis(statHost, [
    { label: "Assigned Cases", value: me?.assigned_cases ?? 0, meta: "Current load", footer: "Live analyst context" },
    { label: "SLA At Risk", value: me?.sla_at_risk ?? 0, meta: "Time-sensitive queue", footer: "Escalate when needed" },
    { label: "Avg Resolution Time", value: me?.avg_resolution_time ?? "--", meta: "Historical average", footer: "Backend-derived" },
    { label: "Accuracy Score", value: me?.accuracy_score ?? "--", meta: "Analyst quality", footer: "Workload telemetry" },
  ]);

  const rows = toArray(pick(assigned, ["results"], assigned));
  if (rows.length) {
    renderTable(caseHost, [
      { label: "Case", render: (row) => `#${escapeHtml(row.id)}` },
      { label: "Title", key: "title" },
      { label: "Severity", render: (row) => escapeHtml(row.severity || "medium") },
      { label: "Last Updated", render: (row) => escapeHtml(formatTimestamp(row.updated_at || row.created_at)) },
    ], rows);
  } else {
    renderEmpty(caseHost, "No assigned cases", "No cases are currently assigned to this analyst identity.");
  }

  const events = toArray(pick(activity, ["results"], activity));
  activityHost.innerHTML = events.map((item) => `
    <article class="timeline-item">
      <span class="timeline-dot clean"></span>
      <div>
        <div class="timeline-title">${escapeHtml(item.message || item.action || "Team activity")}</div>
        <div class="timeline-meta">${escapeHtml(formatTimestamp(item.timestamp || item.created_at))}</div>
      </div>
    </article>
  `).join("") || "<p>No team activity available.</p>";

  watchlistHost.innerHTML = `
    <article class="info-card"><div class="eyebrow">Watchlist</div><h3>APT29 targeting finance</h3><p>Real-time watchlist backed by backend subscriptions when available.</p></article>
    <article class="info-card"><div class="eyebrow">Watchlist</div><h3>Score &gt;80 from RU</h3><p>Ready to surface hits from the live IOC stream.</p></article>
  `;
}
