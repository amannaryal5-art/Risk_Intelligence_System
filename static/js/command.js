import { createThreatMap } from "./map.js";
import { drawSparkline, toneColor } from "./charts.js";
import { renderEmpty, renderKpis, renderTable, renderSkeleton } from "./components.js";
import { buildUrl, escapeHtml, formatNumber, formatTimestamp, pick, severityTone, toArray, request } from "./utils.js";

let mapInstance;

function kpiCards(stats = {}) {
  return [
    {
      label: "THREATS DETECTED (24H)",
      value: formatNumber(pick(stats, ["threats_today", "threats_24h", "threats_detected"], 0)),
      meta: `Trend ${pick(stats, ["threat_trend", "trend_24h"], "+0%")}`,
      footer: "Autonomous telemetry",
    },
    {
      label: "ACTIVE CASES",
      value: formatNumber(pick(stats, ["active_cases", "case_count"], 0)),
      meta: pick(stats, ["active_case_breakdown", "case_breakdown_text"], "Critical 0 | High 0 | Medium 0"),
      footer: "Live case queue",
    },
    {
      label: "IOC QUEUE DEPTH",
      value: formatNumber(pick(stats, ["queue_depth", "ioc_queue_depth"], 0)),
      meta: pick(stats, ["queue_meta", "queue_breakdown"], "Processing 0 | Backlog 0"),
      footer: "Worker pipeline state",
    },
    {
      label: "FEED HEALTH",
      value: pick(stats, ["feed_health", "feed_health_text"], "0/0 OPERATIONAL"),
      meta: pick(stats, ["feed_health_meta", "feeds_summary"], "No feed telemetry"),
      footer: "Provider availability",
    },
    {
      label: "AUTONOMY ACTIONS (24H)",
      value: formatNumber(pick(stats, ["autonomy_actions", "auto_actions_24h"], 0)),
      meta: pick(stats, ["autonomy_meta", "actions_meta"], "No autonomous actions"),
      footer: "System response volume",
    },
    {
      label: "MEAN TIME TO DETECT",
      value: pick(stats, ["mean_time_to_detect", "mttd"], "--"),
      meta: pick(stats, ["mttd_target", "mttd_meta"], "Target <5s"),
      footer: "Detection SLA",
    },
  ];
}

function renderPipeline(container, scans = []) {
  if (!container) return;
  const stages = [
    { key: "ingestion", label: "INGESTION" },
    { key: "enrichment", label: "ENRICHMENT" },
    { key: "scoring", label: "SCORING" },
    { key: "response", label: "RESPONSE" },
    { key: "archive", label: "ARCHIVE" },
  ];
  const grouped = stages.map((stage) => {
    const items = scans.filter((scan) => String(scan.stage || scan.status || "").toLowerCase().includes(stage.key));
    return { ...stage, count: items.length, items };
  });
  container.innerHTML = grouped.map((stage) => `
    <div class="pipeline-stage">
      <div class="pipeline-head">
        <strong>${stage.label}</strong>
        <span>${stage.count} active</span>
      </div>
      <div class="pipeline-bar">${new Array(Math.max(stage.count, 1)).fill(0).map(() => "<span></span>").join("")}</div>
      <div class="pipeline-meta">${stage.items[0] ? escapeHtml(stage.items[0].summary || stage.items[0].id || "Live worker activity") : "Idle"}</div>
    </div>
  `).join("");
}

function threatRows(activity = [], cases = []) {
  const caseIds = new Set(cases.map((item) => item.id));
  return activity.slice(0, 20).map((event, index) => ({
    severity: pick(event, ["severity", "risk_level"], "medium"),
    ioc: pick(event, ["value", "ioc_value", "indicator"], `event-${index}`),
    type: pick(event, ["type", "ioc_type", "indicator_type"], "unknown"),
    score: pick(event, ["score", "risk_score"], "--"),
    actor: pick(event, ["actor", "threat_actor"], "Unattributed"),
    campaign: pick(event, ["campaign", "campaign_name"], "--"),
    detected: pick(event, ["timestamp", "detected_at"], "--"),
    action: caseIds.has(event.case_id) ? `View Case #${event.case_id}` : "Create Case",
  }));
}

function renderAutonomy(container, activity = []) {
  if (!container) return;
  if (!activity.length) {
    renderEmpty(container, "No autonomous actions", "The system has not published recent command log events.");
    return;
  }
  container.innerHTML = activity.slice(0, 8).map((item) => `
    <button type="button" class="timeline-item">
      <span class="timeline-dot ${escapeHtml(severityTone(item.severity || item.level || "low"))}"></span>
      <div>
        <div class="timeline-title">${escapeHtml(item.message || item.description || item.action || "System event")}</div>
        <div class="timeline-meta">${escapeHtml(formatTimestamp(item.timestamp || item.detected_at || item.created_at))}</div>
      </div>
    </button>
  `).join("");
}

function extractMapPoints(activity = []) {
  return activity
    .filter((item) => pick(item, ["lat", "latitude"]) !== null || pick(item, ["lon", "longitude"]) !== null)
    .map((item) => ({
      lat: pick(item, ["lat", "latitude"], 0),
      lon: pick(item, ["lon", "longitude"], 0),
      score: pick(item, ["score", "risk_score"], 50),
      severity: pick(item, ["severity", "risk_level"], "low"),
      value: pick(item, ["value", "ioc_value"], "IOC"),
      country: pick(item, ["country", "geo.country"], "Unknown"),
      actor: pick(item, ["actor", "threat_actor"], "Unattributed"),
      detected_at: pick(item, ["timestamp", "detected_at"]),
    }));
}

export async function initCommandView({ bus }) {
  const kpiHost = document.getElementById("commandKpis");
  const pipelineHost = document.getElementById("processingPipeline");
  const tableHost = document.getElementById("highConfidenceThreats");
  const logHost = document.getElementById("autonomyLog");
  renderSkeleton(kpiHost, 6);
  renderSkeleton(pipelineHost, 5);
  renderSkeleton(tableHost, 8);
  mapInstance = createThreatMap(document.getElementById("threatMap"));

  async function load() {
    const [stats, activity, scans, cases] = await Promise.allSettled([
      request("/api/v1/dashboard/stats", {}, { allow404: true }),
      request("/api/v1/dashboard/activity", {}, { allow404: true }),
      request("/api/v1/scans/active", {}, { allow404: true }),
      request("/api/v1/cases?limit=20", {}, { allow404: true }),
    ]);
    const statsData = stats.status === "fulfilled" ? (stats.value || {}) : {};
    const activityData = toArray(activity.status === "fulfilled" ? pick(activity.value, ["results"], activity.value) : []);
    const scansData = toArray(scans.status === "fulfilled" ? pick(scans.value, ["results"], scans.value) : []);
    const caseData = toArray(cases.status === "fulfilled" ? pick(cases.value, ["results"], cases.value) : []);

    renderKpis(kpiHost, kpiCards(statsData));
    renderPipeline(pipelineHost, scansData);
    renderTable(
      tableHost,
      [
        { label: "Severity", render: (row) => `<span class="severity-line ${escapeHtml(severityTone(row.severity))}">${escapeHtml(row.severity)}</span>` },
        { label: "IOC", key: "ioc", className: "mono" },
        { label: "Type", key: "type" },
        { label: "Score", key: "score" },
        { label: "Actor", key: "actor" },
        { label: "Campaign", key: "campaign" },
        { label: "Detected", render: (row) => escapeHtml(formatTimestamp(row.detected)) },
        { label: "Action", key: "action" },
      ],
      threatRows(activityData, caseData),
      {
        emptyTitle: "No high-confidence threats",
        emptyDetail: "System operating normally or dashboard endpoints are not available yet.",
      },
    );
    renderAutonomy(logHost, activityData);
    mapInstance.setPoints(extractMapPoints(activityData));
  }

  bus.subscribe("ioc", (payload) => {
    if (!payload?.geo) return;
    mapInstance.setPoints([
      {
        lat: pick(payload, ["geo.lat", "lat"], 0),
        lon: pick(payload, ["geo.lon", "lon"], 0),
        severity: pick(payload, ["severity", "risk_level"], "medium"),
        score: pick(payload, ["score", "risk_score"], 70),
        value: pick(payload, ["value", "ioc_value"], "IOC"),
        country: pick(payload, ["geo.country", "country"], "Unknown"),
        actor: pick(payload, ["actor", "threat_actor"], "Unattributed"),
        detected_at: pick(payload, ["timestamp", "detected_at"]),
      },
    ]);
  });

  document.getElementById("refreshCommandView")?.addEventListener("click", load);
  await load();
}
