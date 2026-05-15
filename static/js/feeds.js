import { drawSparkline } from "./charts.js";
import { openModal, renderEmpty, renderSkeleton, showToast } from "./components.js";
import { escapeHtml, formatPercent, formatTimestamp, pick, request, toArray } from "./utils.js";

const feedLogLines = [];

function renderTopology(container, feeds = []) {
  if (!container) return;
  if (!feeds.length) {
    renderEmpty(container, "No feed topology", "Feed health endpoints are unavailable.");
    return;
  }
  container.innerHTML = `
    <svg viewBox="0 0 900 320" class="topology-svg">
      <circle cx="450" cy="160" r="56" class="core-node"></circle>
      <text x="450" y="166" text-anchor="middle">RiskIntel Core</text>
      ${feeds.map((feed, index) => {
        const angle = (Math.PI * 2 * index) / Math.max(feeds.length, 1);
        const x = 450 + Math.cos(angle) * 220;
        const y = 160 + Math.sin(angle) * 110;
        const tone = String(feed.status || feed.state || feed.reachable || "").toLowerCase();
        return `
          <line x1="450" y1="160" x2="${x}" y2="${y}" class="topology-line ${escapeHtml(tone)}"></line>
          <circle cx="${x}" cy="${y}" r="${Math.max(20, Number(feed.volume || 20) / 8)}" class="satellite-node ${escapeHtml(tone)}"></circle>
          <text x="${x}" y="${y + 4}" text-anchor="middle">${escapeHtml(feed.name || feed.provider || "Feed")}</text>
        `;
      }).join("")}
    </svg>
  `;
}

function renderProviders(container, feeds = []) {
  if (!container) return;
  if (!feeds.length) {
    renderEmpty(container, "No provider health data", "The live backend did not return provider status.");
    return;
  }
  container.innerHTML = feeds.map((feed) => `
    <article class="feed-card ${escapeHtml(String(feed.status || feed.state || "ready").toLowerCase())}">
      <div class="feed-card-header">
        <strong>${escapeHtml(feed.display_name || feed.name || "Provider")}</strong>
        <span class="pill ${escapeHtml(String(feed.status || "ready").toLowerCase())}">${escapeHtml(feed.status || feed.state || "Ready")}</span>
      </div>
      <div class="stat-line"><span>Uptime</span><strong>${escapeHtml(formatPercent(feed.uptime_pct || 0))}</strong></div>
      <div class="stat-line"><span>Avg Latency</span><strong>${escapeHtml(feed.latency_ms || "--")}ms</strong></div>
      <div class="stat-line"><span>IOCs/hour</span><strong>${escapeHtml(feed.iocs_per_hour || feed.volume || 0)}</strong></div>
      <div class="stat-line"><span>Status</span><strong>${escapeHtml(feed.message || feed.error || "Operational")}</strong></div>
      <canvas width="160" height="34" data-feed-latency="${escapeHtml(feed.name || "")}"></canvas>
      <div class="button-row">
        <button type="button" class="button secondary compact" data-probe="${escapeHtml(feed.id || feed.name || "")}">Probe Now</button>
        <button type="button" class="button ghost compact" data-detail="${escapeHtml(feed.id || feed.name || "")}">View Logs</button>
      </div>
    </article>
  `).join("");
  feeds.forEach((feed) => {
    const canvas = container.querySelector(`[data-feed-latency="${CSS.escape(feed.name || "")}"]`);
    drawSparkline(canvas, toArray(feed.sparkline || feed.latency_history || [10, 18, 12, 20]), "#06b6d4");
  });
}

function renderQuota(container, quotas = []) {
  if (!container) return;
  if (!quotas.length) {
    renderEmpty(container, "No quota telemetry", "Quota endpoints are unavailable.");
    return;
  }
  container.innerHTML = quotas.map((quota) => {
    const used = Number(quota.used_pct || quota.percent_used || 0);
    const tone = used >= 95 ? "critical" : used >= 80 ? "high" : "clean";
    return `
      <div class="quota-item">
        <div class="quota-head">
          <strong>${escapeHtml(quota.name || quota.provider || "Provider")}</strong>
          <span>${used}%</span>
        </div>
        <div class="progress-bar"><span style="width:${used}%" class="${tone}"></span></div>
        <div class="quota-foot">${escapeHtml(quota.projected_exhaustion || "Projected exhaustion unavailable")}</div>
      </div>
    `;
  }).join("");
}

function appendLog(line, tone = "clean") {
  const host = document.getElementById("feedLogs");
  if (!host) return;
  feedLogLines.unshift(`<span class="${escapeHtml(tone)}">${escapeHtml(line)}</span>`);
  host.innerHTML = feedLogLines.slice(0, 120).join("\n");
}

export async function initFeedsView({ bus }) {
  const topology = document.getElementById("feedTopology");
  const providers = document.getElementById("feedProviderGrid");
  const quota = document.getElementById("quotaDashboard");
  renderSkeleton(providers, 4);
  renderSkeleton(quota, 3);

  const load = async () => {
    const [status, statusFallback, quotaData] = await Promise.allSettled([
      request("/api/v1/feeds/status", {}, { allow404: true }),
      request("/api/v1/feeds/status/live", {}, { allow404: true }),
      request("/api/v1/feeds/quota", {}, { allow404: true }),
    ]);
    const feedData = status.status === "fulfilled" && status.value
      ? toArray(pick(status.value, ["feeds"], status.value))
      : toArray(statusFallback.status === "fulfilled" ? pick(statusFallback.value, ["feeds"], statusFallback.value) : []);
    const quotas = quotaData.status === "fulfilled" ? toArray(pick(quotaData.value, ["results", "feeds"], quotaData.value)) : [];
    renderTopology(topology, feedData);
    renderProviders(providers, feedData);
    renderQuota(quota, quotas);
    appendLog(`[${new Date().toLocaleTimeString()}] feed status refresh complete`, "clean");
  };

  providers?.addEventListener("click", async (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;
    if (target.dataset.probe) {
      await request(`/api/v1/feeds/${target.dataset.probe}/probe`, { method: "POST" }, { allow404: true });
      showToast("Probe request submitted", "info");
      await load();
    }
    if (target.dataset.detail) {
      openModal({ title: `Feed ${target.dataset.detail}`, content: `<pre class="json-block">${escapeHtml(feedLogLines.join("\n"))}</pre>`, mode: "slide-over" });
    }
  });

  document.getElementById("probeAllFeeds")?.addEventListener("click", load);
  document.getElementById("downloadFeedLogs")?.addEventListener("click", () => {
    const blob = new Blob([feedLogLines.join("\n")], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const link = Object.assign(document.createElement("a"), { href: url, download: "feed-logs.txt" });
    link.click();
    URL.revokeObjectURL(url);
  });

  bus.subscribe("ws:message", (payload) => {
    if (payload?.type === "feed_status" || payload?.feed) {
      appendLog(`[${new Date().toLocaleTimeString()}] ${payload.message || payload.feed || "feed event"}`, payload.severity || "clean");
      load();
    }
  });

  await load();
}
