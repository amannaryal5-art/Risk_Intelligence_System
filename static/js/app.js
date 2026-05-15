import { drawSparkline } from "./charts.js";
import { createJsonBlock, openModal, renderEmpty, showToast } from "./components.js";
import { initActorsView } from "./actors.js";
import { initAssetsView } from "./assets.js";
import { initCampaignsView } from "./campaigns.js";
import { initCasesView } from "./cases.js";
import { initCommandView } from "./command.js";
import { initFeedsView } from "./feeds.js";
import { initReportsView } from "./reports.js";
import { initSettingsView } from "./settings.js";
import { initWorkbenchView } from "./workbench.js";
import { LiveDataBus } from "./liveBus.js";
import {
  $,
  $$,
  buildUrl,
  copyText,
  emit,
  escapeHtml,
  formatTimestamp,
  iconForIoc,
  jsonRequest,
  middleEllipsis,
  on,
  pick,
  relativeTime,
  request,
  severityTone,
  toArray,
} from "./utils.js";

const pageView = document.body.dataset.view;
const bus = new LiveDataBus({
  wsPath: document.body.dataset.wsPath,
  ssePath: document.body.dataset.iocStreamPath,
});

function activateNav() {
  $$("[data-nav]").forEach((link) => {
    link.classList.toggle("active", link.dataset.nav === pageView);
  });
}

function updateConnectionBadge(state) {
  const badge = $("#connectionBadge");
  const overlay = $("#offlineOverlay");
  if (!badge) return;
  badge.className = `status-chip ${state.state}`;
  if (state.state === "live") badge.textContent = "Live";
  if (state.state === "reconnecting") badge.textContent = `Reconnecting (${Math.ceil(state.retryIn || 1)}s)`;
  if (state.state === "offline") badge.textContent = "Offline";
  overlay.hidden = state.state === "live";
  $("#offlineMessage").textContent = state.state === "reconnecting"
    ? `Reconnecting to backend in ${Math.ceil(state.retryIn || 1)}s.`
    : "Connection lost. Retrying live control plane.";
}

function bindMenus() {
  $("#userMenuButton")?.addEventListener("click", () => {
    const menu = $("#userMenu");
    const expanded = !menu.hidden;
    menu.hidden = expanded;
    $("#userMenuButton").setAttribute("aria-expanded", String(!expanded));
  });
  $("#notificationsButton")?.addEventListener("click", () => {
    openModal({ title: "Recent Alerts", content: $("#toastRoot")?.cloneNode(true) || "<p>No alerts</p>", mode: "slide-over" });
  });
}

function renderStreamItem(item) {
  const severity = severityTone(item.severity || item.risk_level || "medium");
  const timestamp = item.timestamp || item.detected_at || Date.now();
  return `
    <button type="button" class="stream-item ${escapeHtml(severity)}" data-ioc-type="${escapeHtml(item.type || item.ioc_type || "domain")}" data-ioc-value="${escapeHtml(item.value || item.ioc_value || item.raw || "")}">
      <span class="stream-icon">${iconForIoc(item.type || item.ioc_type)}</span>
      <div class="stream-copy">
        <strong class="mono">${escapeHtml(middleEllipsis(item.value || item.ioc_value || item.raw || "IOC", 18, 10))}</strong>
        <span>${escapeHtml(relativeTime(timestamp))}</span>
      </div>
      <span class="pill ${escapeHtml(severity)}">${escapeHtml(item.score || item.risk_score || "--")}</span>
    </button>
  `;
}

async function openIocDetail(type, value) {
  const detail = await request(`/api/v1/ioc/${encodeURIComponent(type)}/${encodeURIComponent(value)}`, {}, { allow404: true });
  openModal({
    title: `${type.toUpperCase()} Intelligence`,
    content: detail ? createJsonBlock(detail) : `<p>IOC detail endpoint unavailable for ${escapeHtml(value)}.</p>`,
    mode: "slide-over",
  });
}

function bindStreamInteractions() {
  $("#iocStream")?.addEventListener("click", (event) => {
    const target = event.target.closest(".stream-item");
    if (!target) return;
    openIocDetail(target.dataset.iocType, target.dataset.iocValue);
  });
  $("#streamToggle")?.addEventListener("click", () => {
    const paused = bus.togglePause();
    $("#streamToggle").textContent = paused ? "Play" : "Pause";
  });
  $("#streamFilterToggle")?.addEventListener("click", () => {
    $("#streamFilters").hidden = !$("#streamFilters").hidden;
  });
}

function installShortcuts() {
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      $(".modal-layer.visible:last-child")?.remove();
    }
    if (event.key === "/" || (event.ctrlKey && event.key.toLowerCase() === "k")) {
      event.preventDefault();
      openCommandPalette();
    }
    if (event.key === "?") {
      openModal({
        title: "Keyboard Shortcuts",
        content: `
          <div class="shortcut-grid">
            <div>/ or Ctrl+K</div><div>Open command palette</div>
            <div>Esc</div><div>Close modal</div>
            <div>R</div><div>Refresh current view</div>
            <div>N</div><div>New manual case</div>
            <div>1-6</div><div>Switch primary view</div>
          </div>
        `,
      });
    }
    if (event.key.toLowerCase() === "r" && !event.ctrlKey && pageView !== "login") {
      window.location.reload();
    }
    if (event.key.toLowerCase() === "n") {
      $("#newManualCase")?.click();
    }
  });
}

async function openCommandPalette() {
  const results = await Promise.allSettled([
    request("/api/v1/cases?limit=6", {}, { allow404: true }),
    request("/api/v1/threats/campaigns", {}, { allow404: true }),
    request("/api/v1/threats/actors", {}, { allow404: true }),
  ]);
  const content = document.createElement("div");
  content.className = "palette";
  content.innerHTML = `
    <input id="paletteSearch" class="shell-input" type="search" placeholder="Search cases, IOCs, campaigns">
    <div class="palette-results">
      <section><h4>Cases</h4>${toArray(pick(results[0].value, ["results"], results[0].value)).map((item) => `<a href="/cases">#${escapeHtml(item.id)} ${escapeHtml(item.title || "")}</a>`).join("") || "<span>No case results</span>"}</section>
      <section><h4>Campaigns</h4>${toArray(pick(results[1].value, ["results"], results[1].value)).map((item) => `<a href="/campaigns">${escapeHtml(item.name || "")}</a>`).join("") || "<span>No campaign results</span>"}</section>
      <section><h4>Actors</h4>${toArray(pick(results[2].value, ["results"], results[2].value)).map((item) => `<a href="/actors">${escapeHtml(item.name || "")}</a>`).join("") || "<span>No actor results</span>"}</section>
    </div>
  `;
  openModal({ title: "Command Palette", content, mode: "center" });
}

async function loadWhoAmI() {
  const user = await request("/api/v1/auth/whoami", {}, { allow404: true });
  const role = user?.role || "viewer";
  $("#currentUserRole").textContent = role[0].toUpperCase() + role.slice(1);
  $$("[data-role='admin']").forEach((item) => {
    item.hidden = role !== "admin";
  });
  if (role === "viewer") {
    $$("[href='/workbench'], [href='/settings']").forEach((item) => item.hidden = true);
  }
}

async function loadFooterTicker() {
  const activity = await request("/api/v1/dashboard/activity", {}, { allow404: true });
  const items = toArray(pick(activity, ["results"], activity)).slice(0, 5);
  $("#activityTicker").textContent = items.length
    ? items.map((item) => `${formatTimestamp(item.timestamp || item.created_at)} ${item.message || item.description || item.action || "event"}`).join(" | ")
    : "Awaiting live activity...";
}

function bindCopyEndpoints() {
  $$("[data-copy]").forEach((button) => {
    button.addEventListener("click", async () => {
      await copyText(button.dataset.copy);
      showToast(`Copied ${button.dataset.copy}`, "info");
    });
  });
}

function wireBus() {
  bus.connect();
  bus.subscribe("connection", updateConnectionBadge);
  bus.subscribe("latency", ({ current, values }) => {
    $("#latencyValue").textContent = `${current}ms`;
    drawSparkline($("#latencySparkline"), values, "#06b6d4");
  });
  bus.subscribe("ioc", (payload) => {
    const host = $("#iocStream");
    if (!host) return;
    host.insertAdjacentHTML("afterbegin", renderStreamItem(payload));
    host.querySelectorAll(".stream-item").forEach((item, index) => {
      if (index > 49) item.remove();
    });
  });
  bus.subscribe("queue:changed", ({ count }) => {
    $("#offlineQueueCount").textContent = `Queued analyst actions: ${count}`;
  });
  on("alert:critical", (payload) => {
    $("#screenEdgeAlert").classList.add("active");
    $("#notificationCount").textContent = String(Number($("#notificationCount").textContent || "0") + 1);
    showToast(payload.message || "Critical alert received", "critical", { sticky: true });
    window.setTimeout(() => $("#screenEdgeAlert").classList.remove("active"), 2200);
  });
}

function initLogin() {
  $("#loginForm")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const payload = Object.fromEntries(new FormData(event.currentTarget).entries());
    try {
      const response = await jsonRequest("/api/v1/auth/login", { method: "POST", body: JSON.stringify(payload) }, { allow404: true });
      if (!response) {
        $("#loginStatus").textContent = "Live login endpoint is not available yet. The page is wired and waiting for backend auth.";
        return;
      }
      window.location.href = "/";
    } catch (error) {
      $("#loginStatus").textContent = error.message;
    }
  });
}

const viewInit = {
  command: initCommandView,
  cases: initCasesView,
  feeds: initFeedsView,
  campaigns: initCampaignsView,
  actors: initActorsView,
  assets: initAssetsView,
  reports: initReportsView,
  workbench: initWorkbenchView,
  settings: initSettingsView,
};

async function bootstrap() {
  activateNav();
  if (pageView === "login") {
    initLogin();
    return;
  }
  bindMenus();
  bindStreamInteractions();
  bindCopyEndpoints();
  installShortcuts();
  wireBus();
  await Promise.allSettled([loadWhoAmI(), loadFooterTicker()]);
  const initializer = viewInit[pageView];
  await initializer?.({ bus });
  window.setInterval(loadFooterTicker, 30000);
  window.setInterval(async () => {
    await request("/api/v1/auth/refresh", { method: "POST" }, { allow404: true }).catch(() => {});
  }, 14 * 60 * 1000);
}

on("auth:expired", () => {
  if (window.location.pathname !== "/login") {
    window.location.href = `/login?return=${encodeURIComponent(window.location.pathname)}`;
  }
});

bootstrap().catch((error) => {
  const main = $("#mainContent");
  if (main) {
    renderEmpty(main, "Backend disconnected", error.message);
  }
});
