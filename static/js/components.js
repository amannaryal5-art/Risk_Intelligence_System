import { gaugeSvg, toneColor } from "./charts.js";
import {
  $,
  escapeHtml,
  formatNumber,
  jsonPreview,
  severityTone,
  classNames,
} from "./utils.js";

const toastState = [];

export function renderSkeleton(container, rows = 4) {
  if (!container) return;
  container.innerHTML = "";
  for (let index = 0; index < rows; index += 1) {
    const skeleton = document.createElement("div");
    skeleton.className = "skeleton-row";
    skeleton.innerHTML = "<span></span><span></span><span></span>";
    container.append(skeleton);
  }
}

export function renderEmpty(container, title, detail = "") {
  if (!container) return;
  container.innerHTML = `
    <div class="empty-state">
      <div class="empty-icon">◎</div>
      <h3>${escapeHtml(title)}</h3>
      <p>${escapeHtml(detail || "No live data has arrived yet.")}</p>
    </div>
  `;
}

export function renderKpis(container, cards = []) {
  if (!container) return;
  container.innerHTML = cards.map((card) => `
    <article class="kpi-card">
      <div class="kpi-label">${escapeHtml(card.label)}</div>
      <div class="kpi-value">${escapeHtml(card.value)}</div>
      <div class="kpi-meta">${escapeHtml(card.meta || "--")}</div>
      <div class="kpi-footer">${escapeHtml(card.footer || "")}</div>
    </article>
  `).join("");
}

export function renderBadge(value, tone = value) {
  return `<span class="pill ${escapeHtml(severityTone(tone))}">${escapeHtml(value)}</span>`;
}

export function renderTable(container, columns = [], rows = [], options = {}) {
  if (!container) return;
  if (!rows.length) {
    renderEmpty(container, options.emptyTitle || "No records", options.emptyDetail || "");
    return;
  }
  const table = document.createElement("table");
  table.className = "data-table";
  const thead = document.createElement("thead");
  const headRow = document.createElement("tr");
  columns.forEach((column) => {
    const cell = document.createElement("th");
    cell.textContent = column.label;
    headRow.append(cell);
  });
  thead.append(headRow);
  table.append(thead);
  const tbody = document.createElement("tbody");
  rows.forEach((row, rowIndex) => {
    const tr = document.createElement("tr");
    if (options.onRowClick) {
      tr.tabIndex = 0;
      tr.classList.add("interactive-row");
      tr.addEventListener("click", () => options.onRowClick(row, rowIndex));
      tr.addEventListener("keydown", (event) => {
        if (event.key === "Enter") options.onRowClick(row, rowIndex);
      });
    }
    columns.forEach((column) => {
      const cell = document.createElement("td");
      if (column.className) cell.className = column.className;
      const value = typeof column.render === "function" ? column.render(row, rowIndex) : row[column.key];
      if (value instanceof Node) {
        cell.append(value);
      } else {
        cell.innerHTML = String(value ?? "");
      }
      tr.append(cell);
    });
    tbody.append(tr);
  });
  table.append(tbody);
  container.innerHTML = "";
  container.append(table);
}

export function showToast(message, type = "info", options = {}) {
  const host = $("#toastRoot");
  if (!host) return;
  const similar = toastState.filter((item) => item.type === type);
  const record = {
    id: crypto.randomUUID(),
    type,
    message,
    sticky: Boolean(options.sticky || type === "critical"),
  };
  toastState.push(record);
  if (similar.length >= 2) {
    const collapsed = host.querySelector(`[data-toast-group="${type}"]`);
    if (collapsed) {
      const count = Number(collapsed.dataset.count || "2") + 1;
      collapsed.dataset.count = String(count);
      $(".toast-count", collapsed).textContent = `${count} new alerts`;
      return;
    }
  }
  const toast = document.createElement("div");
  toast.className = classNames("toast", type);
  if (similar.length >= 2) {
    toast.dataset.toastGroup = type;
    toast.dataset.count = "3";
    toast.innerHTML = `<strong class="toast-count">3 new alerts</strong><button type="button" class="button ghost compact">Expand</button>`;
    toast.querySelector("button")?.addEventListener("click", () => toast.remove());
  } else {
    toast.innerHTML = `<strong>${escapeHtml(type.toUpperCase())}</strong><span>${escapeHtml(message)}</span>`;
  }
  host.prepend(toast);
  requestAnimationFrame(() => toast.classList.add("visible"));
  if (!record.sticky) {
    window.setTimeout(() => dismissToast(toast, record.id), 5000);
  } else {
    maybeBeep();
  }
}

function dismissToast(element, id) {
  element?.classList.remove("visible");
  const index = toastState.findIndex((item) => item.id === id);
  if (index >= 0) toastState.splice(index, 1);
  window.setTimeout(() => element?.remove(), 180);
}

function maybeBeep() {
  const AudioContextRef = window.AudioContext || window.webkitAudioContext;
  if (!AudioContextRef) return;
  const audio = new AudioContextRef();
  const oscillator = audio.createOscillator();
  const gain = audio.createGain();
  oscillator.type = "square";
  oscillator.frequency.value = 880;
  gain.gain.value = 0.03;
  oscillator.connect(gain);
  gain.connect(audio.destination);
  oscillator.start();
  oscillator.stop(audio.currentTime + 0.12);
}

export function createJsonBlock(value) {
  const block = document.createElement("pre");
  block.className = "json-block";
  block.textContent = jsonPreview(value);
  return block;
}

export function openModal({ title = "", content = "", mode = "center", actions = [] }) {
  const host = $("#modalRoot");
  if (!host) return null;
  const layer = document.createElement("div");
  layer.className = classNames("modal-layer", mode);
  const actionMarkup = actions.map((action, index) => `
    <button type="button" class="button ${index === 0 ? "" : "secondary"}" data-action="${escapeHtml(action.id)}">${escapeHtml(action.label)}</button>
  `).join("");
  layer.innerHTML = `
    <div class="modal-backdrop" data-close="true"></div>
    <div class="modal-card">
      <div class="modal-header">
        <h3>${escapeHtml(title)}</h3>
        <button type="button" class="icon-button compact" data-close="true" aria-label="Close">Close</button>
      </div>
      <div class="modal-body"></div>
      ${actions.length ? `<div class="modal-actions">${actionMarkup}</div>` : ""}
    </div>
  `;
  const body = $(".modal-body", layer);
  if (content instanceof Node) body.append(content);
  else body.innerHTML = String(content);
  layer.addEventListener("click", (event) => {
    const target = event.target;
    if (target instanceof HTMLElement && target.dataset.close) closeModal(layer);
    if (target instanceof HTMLElement && target.dataset.action) {
      const action = actions.find((item) => item.id === target.dataset.action);
      action?.onClick?.(layer);
    }
  });
  host.append(layer);
  requestAnimationFrame(() => layer.classList.add("visible"));
  return layer;
}

export function closeModal(layer) {
  layer?.classList.remove("visible");
  window.setTimeout(() => layer?.remove(), 180);
}

export function statList(items = []) {
  return items.map((item) => `
    <div class="stat-line">
      <span>${escapeHtml(item.label)}</span>
      <strong>${escapeHtml(item.value)}</strong>
    </div>
  `).join("");
}

export function iocScoreChip(score = 0, tone = "medium") {
  return `<div class="score-chip ${escapeHtml(severityTone(tone))}">${gaugeSvg(score, tone)}</div>`;
}

export function severityPill(value) {
  return renderBadge(String(value || "Unknown"), value);
}

export function actionButton(label, action, tone = "secondary") {
  return `<button type="button" class="button ${escapeHtml(tone)} compact" data-action="${escapeHtml(action)}">${escapeHtml(label)}</button>`;
}

export function renderInfoCard(title, subtitle, details = []) {
  return `
    <article class="info-card">
      <div class="eyebrow">${escapeHtml(subtitle)}</div>
      <h3>${escapeHtml(title)}</h3>
      <div class="info-card-body">
        ${statList(details)}
      </div>
    </article>
  `;
}

export function renderProgressBar(value = 0, tone = "low") {
  const normalized = Math.max(0, Math.min(100, Number(value) || 0));
  return `<div class="progress-bar"><span style="width:${normalized}%;background:${toneColor(tone)}"></span></div>`;
}
