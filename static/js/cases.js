import { actionButton, createJsonBlock, openModal, renderEmpty, renderSkeleton, renderTable, showToast } from "./components.js";
import { buildUrl, debounce, escapeHtml, formatTimestamp, jsonRequest, pick, request, severityTone, toArray } from "./utils.js";

const filterPills = ["All", "Auto-Created", "Manual", "Critical", "SLA At Risk", "Resolved Today"];

function buildFilters(container) {
  container.innerHTML = filterPills
    .map((label, index) => `<button class="pill-button ${index === 0 ? "active" : ""}" type="button">${escapeHtml(label)}</button>`)
    .join("");
}

function openCaseDetail(caseId, row, bus) {
  const panel = document.createElement("div");
  panel.className = "case-detail";
  panel.innerHTML = "<div class='loading-copy'>Loading case detail...</div>";
  const layer = openModal({ title: `Case #${caseId}`, content: panel, mode: "slide-over" });

  const loadDetail = async () => {
    const detail = await request(`/api/v1/cases/${caseId}`, {}, { allow404: true });
    if (!detail) {
      renderEmpty(panel, "Case endpoint unavailable", "This backend does not yet expose the requested case detail route.");
      return;
    }
    panel.innerHTML = `
      <div class="detail-tabs">
        <button class="pill-button active" type="button">Overview</button>
        <button class="pill-button" type="button">Timeline</button>
        <button class="pill-button" type="button">Raw Data</button>
      </div>
      <div class="detail-section">
        <div class="stat-grid">
          <div><span>Severity</span><strong>${escapeHtml(detail.severity || "--")}</strong></div>
          <div><span>Status</span><strong>${escapeHtml(detail.status || "--")}</strong></div>
          <div><span>Assignee</span><strong>${escapeHtml(detail.assigned_to || "Auto")}</strong></div>
          <div><span>Reporter</span><strong>${escapeHtml(detail.reporter || "--")}</strong></div>
        </div>
      </div>
      <div class="detail-section">
        <h4>Executive Summary</h4>
        <p>${escapeHtml(pick(detail, ["summary", "notes", "title"], "No executive summary available from backend."))}</p>
      </div>
      <div class="detail-section">
        <h4>Analyst Notes</h4>
        <div>${toArray(detail.comments).map((comment) => `
          <article class="note-card">
            <strong>${escapeHtml(comment.author || "Analyst")}</strong>
            <p>${escapeHtml(comment.message || "")}</p>
            <span>${escapeHtml(formatTimestamp(comment.created_at))}</span>
          </article>
        `).join("") || "<p>No notes yet.</p>"}</div>
      </div>
    `;
    const raw = createJsonBlock(detail);
    const rawWrap = document.createElement("div");
    rawWrap.className = "detail-section";
    rawWrap.append(raw);
    panel.append(rawWrap);
  };

  loadDetail().catch((error) => {
    panel.innerHTML = `<div class="error-banner">${escapeHtml(error.message)}</div>`;
  });
}

async function updateCase(caseId, payload, bus, successMessage) {
  const action = async () => {
    try {
      await jsonRequest(`/api/v1/cases/${caseId}/status`, { method: "PATCH", body: JSON.stringify(payload) }, { allow404: true });
    } catch {
      await jsonRequest(`/api/v1/cases/${caseId}`, { method: "PATCH", body: JSON.stringify(payload) }, { retries: 1 });
    }
    showToast(successMessage, "success");
  };
  if (!bus.connected) {
    bus.enqueueAction(action);
    showToast("Action queued until live connection returns.", "warning");
    return;
  }
  await action();
}

export async function initCasesView({ bus }) {
  const filtersHost = document.getElementById("caseFilters");
  const tableHost = document.getElementById("casesTable");
  buildFilters(filtersHost);
  renderSkeleton(tableHost, 8);

  const loadCases = async (search = "") => {
    const data = await request(buildUrl("/api/v1/cases", { limit: 100, search }), {}, { allow404: true });
    if (!data) {
      renderEmpty(tableHost, "Case API unavailable", "The live backend does not currently expose the full autonomous case queue contract.");
      return;
    }
    const rows = toArray(data.results).map((item) => ({
      ...item,
      priority: item.severity === "critical" ? "P1" : item.severity === "high" ? "P2" : "P3",
      source: item.source_type || "System",
      sla: item.sla_remaining || "Monitoring",
      last_action: item.updated_at || item.created_at,
    }));
    renderTable(
      tableHost,
      [
        { label: "Priority", render: (row) => `<span class="flag ${escapeHtml(severityTone(row.severity))}">${escapeHtml(row.priority)}</span>` },
        { label: "Case ID", render: (row) => `<span class="mono">#${escapeHtml(row.id)}</span>` },
        { label: "Title", render: (row) => `${row.source === "manual" ? "" : "🤖 "}${escapeHtml(row.title || "Untitled")}` },
        { label: "Severity", render: (row) => `<span class="severity-line ${escapeHtml(severityTone(row.severity))}">${escapeHtml(row.severity)}</span>` },
        { label: "Status", render: (row) => escapeHtml(row.status || "new") },
        { label: "Analyst", render: (row) => escapeHtml(row.assigned_to || "🤖 Auto") },
        { label: "Source", render: (row) => escapeHtml(row.source) },
        { label: "Last Action", render: (row) => escapeHtml(formatTimestamp(row.last_action)) },
        { label: "Controls", render: (row) => `${actionButton("View", `view:${row.id}`)} ${actionButton("Assign to Me", `assign:${row.id}`)} ${actionButton("Close", `close:${row.id}`)}` },
      ],
      rows,
      {
        onRowClick: (row) => openCaseDetail(row.id, row, bus),
        emptyTitle: "No cases",
        emptyDetail: "The case queue is empty or the endpoint returned no records.",
      },
    );

    tableHost.querySelectorAll("[data-action]").forEach((button) => {
      button.addEventListener("click", async (event) => {
        event.stopPropagation();
        const [action, id] = button.dataset.action.split(":");
        if (action === "view") openCaseDetail(Number(id), rows.find((row) => String(row.id) === id), bus);
        if (action === "assign") {
          await updateCase(Number(id), { assigned_to: "me" }, bus, "Case assignment submitted");
          await loadCases(search);
        }
        if (action === "close") {
          await updateCase(Number(id), { status: "closed" }, bus, "Case closure submitted");
          await loadCases(search);
        }
      });
    });
  };

  document.getElementById("newManualCase")?.addEventListener("click", () => {
    const form = document.createElement("form");
    form.className = "rule-form";
    form.innerHTML = `
      <label><span>Title</span><input class="shell-input" name="title" required></label>
      <label><span>Severity</span><select class="shell-input" name="severity"><option>medium</option><option>high</option><option>critical</option></select></label>
      <button class="button" type="submit">Create Manual Case</button>
    `;
    const layer = openModal({ title: "Create Manual Case", content: form });
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const payload = Object.fromEntries(new FormData(form).entries());
      await jsonRequest("/api/v1/cases", { method: "POST", body: JSON.stringify({ ...payload, source_type: "manual", status: "new" }) });
      showToast("Manual case created", "success");
      layer?.remove();
      await loadCases();
    });
  });

  document.getElementById("caseSearch")?.addEventListener("input", debounce((event) => {
    loadCases(event.target.value);
  }, 300));

  await loadCases();
}
