import { openModal, renderEmpty, renderSkeleton, renderTable, showToast } from "./components.js";
import { escapeHtml, jsonRequest, pick, request, toArray } from "./utils.js";

function ruleBuilder(loadRules) {
  const form = document.createElement("form");
  form.className = "rule-form";
  form.innerHTML = `
    <label><span>Rule Name</span><input class="shell-input" name="name" required></label>
    <label><span>Trigger</span>
      <select class="shell-input" name="trigger">
        <option>IOC Detected</option>
        <option>Score Changed</option>
        <option>Case Created</option>
        <option>Feed Down</option>
        <option>Time Schedule</option>
      </select>
    </label>
    <label><span>Conditions</span><textarea class="shell-input" name="conditions" rows="4">IOC Type is IP AND Score greater than 80</textarea></label>
    <label><span>Actions</span><textarea class="shell-input" name="actions" rows="4">Create Case with Severity Critical</textarea></label>
    <button class="button" type="submit">Save Rule</button>
  `;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const payload = Object.fromEntries(new FormData(form).entries());
    await jsonRequest("/api/v1/settings/rules", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    showToast("Rule created", "success");
    form.closest(".modal-layer")?.remove();
    loadRules();
  });
  return form;
}

export async function initSettingsView() {
  const table = document.getElementById("rulesTable");
  renderSkeleton(table, 6);

  const loadRules = async () => {
    const data = await request("/api/v1/settings/rules", {}, { allow404: true });
    if (!data) {
      renderEmpty(table, "Automation rules unavailable", "This backend does not yet expose live automation rules.");
      return;
    }
    const rows = toArray(pick(data, ["results"], data));
    renderTable(table, [
      { label: "Name", key: "name" },
      { label: "Trigger", key: "trigger" },
      { label: "Conditions", key: "conditions" },
      { label: "Actions", key: "actions" },
      { label: "Status", render: (row) => escapeHtml(row.status || "active") },
      { label: "Last Fired", render: (row) => escapeHtml(row.last_fired || "--") },
      { label: "Hit Count", render: (row) => escapeHtml(row.hit_count || 0) },
      { label: "Delete", render: (row) => `<button type="button" class="button ghost compact" data-delete="${escapeHtml(row.id || "")}">Delete</button>` },
    ], rows, {
      emptyTitle: "No automation rules",
      emptyDetail: "Create the first rule when the backend rules service is ready.",
    });
    table.querySelectorAll("[data-delete]").forEach((button) => {
      button.addEventListener("click", async () => {
        await request(`/api/v1/settings/rules/${button.dataset.delete}`, { method: "DELETE" });
        showToast("Rule deleted", "success");
        loadRules();
      });
    });
  };

  document.getElementById("newRule")?.addEventListener("click", () => {
    openModal({ title: "Rule Builder", content: ruleBuilder(loadRules), mode: "center" });
  });

  await loadRules();
}
