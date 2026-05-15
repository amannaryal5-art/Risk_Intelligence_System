import { renderEmpty, renderSkeleton } from "./components.js";
import { escapeHtml, pick, request, toArray } from "./utils.js";

const tactics = ["Recon", "Resource", "Initial", "Execution", "Persistence", "Privilege", "Defense", "Credential", "Discovery", "Lateral", "Collection", "C2", "Exfil", "Impact"];

function renderMatrix(container, actors = []) {
  if (!container) return;
  container.innerHTML = `
    <div class="matrix-head">${tactics.map((tactic) => `<span>${escapeHtml(tactic)}</span>`).join("")}</div>
    <div class="matrix-row">${tactics.map(() => "<button type='button' class='matrix-cell active'></button>").join("")}</div>
  `;
}

function renderCards(container, actors = []) {
  if (!container) return;
  if (!actors.length) {
    renderEmpty(container, "No actor data", "Threat actor intelligence is not yet available from the backend.");
    return;
  }
  container.innerHTML = actors.map((actor) => `
    <article class="actor-card">
      <div class="actor-avatar">${escapeHtml((actor.name || "A").slice(0, 2).toUpperCase())}</div>
      <div>
        <h3>${escapeHtml(actor.name || "Unknown Actor")}</h3>
        <p>${escapeHtml(actor.motivation || actor.summary || "No motivation profile supplied.")}</p>
        <div class="stat-line"><span>Aliases</span><strong>${escapeHtml(toArray(actor.aliases).join(", ") || "--")}</strong></div>
        <div class="stat-line"><span>Campaigns</span><strong>${escapeHtml(actor.campaign_count || 0)}</strong></div>
      </div>
    </article>
  `).join("");
}

export async function initActorsView() {
  const matrix = document.getElementById("attackMatrix");
  const cards = document.getElementById("actorCards");
  renderSkeleton(cards, 6);
  const data = await request("/api/v1/threats/actors", {}, { allow404: true });
  const actors = toArray(pick(data, ["results"], data));
  renderMatrix(matrix, actors);
  renderCards(cards, actors);
}
