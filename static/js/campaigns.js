import { createJsonBlock, renderEmpty, renderSkeleton } from "./components.js";
import { escapeHtml, formatTimestamp, pick, request, toArray } from "./utils.js";

function renderCards(container, campaigns = [], detailHost) {
  if (!container) return;
  if (!campaigns.length) {
    renderEmpty(container, "No campaign telemetry", "The backend did not return active campaign data.");
    return;
  }
  container.innerHTML = campaigns.map((campaign) => `
    <button class="campaign-card" type="button" data-id="${escapeHtml(campaign.id || campaign.name || "")}">
      <div class="eyebrow">${escapeHtml(campaign.threat_actor || "Unknown Actor")}</div>
      <h3>${escapeHtml(campaign.name || "Untitled Campaign")}</h3>
      <div class="progress-bar"><span style="width:${Math.min(100, Number(campaign.progress_pct || campaign.duration_pct || 50))}%"></span></div>
      <p>${escapeHtml(campaign.description || "No narrative supplied by backend.")}</p>
      <div class="stat-line"><span>First seen</span><strong>${escapeHtml(formatTimestamp(campaign.start_date || campaign.first_seen))}</strong></div>
      <div class="stat-line"><span>IOCs</span><strong>${escapeHtml(campaign.ioc_count || 0)}</strong></div>
    </button>
  `).join("");
  container.querySelectorAll("[data-id]").forEach((button, index) => {
    button.addEventListener("click", async () => {
      const selected = campaigns[index];
      const detail = await request(`/api/v1/threats/campaigns/${selected.id}`, {}, { allow404: true });
      if (!detail) {
        detailHost.innerHTML = "";
        detailHost.append(createJsonBlock(selected));
        return;
      }
      detailHost.innerHTML = `
        <div class="detail-section">
          <div class="eyebrow">${escapeHtml(detail.threat_actor || "Unknown Actor")}</div>
          <h2>${escapeHtml(detail.name || "Campaign Detail")}</h2>
          <p>${escapeHtml(detail.description || "No backend narrative available.")}</p>
        </div>
      `;
      detailHost.append(createJsonBlock(detail));
    });
  });
}

export async function initCampaignsView() {
  const cards = document.getElementById("campaignCards");
  const detail = document.getElementById("campaignDetail");
  renderSkeleton(cards, 6);
  const data = await request("/api/v1/threats/campaigns", {}, { allow404: true });
  const items = toArray(pick(data, ["results"], data));
  renderCards(cards, items, detail);
}
