/* ARIA — Frontend App */

const API = '';
let allAssets    = [];
let chatHistory  = [];   // {role, content}
let sidebarOpen  = true;
let currentReport = null;

// ── Boot ────────────────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  loadAll();
  setInterval(loadAll, 60_000);   // refresh everything every 60s
});

async function loadAll() {
  await Promise.all([loadAssets(), loadAlerts(), loadStats(), loadReports()]);
}

// ── Assets ───────────────────────────────────────────────────────────────────
async function loadAssets() {
  try {
    const res = await fetch(`${API}/api/aria/assets`);
    allAssets = await res.json();
    renderSidebarAssets();
    renderDashboard();
  } catch(e) { console.error('loadAssets:', e) }
}

async function addAsset() {
  const name  = qs('#assetName').value.trim();
  const type  = qs('#assetType').value;
  const value = qs('#assetValue').value.trim();
  if (!value) return flash('Enter an asset value');

  const btn = qs('.btn-add-asset');
  btn.disabled = true;
  btn.textContent = '↻ Adding…';

  try {
    const res = await fetch(`${API}/api/aria/assets`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ name: name || value, type, value }),
    });
    if (!res.ok) throw new Error(await res.text());
    qs('#assetName').value = '';
    qs('#assetValue').value = '';
    await loadAssets();
    setTimeout(loadAssets, 8000);
    setTimeout(loadAssets, 20000);
  } catch(e) {
    flash('Error: ' + e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Monitor this';
  }
}

async function deleteAsset(id, e) {
  e.stopPropagation();
  if (!confirm('Stop monitoring this asset?')) return;
  await fetch(`${API}/api/aria/assets/${id}`, { method: 'DELETE' });
  await loadAssets();
}

async function scanNow(id, e) {
  e && e.stopPropagation();
  await fetch(`${API}/api/aria/assets/${id}/scan`, { method: 'POST' });
  setTimeout(loadAssets, 8000);
  setTimeout(loadAssets, 20000);
}

async function runAllScans() {
  const btn = qs('.btn-secondary');
  btn.disabled = true; btn.textContent = '↻ Scanning…';
  await Promise.all(allAssets.map(a => fetch(`${API}/api/aria/assets/${a.id}/scan`, {method:'POST'})));
  setTimeout(async () => { await loadAssets(); btn.disabled=false; btn.textContent='↻ Scan all now'; }, 12000);
}

// ── Sidebar render ────────────────────────────────────────────────────────────
function renderSidebarAssets() {
  const el = qs('#assetList');
  if (!allAssets.length) {
    el.innerHTML = '<div class="asset-empty">No assets yet.<br/>Add one below.</div>';
    return;
  }
  el.innerHTML = allAssets.map(a => {
    const level = a.last_risk_level || 'Unknown';
    const dot   = riskColor(level);
    return `
      <div class="asset-row" onclick="openAssetDetail(${a.id})">
        <div class="asset-risk-dot" style="background:${dot};box-shadow:0 0 5px ${dot}"></div>
        <div class="asset-row-info">
          <div class="asset-row-name">${esc(a.name || a.value)}</div>
          <div class="asset-row-level">${level} · ${a.type}</div>
        </div>
        <button class="asset-row-del" onclick="deleteAsset(${a.id},event)" title="Remove">✕</button>
      </div>`;
  }).join('');
}

// ── Dashboard render ──────────────────────────────────────────────────────────
function renderDashboard() {
  const grid = qs('#assetCards');
  if (!allAssets.length) {
    grid.innerHTML = '<div class="dash-empty">Add assets in the sidebar to start monitoring.</div>';
    return;
  }
  grid.innerHTML = allAssets.map(a => {
    const level = a.last_risk_level || 'Unknown';
    const score = a.last_risk_score || 0;
    const color = riskColor(level);
    const time  = a.last_scanned_at ? timeAgo(a.last_scanned_at) : 'pending…';
    return `
      <div class="asset-card risk-${level}" onclick="openAssetDetail(${a.id})">
        <div class="card-top">
          <div class="card-meta">
            <div class="card-type">${a.type}</div>
            <div class="card-name">${esc(a.name || a.value)}</div>
            <div class="card-value">${esc(a.value)}</div>
          </div>
          <div class="risk-pill ${level}">${level}</div>
        </div>
        <div class="score-bar-wrap">
          <div class="score-bar">
            <div class="score-fill" style="width:${score}%;background:${color}"></div>
          </div>
        </div>
        <div class="card-summary">${esc(a.last_summary || 'Scanning…')}</div>
        <div class="card-footer">
          <span class="card-time">${time}</span>
          <div class="card-actions-row">
            <button class="btn-card" onclick="scanNow(${a.id},event)">↻ Scan</button>
            <button class="btn-card" onclick="openAssetDetail(${a.id})">Details</button>
          </div>
        </div>
      </div>`;
  }).join('');
}

// ── Stats ─────────────────────────────────────────────────────────────────────
async function loadStats() {
  try {
    const s = await fetch(`${API}/api/aria/stats`).then(r => r.json());
    setText('#statTotal',    s.total);
    setText('#statCritical', s.critical + s.high);
    setText('#statHigh',     s.high);
    setText('#statClean',    s.clean);
    const badge = qs('#alertBadge');
    if (s.unseen_alerts > 0) {
      badge.textContent = s.unseen_alerts;
      badge.classList.remove('hidden');
    } else {
      badge.classList.add('hidden');
    }
  } catch(e) {}
}

// ── Asset Detail Modal ────────────────────────────────────────────────────────
async function openAssetDetail(id) {
  const asset = allAssets.find(a => a.id === id);
  if (!asset) return;

  qs('#modalInner').innerHTML = `<div style="color:var(--text3);font-size:13px;padding:20px 0">Loading history…</div>`;
  qs('#modalBg').classList.remove('hidden');

  try {
    const [history, summaryRes] = await Promise.all([
      fetch(`${API}/api/aria/assets/${id}/history`).then(r => r.json()),
      fetch(`${API}/api/aria/assets/${id}/summary`).then(r => r.json()),
    ]);

    const level = asset.last_risk_level || 'Unknown';
    const findings = JSON.parse(history[0]?.key_findings || '[]');
    const recs     = JSON.parse(history[0]?.recommendations || '[]');
    const indics   = JSON.parse(history[0]?.threat_indicators || '[]');

    qs('#modalInner').innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:18px">
        <div>
          <div style="font-size:11px;color:var(--text3);font-family:var(--font-mono);margin-bottom:4px">${asset.type.toUpperCase()}</div>
          <div style="font-size:18px;font-weight:600;font-family:var(--font-head)">${esc(asset.name||asset.value)}</div>
          <div style="font-size:12px;color:var(--text3);font-family:var(--font-mono)">${esc(asset.value)}</div>
        </div>
        <div class="risk-pill ${level}" style="font-size:13px;padding:6px 14px">${level}</div>
      </div>

      <div style="background:var(--bg3);border-radius:var(--radius-sm);padding:14px;margin-bottom:16px;font-size:13px;color:var(--text2);line-height:1.7">
        ${esc(summaryRes.summary || 'No summary available.')}
      </div>

      ${findings.length ? `
        <div style="margin-bottom:16px">
          <div style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Key Findings</div>
          ${findings.map(f => `<div style="font-size:12px;color:var(--text2);padding:4px 0;border-bottom:1px solid var(--border)">• ${esc(f)}</div>`).join('')}
        </div>` : ''}

      ${recs.length ? `
        <div style="margin-bottom:16px">
          <div style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Recommendations</div>
          ${recs.map(r => `<div style="font-size:12px;color:var(--green);padding:4px 0">→ ${esc(r)}</div>`).join('')}
        </div>` : ''}

      ${indics.length ? `
        <div style="margin-bottom:16px">
          <div style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Threat Indicators</div>
          <div style="display:flex;flex-wrap:wrap;gap:6px">
          ${indics.map(i => `<span style="background:var(--red-bg);color:var(--red);border-radius:99px;padding:2px 10px;font-size:11px">${esc(i)}</span>`).join('')}
          </div>
        </div>` : ''}

      <div>
        <div style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px">Scan History (last 30)</div>
        <table style="width:100%;border-collapse:collapse;font-size:12px">
          <thead>
            <tr style="color:var(--text3)">
              <th style="text-align:left;padding:6px 8px;border-bottom:1px solid var(--border)">Risk</th>
              <th style="text-align:left;padding:6px 8px;border-bottom:1px solid var(--border)">Score</th>
              <th style="text-align:left;padding:6px 8px;border-bottom:1px solid var(--border)">When</th>
            </tr>
          </thead>
          <tbody>
            ${history.map(h => `
              <tr>
                <td style="padding:7px 8px;border-bottom:1px solid var(--border);color:${riskColor(h.risk_level)}">${h.risk_level||'—'}</td>
                <td style="padding:7px 8px;border-bottom:1px solid var(--border);color:var(--text2);font-family:var(--font-mono)">${h.risk_score??'—'}</td>
                <td style="padding:7px 8px;border-bottom:1px solid var(--border);color:var(--text3);font-family:var(--font-mono)">${timeAgo(h.scanned_at)}</td>
              </tr>`).join('') || '<tr><td colspan="3" style="padding:12px 8px;color:var(--text3)">No history yet</td></tr>'}
          </tbody>
        </table>
      </div>`;
  } catch(e) {
    qs('#modalInner').innerHTML = `<div style="color:var(--red)">Failed to load details.</div>`;
  }
}

function closeModal() { qs('#modalBg').classList.add('hidden'); }

// ── Chat ──────────────────────────────────────────────────────────────────────
async function sendChat() {
  const inp = qs('#chatInput');
  const text = inp.value.trim();
  if (!text) return;

  inp.value = '';
  inp.style.height = 'auto';
  appendMsg('user', text);
  chatHistory.push({ role: 'user', content: text });

  const thinkId = appendThinking();
  qs('#btnSend').disabled = true;

  try {
    const res = await fetch(`${API}/api/aria/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ messages: chatHistory }),
    });
    const data = await res.json();
    const reply = data.reply || 'No response.';
    removeThinking(thinkId);
    appendMsg('ai', reply);
    chatHistory.push({ role: 'assistant', content: reply });
  } catch(e) {
    removeThinking(thinkId);
    appendMsg('ai', '⚠️ Connection error. Check that the backend is running.');
  } finally {
    qs('#btnSend').disabled = false;
    inp.focus();
  }
}

function sendQuick(text) {
  qs('#chatInput').value = text;
  sendChat();
}

function chatKeydown(e) {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendChat(); }
}

function appendMsg(role, content) {
  const wrap = qs('#chatMessages');
  const div  = document.createElement('div');
  div.className = `msg ${role}`;
  const avatar = role === 'ai' ? 'A' : 'U';
  div.innerHTML = `
    <div class="msg-avatar">${avatar}</div>
    <div class="msg-bubble">${role==='ai' ? markdownToHtml(content) : `<p>${esc(content)}</p>`}</div>`;
  wrap.appendChild(div);
  wrap.scrollTop = wrap.scrollHeight;
  return div;
}

function appendThinking() {
  const wrap = qs('#chatMessages');
  const id   = 'thinking-' + Date.now();
  const div  = document.createElement('div');
  div.id = id;
  div.className = 'msg ai thinking';
  div.innerHTML = `<div class="msg-avatar">A</div><div class="msg-bubble"><div class="thinking-dots"><span></span><span></span><span></span></div></div>`;
  wrap.appendChild(div);
  wrap.scrollTop = wrap.scrollHeight;
  return id;
}

function removeThinking(id) {
  const el = document.getElementById(id);
  if (el) el.remove();
}

// ── Alerts ────────────────────────────────────────────────────────────────────
async function loadAlerts() {
  try {
    const alerts = await fetch(`${API}/api/aria/alerts`).then(r => r.json());
    renderAlerts(alerts);
  } catch(e) {}
}

function renderAlerts(alerts) {
  const el = qs('#alertsList');
  if (!alerts.length) {
    el.innerHTML = '<div class="dash-empty">No alerts yet. ARIA will notify you automatically when threats are detected.</div>';
    return;
  }
  el.innerHTML = alerts.map(a => {
    const icon = a.risk_level === 'Critical' ? '🔴' : a.risk_level === 'High' ? '🟠' : '🟡';
    return `
      <div class="alert-card ${a.seen ? 'seen' : ''}" id="alert-${a.id}">
        <div class="alert-icon">${icon}</div>
        <div class="alert-body">
          <div class="alert-title">${esc(a.title || 'Threat detected')}</div>
          <div class="alert-msg">${esc(a.message || '')}</div>
          <div class="alert-meta">
            <span class="alert-level-pill risk-pill ${a.risk_level}">${a.risk_level}</span>
            <span class="alert-time">${timeAgo(a.created_at)}</span>
          </div>
        </div>
        ${!a.seen ? `<button class="btn-seen" onclick="markSeen(${a.id})">Seen</button>` : ''}
      </div>`;
  }).join('');
}

async function markSeen(id) {
  await fetch(`${API}/api/aria/alerts/${id}/seen`, { method: 'POST' });
  await loadAlerts();
  loadStats();
}

async function markAllSeen() {
  await fetch(`${API}/api/aria/alerts/seen-all`, { method: 'POST' });
  await loadAlerts();
  loadStats();
}

// ── Reports ───────────────────────────────────────────────────────────────────
async function loadReports() {
  try {
    const reports = await fetch(`${API}/api/aria/reports`).then(r => r.json());
    renderReportsList(reports);
  } catch(e) {}
}

function renderReportsList(reports) {
  const el = qs('#reportsList');
  if (!reports.length) {
    el.innerHTML = '<div style="font-size:12px;color:var(--text3);padding:12px">No reports yet. Click "Generate now".</div>';
    return;
  }
  el.innerHTML = reports.map(r => `
    <div class="report-item ${currentReport === r.id ? 'active':''}" onclick="openReport(${r.id})">
      <div class="report-item-title">${esc(r.title)}</div>
      <div class="report-item-date">${timeAgo(r.generated_at)}</div>
    </div>`).join('');
}

async function openReport(id) {
  currentReport = id;
  qs('#reportContent').innerHTML = '<div style="color:var(--text3);font-size:13px">Loading…</div>';
  try {
    const r = await fetch(`${API}/api/aria/reports/${id}`).then(res => res.json());
    qs('#reportContent').innerHTML = `<div class="report-md">${markdownToHtml(r.content)}</div>`;
    await loadReports();
  } catch(e) {
    qs('#reportContent').innerHTML = '<div style="color:var(--red)">Failed to load report.</div>';
  }
}

async function generateReport() {
  const btn = qs('.btn-secondary');
  const spinner = qs('#reportSpinner');
  btn.disabled = true;
  spinner.classList.remove('hidden');
  spinner.classList.add('spinning');

  try {
    const res = await fetch(`${API}/api/aria/reports/generate`, { method: 'POST' });
    const data = await res.json();
    await loadReports();
    openReport(data.id);
  } catch(e) {
    alert('Report generation failed: ' + e.message);
  } finally {
    btn.disabled = false;
    spinner.classList.add('hidden');
    spinner.classList.remove('spinning');
  }
}

// ── Tab navigation ────────────────────────────────────────────────────────────
function switchTab(name, el) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  el.classList.add('active');
  qs(`#tab-${name}`).classList.add('active');
}

// ── Sidebar ───────────────────────────────────────────────────────────────────
function toggleSidebar() {
  sidebarOpen = !sidebarOpen;
  qs('#sidebar').classList.toggle('open', sidebarOpen);
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function qs(sel) { return document.querySelector(sel); }
function setText(sel, val) { const el = qs(sel); if (el) el.textContent = val; }
function esc(s) { if (!s) return ''; return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

function autoResize(el) {
  el.style.height = 'auto';
  el.style.height = Math.min(el.scrollHeight, 120) + 'px';
}

function riskColor(level) {
  return level === 'Critical' ? 'var(--red)'
       : level === 'High'     ? 'var(--amber)'
       : level === 'Medium'   ? 'var(--blue)'
       : level === 'Low'      ? 'var(--green)'
       : level === 'Clean'    ? 'var(--green)'
       : 'var(--text3)';
}

function timeAgo(iso) {
  if (!iso) return '—';
  const s = (Date.now() - new Date(iso.endsWith('Z') ? iso : iso + 'Z').getTime()) / 1000;
  if (s < 60)   return 'just now';
  if (s < 3600) return Math.floor(s/60) + 'm ago';
  if (s < 86400)return Math.floor(s/3600) + 'h ago';
  return Math.floor(s/86400) + 'd ago';
}

function flash(msg) { alert(msg); }

// Minimal markdown → HTML (headers, bold, italic, lists, code)
function markdownToHtml(md) {
  if (!md) return '';
  let html = esc(md);  // escape first, then selectively unescape for formatting
  html = md
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    // Headings
    .replace(/^### (.+)$/gm, '<h3>$1</h3>')
    .replace(/^## (.+)$/gm,  '<h2>$1</h2>')
    .replace(/^# (.+)$/gm,   '<h1>$1</h1>')
    // Bold, italic
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.+?)\*/g,     '<em>$1</em>')
    // Code blocks
    .replace(/```[\w]*\n?([\s\S]*?)```/g, '<pre>$1</pre>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    // HR
    .replace(/^---+$/gm, '<hr/>')
    // Bullet lists
    .replace(/^\- (.+)$/gm, '<li>$1</li>')
    .replace(/^• (.+)$/gm,  '<li>$1</li>')
    // Numbered lists
    .replace(/^\d+\. (.+)$/gm, '<li>$1</li>')
    // Wrap consecutive <li> in <ul>
    .replace(/(<li>[\s\S]*?<\/li>)(\s*(?!<li>))/g, (m, list) => `<ul>${list}</ul>`)
    // Paragraphs (double newlines)
    .split(/\n{2,}/)
    .map(block => {
      if (/^<(h[1-6]|ul|ol|pre|hr)/.test(block.trim())) return block;
      return `<p>${block.replace(/\n/g,' ')}</p>`;
    })
    .join('\n');
  return html;
}
