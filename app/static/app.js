'use strict';

let lastAnalysis = null;
let lastWebTrace = null;
let lastFusion = null;
let currentMode = 'text';
let currentCase = null;
let activeResultTab = 'overview';
let feedsSocket = null;
let feedsPollTimer = null;

const STORAGE_KEY = 'crie_recent_v3';
const FEED_RESULTS_KEY = 'crie_feed_results_v1';
const TIMEOUTS = {
  default: 28000,
  website: 240000,
  fusion: 240000,
  file: 20000,
  ioc: 12000,
};

const FEED_META = {
  alienvault_otx: {
    key: 'alienvault_otx',
    slug: 'otx',
    icon: '◉',
    accent: '#f97316',
    title: 'AlienVault OTX',
    description: 'Open threat intelligence community. Detects malicious IPs, domains, file hashes, and URLs via 20M+ IOCs.',
    capabilities: ['IP reputation', 'Domain lookup', 'Hash analysis', 'Bulk queries'],
    quotaLabel: 'Free tier',
  },
  abuseipdb: {
    key: 'abuseipdb',
    slug: 'abuseipdb',
    icon: '◆',
    accent: '#ef4444',
    title: 'AbuseIPDB',
    description: 'IP address abuse reporting. Checks IPs against a database of reported malicious activity.',
    capabilities: ['IP reputation', 'Reporter trends', 'Confidence scoring', 'Enrichment'],
    quotaLabel: 'Free tier',
  },
  virustotal: {
    key: 'virustotal',
    slug: 'virustotal',
    icon: '▣',
    accent: '#3b82f6',
    title: 'VirusTotal',
    description: 'Multi-engine malware scanner. Aggregates 70+ antivirus engines and URL scanners.',
    capabilities: ['Hash analysis', 'URL scan', 'Domain intel', 'Multi-engine verdict'],
    quotaLabel: 'Free tier',
  },
  shodan: {
    key: 'shodan',
    slug: 'shodan',
    icon: '⬡',
    accent: '#8b5cf6',
    title: 'Shodan',
    description: 'Internet exposure search. Identifies open services, banners, and exposed hosts.',
    capabilities: ['Banner intel', 'Port exposure', 'Host lookup', 'Asset profiling'],
    quotaLabel: 'Premium',
  },
  urlscan: {
    key: 'urlscan',
    slug: 'urlscan',
    icon: '◌',
    accent: '#06b6d4',
    title: 'URLScan.io',
    description: 'URL detonation and page capture. Records loaded resources, redirects, and visual snapshots.',
    capabilities: ['URL detonation', 'Resource graph', 'Redirect trace', 'Page screenshot'],
    quotaLabel: 'Free tier',
  },
};

const DEFAULT_FEED_ORDER = ['alienvault_otx', 'abuseipdb', 'virustotal'];
const resultTabMap = {
  Overview: 'overview',
  'Links & Domains': 'links',
  'IOC Intel': 'ioc',
  Recommendations: 'recommendations',
};

document.querySelectorAll('.nav-link').forEach((link) => {
  link.addEventListener('click', (event) => {
    if (!link.dataset.tab) return;
    event.preventDefault();
    activateTab(link.dataset.tab);
  });
});

document.querySelectorAll('.detail-tab').forEach((tab) => {
  tab.addEventListener('click', () => {
    switchResultTab(resultTabMap[tab.textContent.trim()] || 'overview');
  });
});

const textInput = document.getElementById('textInput');
if (textInput) {
  textInput.addEventListener('input', () => {
    document.getElementById('charCount').textContent = textInput.value.length.toLocaleString();
    detectQuickIocs(textInput.value);
  });
}

document.getElementById('clearInputBtn')?.addEventListener('click', clearAll);

document.getElementById('flagsToggle')?.addEventListener('click', () => {
  const body = document.getElementById('flagsBody');
  const chevron = document.getElementById('flagsChevron');
  if (!body || !chevron) return;
  const collapsed = body.classList.toggle('hidden');
  chevron.textContent = collapsed ? '+' : '-';
});

const fileDrop = document.getElementById('fileDrop');
const fileInput = document.getElementById('fileInput');
if (fileDrop && fileInput) {
  fileDrop.addEventListener('dragover', (event) => {
    event.preventDefault();
    fileDrop.style.borderColor = 'var(--accent)';
  });
  fileDrop.addEventListener('dragleave', () => {
    fileDrop.style.borderColor = '';
  });
  fileDrop.addEventListener('drop', (event) => {
    event.preventDefault();
    fileDrop.style.borderColor = '';
    if (event.dataTransfer.files[0]) {
      fileInput.files = event.dataTransfer.files;
      showFileInfo(event.dataTransfer.files[0]);
    }
  });
  fileInput.addEventListener('change', () => {
    if (fileInput.files[0]) showFileInfo(fileInput.files[0]);
  });
}

function activateTab(tab) {
  document.querySelectorAll('.nav-link').forEach((item) => item.classList.toggle('active', item.dataset.tab === tab));
  document.querySelectorAll('.tab-content').forEach((item) => item.classList.toggle('active', item.id === `tab-${tab}`));
  if (tab === 'feeds') refreshFeeds(false);
  if (tab === 'cases') loadCases();
}

function setMode(mode) {
  currentMode = mode;
  document.getElementById('modeText')?.classList.toggle('active', mode === 'text');
  document.getElementById('modeWeb')?.classList.toggle('active', mode === 'website');
  document.getElementById('modeFile')?.classList.toggle('active', mode === 'file');
  document.getElementById('textSection')?.classList.toggle('hidden', mode !== 'text');
  document.getElementById('webSection')?.classList.toggle('hidden', mode !== 'website');
  document.getElementById('fileSection')?.classList.toggle('hidden', mode !== 'file');
}
window.setMode = setMode;

function switchResultTab(name) {
  activeResultTab = name;
  document.querySelectorAll('.detail-tab').forEach((tab) => {
    tab.classList.toggle('active', (resultTabMap[tab.textContent.trim()] || 'overview') === name);
  });
  document.querySelectorAll('.result-panel').forEach((panel) => panel.classList.toggle('active', panel.id === `panel-${name}`));
}
window.switchResultTab = switchResultTab;

function detectQuickIocs(text) {
  const panel = document.getElementById('quickExtract');
  const list = document.getElementById('quickIocList');
  if (!panel || !list) return;
  if (!text.trim()) {
    panel.classList.add('hidden');
    list.innerHTML = '';
    return;
  }
  const items = [];
  const urlPat = /(?:https?:\/\/|www\.)[^\s<>'"()]+/gi;
  const ipPat = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
  const hashPat = /\b[a-fA-F0-9]{32,64}\b/g;
  (text.match(urlPat) || []).slice(0, 3).forEach((value) => items.push({ label: 'URL', value }));
  (text.match(ipPat) || []).slice(0, 3).forEach((value) => items.push({ label: 'IP', value }));
  (text.match(hashPat) || []).slice(0, 2).forEach((value) => items.push({ label: 'HASH', value: `${value.slice(0, 18)}...` }));
  panel.classList.toggle('hidden', !items.length);
  list.innerHTML = items.map((item) => `<span class="quick-ioc-chip">${esc(item.label)} ${esc(item.value)}</span>`).join('');
}

function showFileInfo(file) {
  document.getElementById('fileInfo')?.classList.remove('hidden');
  document.getElementById('fileName').textContent = file.name;
  document.getElementById('fileSize').textContent = formatBytes(file.size);
}

async function checkHealth() {
  const dot = document.getElementById('systemDot');
  const status = document.getElementById('systemStatus');
  const badge = document.getElementById('latencyBadge');
  try {
    const start = performance.now();
    const data = await fetchJson('/api/v1/health', {}, 6000);
    const latency = Math.round(performance.now() - start);
    if (dot) dot.className = 'status-dot ok';
    if (status) status.textContent = 'Online';
    if (badge) badge.textContent = `${latency} ms`;
    document.getElementById('footerUser').textContent = `AUTH:${data.auth_enforced ? 'ON' : 'OFF'} · FEEDS:${data.live_feeds_default ? 'LIVE' : 'HEURISTIC'}`;
  } catch {
    if (dot) dot.className = 'status-dot error';
    if (status) status.textContent = 'Offline';
    if (badge) badge.textContent = '-- ms';
  }
}

async function fetchJson(url, options = {}, timeoutMs = TIMEOUTS.default) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    console.log('[DEBUG] Response status:', response.status, 'for', url);
    const contentType = (response.headers.get('content-type') || '').toLowerCase();
    const payload = contentType.includes('application/json') ? await response.json() : { detail: await response.text() };
    if (!response.ok) {
      const detail = typeof payload?.detail === 'string' ? payload.detail : JSON.stringify(payload?.detail || payload);
      throw new Error(detail || `HTTP ${response.status}`);
    }
    return payload;
  } catch (error) {
    if (error?.name === 'AbortError') throw new Error(`Timed out after ${Math.round(timeoutMs / 1000)}s`);
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

function post(url, body, timeout) {
  return fetchJson(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }, timeout);
}

function riskColor(level) {
  return { low: 'var(--green)', medium: 'var(--amber)', high: 'var(--red)', critical: 'var(--red)' }[String(level || '').toLowerCase()] || 'var(--text-primary)';
}

function setLoading(el, msg = 'Loading...') {
  if (typeof el === 'string') el = document.getElementById(el);
  if (el) el.innerHTML = `<div class="loading">${esc(msg)}</div>`;
}

function setEmpty(el, msg = 'No data') {
  if (typeof el === 'string') el = document.getElementById(el);
  if (el) el.innerHTML = `<div class="empty-inline">${esc(msg)}</div>`;
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}

function showResults() {
  document.getElementById('emptyState')?.classList.add('hidden');
  document.getElementById('resultsContent')?.classList.remove('hidden');
}

function setScoreBars(breakdown = {}) {
  const pairs = [
    ['rule', breakdown.rule],
    ['nlp', breakdown.nlp],
    ['intel', breakdown.intel],
    ['fusion', breakdown.fusion],
  ];
  pairs.forEach(([name, raw]) => {
    const pctValue = `${Math.round((raw || 0) * 100)}%`;
    const label = document.getElementById(`${name}Pct`);
    const bar = document.getElementById(`${name}Bar`);
    if (label) label.textContent = pctValue;
    if (bar) bar.style.width = pctValue;
  });
}

function renderScore(score, level, confidence, verdict, breakdown) {
  showResults();
  const value = document.getElementById('scoreValue');
  const badge = document.getElementById('riskBadge');
  const verdictEl = document.getElementById('plainVerdict');
  const confEl = document.getElementById('confidenceValue');
  const basis = document.getElementById('scoreBasis');
  const riskCard = document.getElementById('riskCard');
  const normalized = String(level || 'low').toLowerCase();
  const gradients = {
    low: 'linear-gradient(135deg, #051510, #0a1f1a)',
    medium: 'linear-gradient(135deg, #150f00, #1f1800)',
    high: 'linear-gradient(135deg, #150500, #1f0a00)',
    critical: 'linear-gradient(135deg, #1a0000, #250000)',
  };
  if (riskCard) {
    riskCard.style.background = gradients[normalized] || 'var(--panel-gradient)';
    riskCard.style.borderLeftColor = riskColor(normalized);
    riskCard.style.animation = normalized === 'critical' ? 'critical-pulse 1.8s infinite' : 'none';
  }
  if (value) {
    value.textContent = score ?? 0;
    value.style.color = riskColor(normalized);
  }
  if (badge) {
    badge.textContent = normalized.toUpperCase();
    badge.style.color = riskColor(normalized);
    badge.style.border = `1px solid ${resolveRiskTint(normalized)}`;
    badge.style.background = resolveRiskBg(normalized);
  }
  if (verdictEl) verdictEl.textContent = verdict || 'Awaiting analysis.';
  if (confEl) confEl.textContent = `Confidence: ${confidence ? `${confidence}%` : '--'}`;
  if (basis) {
    basis.textContent = breakdown
      ? `Rule ${pct(breakdown.rule)} · NLP ${pct(breakdown.nlp)} · Intel ${pct(breakdown.intel)} · Fusion ${pct(breakdown.fusion)}`
      : 'No scoring details yet.';
  }
  setScoreBars(breakdown);
}

function pct(value) {
  return `${Math.round((value || 0) * 100)}%`;
}

function resolveRiskBg(level) {
  return {
    low: 'rgba(16, 185, 129, 0.08)',
    medium: 'rgba(245, 158, 11, 0.08)',
    high: 'rgba(239, 68, 68, 0.08)',
    critical: 'rgba(239, 68, 68, 0.12)',
  }[level] || 'rgba(100, 116, 139, 0.08)';
}

function resolveRiskTint(level) {
  return {
    low: 'rgba(16, 185, 129, 0.3)',
    medium: 'rgba(245, 158, 11, 0.3)',
    high: 'rgba(239, 68, 68, 0.3)',
    critical: 'rgba(239, 68, 68, 0.35)',
  }[level] || 'rgba(100, 116, 139, 0.25)';
}

function buildFlagItems(signals = [], topFlags = [], dimensions = {}) {
  const strongestCategory = Object.entries(dimensions || {}).sort((a, b) => (b[1] || 0) - (a[1] || 0))[0]?.[0] || '';
  const mapped = (topFlags || []).map((flag, index) => ({
    title: flag,
    detail: flag,
    category: inferFlagCategory(flag, strongestCategory),
    weight: Math.max(0.3, 1 - index * 0.12),
  }));
  const extra = (signals || []).slice(0, 5).map((signal) => ({
    title: signal.name || 'Signal',
    detail: signal.detail || 'Observed anomaly',
    category: inferFlagCategory(`${signal.name} ${signal.detail}`, strongestCategory),
    weight: Math.min(1, Math.max(0.24, (signal.score || 0.12) * 3.5)),
  }));
  return [...mapped, ...extra].slice(0, 6);
}

function inferFlagCategory(text, strongestCategory = '') {
  const value = String(text || '').toLowerCase();
  if (value.includes('link') || value.includes('url') || value.includes('domain')) return 'LINK';
  if (value.includes('password') || value.includes('login') || value.includes('auth')) return 'AUTH';
  if (value.includes('gift') || value.includes('money') || value.includes('urgent') || value.includes('invoice')) return 'SCAM';
  if (value.includes('social') || value.includes('love') || value.includes('friend') || value.includes('trust')) return 'SOCIAL';
  if (strongestCategory.includes('social')) return 'SOCIAL';
  if (strongestCategory.includes('credential')) return 'AUTH';
  if (strongestCategory.includes('link')) return 'LINK';
  return 'SCAM';
}

function flagPalette(category) {
  if (category === 'LINK') return { color: 'var(--cyan)', bg: 'rgba(6, 182, 212, 0.12)' };
  if (category === 'AUTH') return { color: 'var(--purple)', bg: 'rgba(139, 92, 246, 0.12)' };
  if (category === 'SOCIAL') return { color: 'var(--red)', bg: 'rgba(239, 68, 68, 0.12)' };
  return { color: 'var(--amber)', bg: 'rgba(245, 158, 11, 0.12)' };
}

function renderSignals(signals, topFlags, dimensions) {
  const detailEl = document.getElementById('signals');
  const flagEl = document.getElementById('topFlags');
  const mergedFlags = buildFlagItems(signals, topFlags, dimensions);

  if (!mergedFlags.length) {
    setEmpty(flagEl, 'No major risk indicators surfaced in the current result set.');
  } else {
    flagEl.innerHTML = mergedFlags.map((flag) => {
      const palette = flagPalette(flag.category);
      return `
        <div class="flag-item">
          <div class="flag-category" style="color:${palette.color};background:${palette.bg};border:1px solid ${palette.bg};">${esc(flag.category)}</div>
          <div class="flag-main">
            <div class="flag-title">${esc(flag.title)}</div>
            <div class="sig-detail">${esc(flag.detail)}</div>
          </div>
          <div class="flag-weight">
            <div class="flag-weight-bar"><span style="width:${Math.round(flag.weight * 100)}%;background:${palette.color};"></span></div>
          </div>
        </div>`;
    }).join('');
  }

  if (!signals?.length) {
    setEmpty(detailEl, 'Signal telemetry will populate here after a successful scan.');
  } else {
    detailEl.innerHTML = signals.slice(0, 8).map((signal) => `
      <div class="signal-card">
        <div class="sig-name">${esc(signal.name || 'Signal')}</div>
        <div class="sig-detail">${esc(signal.detail || 'No detail provided')}</div>
      </div>`).join('');
  }
}

function renderLinks(linkAnalysis) {
  const summary = document.getElementById('linkSummaryRow');
  const list = document.getElementById('linkTraces');
  if (!linkAnalysis?.total_links) {
    summary.innerHTML = '';
    setEmpty(list, 'No URLs were extracted from the current payload.');
    return;
  }
  summary.innerHTML = [
    ['Total links', linkAnalysis.total_links],
    ['High risk', linkAnalysis.high_risk_links],
    ['Medium risk', linkAnalysis.medium_risk_links],
    ['Aggregate score', (linkAnalysis.aggregate_score || 0).toFixed(2)],
  ].map(([label, value]) => `<div class="stat-card"><div class="panel-heading">${esc(label)}</div><div>${esc(value)}</div></div>`).join('');
  list.innerHTML = (linkAnalysis.links || []).slice(0, 12).map((link) => `
    <div class="link-card">
      <div class="link-host">${esc(link.host || link.raw || 'Unknown link')}</div>
      <div class="sig-detail">${esc(link.raw || '')}</div>
      <div class="flag-meta">
        <span class="badge ${esc((link.verdict || 'low').toLowerCase())}">${esc((link.verdict || 'unknown').toUpperCase())}</span>
        <span class="meta-pill">Score ${Math.round((link.score || 0) * 100)}</span>
        ${link.ip ? `<span class="meta-pill">${esc(link.ip)}</span>` : ''}
      </div>
      <div class="flag-meta">${(link.flags || []).slice(0, 4).map((flag) => `<span class="flag-chip">${esc(flag)}</span>`).join('')}</div>
    </div>`).join('');
}

function renderIoc(iocIntel) {
  const meta = document.getElementById('iocMetaRow');
  const list = document.getElementById('iocResults');
  if (!iocIntel?.ioc_count) {
    meta.innerHTML = '';
    setEmpty(list, 'IOC enrichment results will appear here when indicators are detected.');
    return;
  }
  const breakdown = Object.entries(iocIntel.ioc_type_breakdown || {}).map(([key, value]) => `<span class="meta-pill">${esc(key)}:${esc(value)}</span>`).join('');
  meta.innerHTML = `
    <span class="meta-pill">overall:${esc(iocIntel.overall_risk || 'minimal')}</span>
    <span class="meta-pill">max:${esc(iocIntel.max_ioc_score || 0)}</span>
    <span class="meta-pill">live:${iocIntel.live_feeds ? 'yes' : 'no'}</span>
    ${breakdown}`;
  list.innerHTML = (iocIntel.results || []).slice(0, 12).map((ioc) => `
    <div class="ioc-card">
      <div>
        <div class="ioc-value">${esc(ioc.value)}</div>
        <div class="flag-meta">
          <span class="ioc-type-badge">${esc(ioc.ioc_type || 'ioc')}</span>
          <span class="meta-pill">score ${esc(ioc.reputation_score || 0)}/100</span>
        </div>
        <div class="flag-meta">${(ioc.flags || []).slice(0, 4).map((flag) => `<span class="flag-chip">${esc(flag)}</span>`).join('')}</div>
      </div>
      <div class="badge ${esc((ioc.reputation || 'low').toLowerCase())}">${esc((ioc.reputation || 'unknown').toUpperCase())}</div>
    </div>`).join('');
}

function renderDomain(analysis) {
  const grid = document.getElementById('domainDetails');
  const di = analysis?.domain_intelligence;
  if (!di) {
    setEmpty(grid, 'No domain intelligence was produced for this scan.');
    return;
  }
  const link = analysis?.link_analysis?.links?.[0] || {};
  const rep = link.domain_intelligence?.domain_reputation || {};
  const whois = link.domain_intelligence?.whois_age || {};
  const typo = link.domain_intelligence?.typosquatting || {};
  grid.innerHTML = `
    <div class="domain-card"><div class="sig-name">Brand impersonation</div><div class="sig-detail">${esc((di.brand_impersonation?.brands || []).join(', ') || 'No brand impersonation detected')}</div></div>
    <div class="domain-card"><div class="sig-name">Domain reputation</div><div class="sig-detail">${esc(rep.category || 'unknown')}</div></div>
    <div class="domain-card"><div class="sig-name">Typosquatting</div><div class="sig-detail">${esc(typo.closest_brand || 'No close brand match')}</div></div>
    <div class="domain-card"><div class="sig-name">WHOIS age</div><div class="sig-detail">${esc(whois.age_days ?? 'Unknown')} days</div></div>`;
}

function renderEntities(entities) {
  const grid = document.getElementById('entityGrid');
  const groups = [
    ['emails', 'Emails'],
    ['phones', 'Phones'],
    ['ipv4s', 'IPs'],
    ['crypto_wallets', 'Wallets'],
    ['numeric_ids', 'IDs'],
    ['domains', 'Domains'],
  ];
  if (!entities) {
    setEmpty(grid, 'Extracted entities will be shown after a successful parse.');
    return;
  }
  grid.innerHTML = groups.map(([key, label]) => `
    <div class="entity-card">
      <div class="entity-card-title">${esc(label)}</div>
      <div class="sig-detail">${(entities[key] || []).slice(0, 4).map(esc).join(', ') || '<span style="color:var(--text-secondary)">None found</span>'}</div>
    </div>`).join('');
}

function renderIntent(intentProfile) {
  const panel = document.getElementById('intentPanel');
  if (!intentProfile?.top_intents?.length) {
    setEmpty(panel, 'Intent scoring will render here when language patterns are recognized.');
    return;
  }
  panel.innerHTML = intentProfile.top_intents.slice(0, 4).map((item) => {
    const percent = Math.round((item.similarity || 0) > 1 ? item.similarity : (item.similarity || 0) * 100);
    return `
      <div class="intent-card">
        <div class="sig-name mono">${esc(item.intent || 'unknown')}</div>
        <div class="intent-progress">
          <div class="intent-bar"><span style="width:${percent}%;"></span></div>
          <div class="mono">${percent}%</div>
        </div>
      </div>`;
  }).join('');
}

function renderCrawl(trace) {
  const stats = document.getElementById('crawlStatsRow');
  const list = document.getElementById('crawlPages');
  if (!trace?.pages_crawled) {
    stats.innerHTML = '';
    setEmpty(list, 'Website crawl telemetry will appear here for URL-based scans.');
    return;
  }
  stats.innerHTML = [
    ['Verdict', trace.site_verdict || 'unknown'],
    ['Pages', trace.pages_crawled || 0],
    ['Scam risk', `${trace.scam_likelihood || 0}%`],
    ['Malware risk', `${trace.malware_likelihood || 0}%`],
  ].map(([label, value]) => `<div class="stat-card"><div class="panel-heading">${esc(label)}</div><div>${esc(value)}</div></div>`).join('');
  list.innerHTML = (trace.top_risky_pages || []).slice(0, 8).map((page) => `
    <div class="crawl-card">
      <div class="crawl-title">${esc(page.title || '(No title)')}</div>
      <div class="sig-detail">${esc(page.url || '')}</div>
      <div class="flag-meta">
        <span class="badge ${esc((page.risk_level || 'low').toLowerCase())}">${esc((page.risk_level || 'low').toUpperCase())}</span>
        <span class="meta-pill">risk ${esc(page.score || 0)}/100</span>
      </div>
    </div>`).join('');
}

function renderCerts(certs) {
  const list = document.getElementById('certList');
  if (!certs?.length) {
    setEmpty(list, 'Certificate intelligence will appear for HTTPS hosts.');
    return;
  }
  list.innerHTML = certs.slice(0, 8).map((cert) => `
    <div class="cert-card">
      <div class="cert-host">${esc(cert.host || 'Unknown host')}</div>
      <div class="sig-detail">Issuer: ${esc(cert.issuer || 'Unknown')}</div>
      <div class="sig-detail">Valid to: ${esc(cert.valid_to || 'Unknown')}</div>
    </div>`).join('');
}

function renderPlaybook(recommendations) {
  const el = document.getElementById('recommendations');
  if (!recommendations?.length) {
    setEmpty(el, 'Recommended response actions will populate once scoring is complete.');
    return;
  }
  el.innerHTML = recommendations.slice(0, 8).map((item, index) => `
    <div class="playbook-item">
      <div class="sig-name">Action ${index + 1}</div>
      <div class="playbook-text">${esc(item)}</div>
    </div>`).join('');
}

function saveRecentScan(item) {
  const previous = JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]');
  localStorage.setItem(STORAGE_KEY, JSON.stringify([item, ...previous].slice(0, 5)));
  renderRecentScans();
}

function readFeedResults() {
  try {
    return JSON.parse(localStorage.getItem(FEED_RESULTS_KEY) || '{}');
  } catch {
    return {};
  }
}

function writeFeedResults(results) {
  localStorage.setItem(FEED_RESULTS_KEY, JSON.stringify(results));
}

function setFeedResult(feed, result) {
  const current = readFeedResults();
  current[feed] = result;
  writeFeedResults(current);
}

function getFeedResult(feed) {
  return readFeedResults()[feed] || null;
}

function renderRecentScans() {
  const el = document.getElementById('recentScans');
  if (!el) return;
  const items = JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]');
  if (!items.length) {
    setEmpty(el, 'Recent analyst activity will appear here after the first scan.');
    return;
  }
  el.innerHTML = items.map((item, index) => `
    <div class="recent-item" onclick="restoreRecent(${index})">
      <div class="badge ${esc((item.risk_level || 'low').toLowerCase())}">${esc((item.risk_level || 'low').toUpperCase())}</div>
      <div class="recent-preview">${esc(item.preview || '')}</div>
      <div class="recent-time">${esc(item.at || '')}</div>
    </div>`).join('');
}

window.restoreRecent = function restoreRecent(index) {
  const items = JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]');
  const item = items[index];
  if (!item) return;
  setMode(item.mode || 'text');
  if (item.mode === 'website') {
    document.getElementById('websiteInput').value = item.text || '';
  } else {
    document.getElementById('textInput').value = item.text || '';
    document.getElementById('charCount').textContent = String(item.text || '').length.toLocaleString();
    detectQuickIocs(item.text || '');
  }
};

function applyAnalysis(data, sourceText = '') {
  lastAnalysis = data;
  renderScore(data.score, data.risk_level, data.confidence, data.plain_verdict, data.score_breakdown);
  renderSignals(data.signals, data.top_flags, data.dimensions);
  renderLinks(data.link_analysis);
  renderIoc(data.ioc_intelligence || null);
  renderDomain(data);
  renderEntities(data.entities);
  renderIntent(data.intent_profile);
  renderPlaybook(data.recommendations);
  switchResultTab(activeResultTab);
  saveRecentScan({
    score: data.score,
    risk_level: data.risk_level,
    preview: sourceText.slice(0, 100),
    text: sourceText.slice(0, 300),
    at: new Date().toLocaleTimeString(),
    mode: currentMode,
  });
  updateFeedCardsFromAnalysis(data, sourceText);
}

function applyWebsiteAnalysis(data, sourceText = '') {
  lastAnalysis = data;
  const level = data.verdict === 'DANGER' ? 'critical' : data.verdict === 'CAUTION' ? 'medium' : 'low';
  const recommendations = [
    data.verdict === 'DANGER' ? 'Do not visit this website.' : data.verdict === 'CAUTION' ? 'Proceed with caution and verify independently.' : 'Safe to visit with normal caution.',
    data.domain ? `Domain: ${data.domain}` : 'No domain extracted.',
    data.ip ? `Resolved IP: ${data.ip}` : 'IP resolution was unavailable.',
  ];
  renderScore(data.riskScore || 0, level, null, data.summary || 'Website analysis complete.', {
    rule: Math.min(1, (data.riskScore || 0) / 100),
    nlp: 0,
    intel: Math.min(1, (data.riskScore || 0) / 100),
    fusion: 0,
  });
  renderSignals([], [
    `Domain: ${data.domain || 'unknown'}`,
    `IP: ${data.ip || 'unresolved'}`,
    `Abuse confidence: ${data.feeds?.abuseipdb?.abuseConfidence ?? 0}`,
    `VirusTotal detections: ${data.feeds?.virustotal?.malicious ?? 0}`,
    `OTX pulses: ${data.feeds?.otx?.pulseCount ?? 0}`,
  ], {});
  renderLinks({
    total_links: 1,
    high_risk_links: data.verdict === 'DANGER' ? 1 : 0,
    medium_risk_links: data.verdict === 'CAUTION' ? 1 : 0,
    aggregate_score: (data.riskScore || 0) / 100,
    links: [{
      host: data.domain || sourceText,
      raw: data.input || sourceText,
      verdict: level,
      score: (data.riskScore || 0) / 100,
      ip: data.ip || '',
      flags: [
        `country ${data.feeds?.abuseipdb?.country || 'unknown'}`,
        `isp ${data.feeds?.abuseipdb?.isp || 'unknown'}`,
      ],
    }],
  });
  renderIoc({
    ioc_count: 2,
    overall_risk: level,
    max_ioc_score: data.riskScore || 0,
    live_feeds: true,
    ioc_type_breakdown: { domain: data.domain ? 1 : 0, ip: data.ip ? 1 : 0 },
    results: [
      {
        ioc_type: 'domain',
        value: data.domain || sourceText,
        reputation_score: data.riskScore || 0,
        reputation: level,
        flags: [`OTX ${data.feeds?.otx?.pulseCount ?? 0}`, `VT ${data.feeds?.virustotal?.malicious ?? 0}`],
      },
      {
        ioc_type: 'ip',
        value: data.ip || 'unresolved',
        reputation_score: data.feeds?.abuseipdb?.abuseConfidence ?? 0,
        reputation: (data.feeds?.abuseipdb?.abuseConfidence ?? 0) > 50 ? 'malicious' : 'clean',
        flags: [`Abuse ${data.feeds?.abuseipdb?.abuseConfidence ?? 0}`, `Country ${data.feeds?.abuseipdb?.country || 'unknown'}`],
      },
    ].filter((item) => item.value && item.value !== 'unresolved'),
  });
  renderPlaybook(recommendations);
  switchResultTab('ioc');
  showResults();
  saveRecentScan({
    score: data.riskScore || 0,
    risk_level: level,
    preview: sourceText.slice(0, 100),
    text: sourceText.slice(0, 300),
    at: new Date().toLocaleTimeString(),
    mode: 'website',
  });
  updateFeedCardsFromAnalysis(data, sourceText);
}

async function analyze() {
  const btn = document.getElementById('analyzeBtn');
  const websiteInput = document.getElementById('websiteInput')?.value?.trim() || '';
  const textValue = document.getElementById('textInput')?.value?.trim() || '';
  console.log('[DEBUG] Analyze clicked');
  console.log('[DEBUG] Input value:', currentMode === 'website' ? websiteInput : textValue);
  console.log('[DEBUG] Tab:', currentMode);
  setButtonLoading(btn, 'Analyzing...');
  setFeedsQueryingState(true);
  try {
    if (currentMode === 'website') {
      const websiteUrl = normalizeUrl(document.getElementById('websiteInput')?.value || '');
      if (!websiteUrl) {
        showToast('Enter a website URL first', 'warning');
        return;
      }
      await runWebsiteIntel(websiteUrl, true);
      return;
    }
    if (currentMode === 'file') {
      const value = document.getElementById('fileHashInput')?.value?.trim();
      if (value && /^[a-fA-F0-9]{32,64}$/.test(value)) {
        const data = await post('/api/v1/analyze', { text: value });
        applyAnalysis(data, value);
        switchResultTab('ioc');
        return;
      }
      await analyzeFile();
      return;
    }
    const text = document.getElementById('textInput')?.value?.trim();
    if (!text) {
      showToast('Enter text to scan', 'warning');
      return;
    }
    if (looksLikeUrl(text)) {
      document.getElementById('websiteInput').value = normalizeUrl(text);
      await runWebsiteIntel(normalizeUrl(text), true);
      return;
    }
    const data = await post('/api/v1/analyze', { text });
    applyAnalysis(data, text);
    switchResultTab('overview');
  } catch (error) {
    renderScore(0, 'low', 0, `Analysis failed: ${error.message}`, null);
    showToast(`Analysis failed: ${error.message}`, 'error');
  } finally {
    resetButton(btn, 'Analyze');
    setFeedsQueryingState(false);
  }
}
window.analyze = analyze;

async function fusionScan(fromAnalyze = false) {
  const text = document.getElementById('textInput')?.value?.trim() || null;
  const url = normalizeUrl(document.getElementById('websiteInput')?.value || '');
  if (!text && !url) {
    showToast('Enter text or URL to analyze', 'warning');
    return;
  }
  const btn = document.getElementById('analyzeBtn');
  if (!fromAnalyze) setButtonLoading(btn, 'Analyzing...');
  setFeedsQueryingState(true);
  try {
    console.log('[RiskIntel] fusionScan request', { text, url, currentMode });
    const data = await post('/api/v1/fusion-scan', {
      text: text || null,
      website_url: url || null,
      max_pages: 40,
      max_depth: 3,
      include_external: false,
      exhaustive: true,
    }, TIMEOUTS.fusion);
    console.log('[RiskIntel] fusionScan response', data);
    lastFusion = data;
    if (data.text_analysis) applyAnalysis(data.text_analysis, text || url);
    if (data.website_intelligence) applyWebsiteAnalysis(data.website_intelligence, url);
    if (data.website_trace) {
      lastWebTrace = data.website_trace;
      renderCrawl(data.website_trace);
      renderCerts(data.website_trace.certificates);
      if (!data.website_intelligence && !data.text_analysis) {
        showResults();
        switchResultTab('links');
      }
    }
  } catch (error) {
    renderScore(0, 'low', 0, `Analysis failed: ${error.message}`, null);
    showToast(`Fusion scan failed: ${error.message}`, 'error');
  } finally {
    if (!fromAnalyze) resetButton(btn, 'Analyze');
    setFeedsQueryingState(false);
  }
}
window.fusionScan = fusionScan;

async function runWebsiteIntel(url, fromAnalyze = false) {
  const btn = document.getElementById('analyzeBtn');
  if (!fromAnalyze) setButtonLoading(btn, 'Analyzing...');
  setFeedsQueryingState(true);
  try {
    const endpoint = '/api/v1/website-intel';
    const payload = { url };
    console.log('[DEBUG] Making API call to:', endpoint);
    console.log('[DEBUG] Payload:', payload);
    const data = await post(endpoint, payload, TIMEOUTS.ioc);
    console.log('[DEBUG] Response data:', data);
    applyWebsiteAnalysis(data, url);
    console.log('[DEBUG] Result state set');
    switchResultTab('ioc');
  } catch (error) {
    console.error('[DEBUG] Error:', error);
    renderScore(0, 'low', 0, `Website analysis failed: ${error.message}`, null);
    showToast(`Website analysis failed: ${error.message}`, 'error');
  } finally {
    if (!fromAnalyze) resetButton(btn, 'Analyze');
    setFeedsQueryingState(false);
  }
}

async function traceWebsite() {
  return fusionScan();
}
window.traceWebsite = traceWebsite;

async function analyzeFile() {
  const fi = document.getElementById('fileInput');
  if (!fi?.files?.[0]) {
    showToast('Select a file first', 'warning');
    return;
  }
  const btn = document.getElementById('analyzeBtn');
  setButtonLoading(btn, 'Analyzing...');
  setFeedsQueryingState(true);
  try {
    const file = fi.files[0];
    const bytes = new Uint8Array(await file.arrayBuffer());
    let binary = '';
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
    }
    const data = await post('/api/v1/malware/analyze-file', {
      filename: file.name,
      content_base64: btoa(binary),
    }, TIMEOUTS.file);
    renderScore(data.risk_score, data.risk_level, null, `File: ${file.name}`, null);
    renderSignals([], data.suspicious_signals || [], {});
    renderIoc(data.ioc_intelligence || null);
    renderPlaybook(data.risk_level === 'critical' || data.risk_level === 'high'
      ? ['Isolate the file immediately.', 'Block the hash in endpoint tooling.', 'Review execution history and related hosts.']
      : ['No immediate high-risk evidence.', 'Run an endpoint scan.', 'Continue monitoring behavior.']);
    switchResultTab('recommendations');
    updateFeedCardsFromAnalysis(data, file.name);
  } catch (error) {
    renderScore(0, 'low', 0, `File analysis failed: ${error.message}`, null);
    showToast(`File analysis failed: ${error.message}`, 'error');
  } finally {
    resetButton(btn, 'Analyze');
    setFeedsQueryingState(false);
  }
}
window.analyzeFile = analyzeFile;

function batchMode() {
  document.getElementById('batchModal')?.classList.remove('hidden');
}
window.batchMode = batchMode;

function closeBatch() {
  document.getElementById('batchModal')?.classList.add('hidden');
}
window.closeBatch = closeBatch;

async function runBatch() {
  const raw = document.getElementById('batchInput')?.value || '';
  const texts = raw.split('\n').map((line) => line.trim()).filter(Boolean).slice(0, 100);
  const results = document.getElementById('batchResults');
  if (!texts.length) {
    showToast('Provide at least one line for batch analysis', 'warning');
    return;
  }
  setLoading(results, 'Running batch analysis...');
  try {
    const data = await post('/api/v1/analyze/batch', { texts });
    results.innerHTML = (data.results || []).map((item, index) => `
      <div class="batch-row">
        <div class="sig-name">Item ${index + 1}</div>
        <div class="sig-detail">${esc(texts[index].slice(0, 140))}</div>
        <div class="flag-meta">
          <span class="badge ${esc((item.risk_level || 'low').toLowerCase())}">${esc((item.risk_level || 'low').toUpperCase())}</span>
          <span class="meta-pill">score ${esc(item.score || 0)}</span>
        </div>
      </div>`).join('');
  } catch (error) {
    results.innerHTML = `<div class="empty-inline">Batch analysis failed: ${esc(error.message)}</div>`;
  }
}
window.runBatch = runBatch;

async function quickIocLookup() {
  const type = document.getElementById('iocType')?.value;
  const value = document.getElementById('iocValue')?.value?.trim();
  const live = document.getElementById('iocLive')?.checked || false;
  const result = document.getElementById('iocLookupResult');
  if (!type || !value) {
    showToast('Enter an indicator value first', 'warning');
    return;
  }
  setLoading(result, 'Looking up indicator...');
  try {
    const data = await fetchJson(`/api/v1/ioc/${type}/${encodeURIComponent(value)}?live=${live}`, {}, TIMEOUTS.ioc);
    const top = data.results?.[0];
    if (!top) {
      setEmpty(result, 'No intelligence was returned for this indicator.');
      return;
    }
    result.innerHTML = `
      <div class="lookup-card">
        <div class="sig-name">${esc(top.value || value)}</div>
        <div class="flag-meta">
          <span class="badge ${esc((top.reputation || 'low').toLowerCase())}">${esc((top.reputation || 'unknown').toUpperCase())}</span>
          <span class="meta-pill">score ${esc(top.reputation_score || 0)}/100</span>
          <span class="meta-pill">feed hits ${esc(top.listed_in || 0)}</span>
        </div>
        <div class="flag-meta">${(top.flags || []).slice(0, 4).map((flag) => `<span class="flag-chip">${esc(flag)}</span>`).join('')}</div>
      </div>`;
  } catch (error) {
    result.innerHTML = `<div class="empty-inline">Lookup failed: ${esc(error.message)}</div>`;
  }
}
window.quickIocLookup = quickIocLookup;

function getVisibleFeedProviders(feeds = []) {
  return feeds.filter((provider) => DEFAULT_FEED_ORDER.includes(String(provider.name || '').toLowerCase()));
}

function summaryChip(label, value, icon) {
  return `<div class="feed-summary-chip"><span>${icon}</span><span>${esc(label)}</span><strong>${esc(value)}</strong></div>`;
}

function latencyTone(ms) {
  if (typeof ms !== 'number') return 'bad';
  if (ms < 500) return 'ok';
  if (ms <= 2000) return 'warn';
  return 'bad';
}

function renderFeedSummary(summary = {}) {
  const bar = document.getElementById('feedSummaryBar');
  if (!bar) return;
  bar.innerHTML = [
    summaryChip('Configured', `${summary.configured || 0}/${summary.total || 0}`, '⌁'),
    summaryChip('Reachable', `${summary.reachable || 0}/${summary.total || 0}`, '↔'),
    summaryChip('Auth-valid', `${summary.auth_valid || 0}/${summary.total || 0}`, '✓'),
  ].join('');
}

function buildFeedTerminal(provider, meta) {
  const stored = getFeedResult(meta.slug || provider.name);
  if (stored?.response) {
    return stored.response;
  }
  const statusText = provider.reachable ? 'Response: reachable' : provider.configured ? 'Response: unavailable' : 'Response: not configured';
  const score = provider.auth_valid ? 'Threat score: 0/100' : provider.configured ? 'Threat score: auth required' : 'Threat score: standby';
  return `> Querying 8.8.8.8...\n> ${statusText}\n> ${score}`;
}

function renderFeedCard(provider) {
  const key = String(provider.name || '').toLowerCase();
  const meta = FEED_META[key] || FEED_META[provider.name] || { title: provider.display_name || provider.name || 'Feed', description: 'Threat feed', icon: '•', capabilities: [] };
  const statusTone = provider.reachable ? 'ok' : provider.configured ? 'bad' : 'warn';
  const liveText = provider.reachable ? 'LIVE' : provider.configured ? 'UNREACHABLE' : 'STANDBY';
  const httpCode = provider.http_status || provider.status_code || '000';
  const latency = typeof provider.latency_ms === 'number' ? `${provider.latency_ms}ms` : 'n/a';
  const latencyClass = latencyTone(provider.latency_ms);
  const quota = provider.configured ? 80 : 100;
  const terminalText = provider.__terminalText || buildFeedTerminal(provider, meta);
  const glow = provider.reachable && provider.auth_valid ? 'glow' : '';
  const querying = provider.__querying ? 'querying' : '';
  const unreachable = provider.configured && provider.reachable === false ? 'unreachable' : '';
  return `
    <article class="feed-card feed-${esc(meta.slug || key)} ${glow} ${querying} ${unreachable}" data-feed="${esc(key)}">
      <div class="feed-header">
        <div class="feed-title-row">
          <div class="feed-logo" style="color:${esc(meta.accent || '#3b82f6')}">${esc(meta.icon || '•')}</div>
          <div>
            <div class="feed-name">${esc(meta.title || provider.display_name || provider.name || 'Feed')}</div>
            <div class="feed-description">${esc(meta.description || '')}</div>
          </div>
        </div>
        <div class="feed-status-line">
          <span class="pulse-dot ${statusTone === 'ok' ? 'green' : statusTone === 'warn' ? 'amber' : 'red'}"></span>
          <span class="feed-status-text ${statusTone === 'ok' ? 'ok' : statusTone === 'warn' ? 'warn' : 'bad'}">${esc(liveText)}</span>
          <span class="feed-chip ${provider.auth_valid ? 'ok' : 'bad'}">HTTP ${esc(httpCode)}</span>
          <span class="feed-chip ${latencyClass}">${esc(latency)}</span>
        </div>
      </div>
      <div class="feed-section">
        <div class="panel-heading">Last query result</div>
        <div class="terminal-shell">
          <div class="terminal-output">${esc(terminalText)}</div>
        </div>
      </div>
      <div class="feed-section">
        <div class="panel-heading">Capabilities</div>
        <div class="feed-capabilities">${(meta.capabilities || []).map((cap) => `<span class="feed-capability">✓ ${esc(cap)}</span>`).join('')}</div>
      </div>
      <div class="feed-section">
        <div class="panel-heading">API quota</div>
        <div class="quota-row">
          <div class="quota-bar"><span style="width:${quota}%;background:linear-gradient(90deg, ${esc(meta.accent || '#3b82f6')}, rgba(255,255,255,0.12));"></span></div>
          <div>${quota}%</div>
        </div>
        <div class="quota-note">${esc(meta.quotaLabel || 'Free tier')}</div>
      </div>
    </article>`;
}

function renderFeedGrid(feeds = []) {
  const grid = document.getElementById('feedGrid');
  if (!grid) return;
  const visibleProviders = getVisibleFeedProviders(feeds);
  if (!visibleProviders.length) {
    setEmpty(grid, 'Threat feeds are standing by. Configure keys to populate live telemetry.');
    return;
  }
  grid.innerHTML = visibleProviders.map(renderFeedCard).join('');
}

function updateFeedCardsFromAnalysis(payload, sourceText = '') {
  const inputSample = sourceText || payload?.input || payload?.plain_verdict || payload?.filename || 'payload';
  const riskScore = payload?.riskScore || payload?.score || payload?.risk_score || payload?.max_ioc_score || 0;
  const feedSnapshots = {
    otx: {
      input: inputSample,
      threatScore: riskScore,
      timestamp: new Date().toISOString(),
      response: `> Querying ${inputSample.slice(0, 36)}...\n> OTX pulses: ${payload?.feeds?.otx?.pulseCount ?? payload?.rawResults?.otx?.pulse_count ?? 0}\n> Threat score: ${riskScore}/100`,
    },
    abuseipdb: {
      input: inputSample,
      threatScore: riskScore,
      timestamp: new Date().toISOString(),
      response: `> Querying ${inputSample.slice(0, 36)}...\n> Abuse confidence: ${payload?.feeds?.abuseipdb?.abuseConfidence ?? payload?.details?.abuseConfidence ?? 0}\n> Threat score: ${riskScore}/100`,
    },
    virustotal: {
      input: inputSample,
      threatScore: riskScore,
      timestamp: new Date().toISOString(),
      response: `> Querying ${inputSample.slice(0, 36)}...\n> VT malicious: ${payload?.feeds?.virustotal?.malicious ?? payload?.details?.vtDetections ?? 0}\n> Threat score: ${riskScore}/100`,
    },
  };
  Object.entries(feedSnapshots).forEach(([feed, snapshot]) => setFeedResult(feed, snapshot));

  if (!document.getElementById('feedGrid')) return;
  const feedCards = document.querySelectorAll('.feed-card');
  if (!feedCards.length) return;
  feedCards.forEach((card) => {
    const key = String(card.dataset.feed || '').toLowerCase();
    const terminal = card.querySelector('.terminal-output');
    if (!terminal) return;
    const feedKey = key === 'alienvault_otx' ? 'otx' : key;
    const snapshot = getFeedResult(feedKey);
    if (!snapshot) return;
    terminal.textContent = snapshot.response;
    card.classList.remove('querying');
    void card.offsetWidth;
    card.classList.add('querying');
    setTimeout(() => card.classList.remove('querying'), 900);
  });
}

function setFeedsQueryingState(active) {
  const grid = document.getElementById('feedGrid');
  if (!grid) return;
  const cards = grid.querySelectorAll('.feed-card');
  cards.forEach((card) => {
    const terminal = card.querySelector('.terminal-output');
    const dot = card.querySelector('.pulse-dot');
    const statusText = card.querySelector('.feed-status-text');
    card.classList.toggle('querying', active);
    if (active && terminal) {
      terminal.textContent = '> Querying indicator...\n> Waiting for upstream telemetry...\n> Correlating reputation feeds...';
    }
    if (active && dot) {
      dot.className = 'pulse-dot amber';
    }
    if (active && statusText) {
      statusText.textContent = 'SCANNING';
      statusText.className = 'feed-status-text warn';
    }
  });
}

async function refreshFeeds(probe = false) {
  const grid = document.getElementById('feedGrid');
  const checked = document.getElementById('feedLastChecked');
  const liveState = document.getElementById('feedLiveState');
  if (grid) grid.innerHTML = `<div class="loading">${probe ? 'Probing all feeds...' : 'Loading feed telemetry...'}</div>`;
  try {
    const data = await fetchJson(probe ? '/api/v1/feeds/probe' : '/api/v1/feeds/status/live', {}, probe ? 30000 : 10000);
    if (checked) checked.textContent = `Last checked: ${new Date().toLocaleTimeString()}${probe ? ' (active probe)' : ' (snapshot)'}`;
    if (liveState) liveState.textContent = feedsSocket && feedsSocket.readyState === WebSocket.OPEN ? 'Live websocket transport connected' : 'Polling every 30 seconds';
    renderFeedSummary(data.summary || {});
    renderFeedGrid(data.feeds || []);
  } catch (error) {
    if (grid) grid.innerHTML = `<div class="empty-inline">Unable to load feed telemetry: ${esc(error.message)}</div>`;
  }
}
window.refreshFeeds = refreshFeeds;

function connectFeedsLive() {
  const liveState = document.getElementById('feedLiveState');
  if (!liveState) return;
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  try {
    feedsSocket = new WebSocket(`${protocol}//${window.location.host}/api/v1/ws/feeds/status`);
  } catch {
    liveState.textContent = 'Polling every 30 seconds';
    feedsPollTimer = setInterval(() => refreshFeeds(false), 30000);
    return;
  }
  feedsSocket.onopen = () => {
    liveState.textContent = 'Live websocket transport connected';
  };
  feedsSocket.onmessage = (event) => {
    try {
      const payload = JSON.parse(event.data);
      if (payload.type !== 'feed_status' || !payload.data) return;
      if (liveState) liveState.textContent = 'Live websocket transport connected';
      document.getElementById('feedLastChecked').textContent = `Last checked: ${new Date(payload.timestamp || Date.now()).toLocaleTimeString()} (live)`;
      renderFeedSummary(payload.data.summary || {});
      renderFeedGrid(payload.data.feeds || []);
    } catch {
      // noop
    }
  };
  feedsSocket.onclose = () => {
    liveState.textContent = 'Polling every 30 seconds';
    if (feedsPollTimer) clearInterval(feedsPollTimer);
    feedsPollTimer = setInterval(() => refreshFeeds(false), 30000);
  };
}

async function loadCases() {
  const el = document.getElementById('caseList');
  const stat = document.getElementById('caseFilterStatus')?.value || '';
  const sev = document.getElementById('caseFilterSeverity')?.value || '';
  const search = document.getElementById('caseSearch')?.value?.trim() || '';
  setLoading(el, 'Loading case queue...');
  try {
    let url = '/api/v1/cases?limit=50';
    if (stat) url += `&status=${stat}`;
    if (sev) url += `&severity=${sev}`;
    if (search) url += `&search=${encodeURIComponent(search)}`;
    const data = await fetchJson(url, {}, 10000);
    const rows = data.results || [];
    if (!rows.length) {
      el.innerHTML = '<div class="empty-inline">No matching cases in the current queue.</div>';
      return;
    }
    el.innerHTML = rows.map((c) => `
      <div class="case-card ${esc((c.severity || 'low').toLowerCase())}" onclick="openCase(${c.id})">
        <div class="case-main">
          <div class="case-id">#${esc(c.id)}</div>
          <div class="case-title">${esc(c.title || 'Untitled')}</div>
          <div class="case-meta">
            <span>${esc(c.created_at || c.updated_at || 'Now')}</span>
            <span>${esc(c.assigned_to || 'Unassigned')}</span>
            <span>${esc(c.ioc_value || c.source_value || 'No IOC')}</span>
          </div>
        </div>
        <div class="case-actions">
          <div class="case-status-row">
            <span class="badge ${esc((c.severity || 'low').toLowerCase())}">${esc((c.severity || 'low').toUpperCase())}</span>
            <span class="badge ${esc((c.status || 'new').toLowerCase())}">${esc((c.status || 'new').toUpperCase())}</span>
          </div>
          <div class="flag-meta">
            <button class="btn-outline compact" onclick="event.stopPropagation(); updateCaseStatus(${c.id}, 'triaged')">Triage</button>
            <button class="btn-outline compact" onclick="event.stopPropagation(); openCase(${c.id})">View</button>
            <button class="btn-outline compact" onclick="event.stopPropagation(); deleteCase(${c.id})">Delete</button>
          </div>
        </div>
      </div>`).join('');
  } catch (error) {
    el.innerHTML = `<div class="empty-inline">Failed to load case queue: ${esc(error.message)}</div>`;
  }
}
window.loadCases = loadCases;

async function openCase(id) {
  const detail = document.getElementById('caseDetail');
  const list = document.getElementById('caseList');
  detail?.classList.remove('hidden');
  if (list) list.style.display = 'none';
  currentCase = id;
  try {
    const data = await fetchJson(`/api/v1/cases/${id}`, {}, 8000);
    document.getElementById('caseDetailTitle').textContent = data.title || `Case #${id}`;
    document.getElementById('caseDetailMeta').innerHTML = `
      <div class="case-meta-item"><div class="panel-heading">Severity</div><div>${esc((data.severity || '?').toUpperCase())}</div></div>
      <div class="case-meta-item"><div class="panel-heading">Status</div><div>${esc((data.status || '?').toUpperCase())}</div></div>
      <div class="case-meta-item"><div class="panel-heading">Reporter</div><div>${esc(data.reporter || '?')}</div></div>
      <div class="case-meta-item"><div class="panel-heading">Assigned</div><div>${esc(data.assigned_to || 'Unassigned')}</div></div>`;
    const comments = data.comments || [];
    document.getElementById('caseComments').innerHTML = comments.length ? comments.map((comment) => `
      <div class="comment-card">
        <div class="sig-name">${esc(comment.author || '?')}</div>
        <div class="comment-text">${esc(comment.message || '')}</div>
        <div class="comment-time">${esc(comment.created_at || '')}</div>
      </div>`).join('') : '<div class="empty-inline">No analyst comments have been posted yet.</div>';
  } catch (error) {
    document.getElementById('caseDetailTitle').textContent = `Error: ${error.message}`;
  }
}
window.openCase = openCase;

function closeCaseDetail() {
  document.getElementById('caseDetail')?.classList.add('hidden');
  document.getElementById('caseList').style.display = '';
  currentCase = null;
}
window.closeCaseDetail = closeCaseDetail;

async function addComment() {
  if (!currentCase) return;
  const message = document.getElementById('commentInput')?.value?.trim();
  if (!message) {
    showToast('Write a comment before posting', 'warning');
    return;
  }
  try {
    await post(`/api/v1/cases/${currentCase}/comments`, { message });
    document.getElementById('commentInput').value = '';
    openCase(currentCase);
  } catch (error) {
    showToast(`Failed to add comment: ${error.message}`, 'error');
  }
}
window.addComment = addComment;

function showCreateCase() {
  document.getElementById('createCaseModal')?.classList.remove('hidden');
}
window.showCreateCase = showCreateCase;

function hideCreateCase() {
  document.getElementById('createCaseModal')?.classList.add('hidden');
}
window.hideCreateCase = hideCreateCase;

async function createCase() {
  const title = document.getElementById('caseTitle')?.value?.trim();
  const severity = document.getElementById('caseSeverity')?.value || 'medium';
  const assigned = document.getElementById('caseAssignee')?.value?.trim() || null;
  const tags = (document.getElementById('caseTags')?.value || '').split(',').map((item) => item.trim()).filter(Boolean);
  if (!title) {
    showToast('Title required', 'warning');
    return;
  }
  try {
    await post('/api/v1/cases', { title, severity, assigned_to: assigned, tags, findings: {}, recommendations: [], status: 'new', source_type: 'manual' });
    hideCreateCase();
    showToast('Case created', 'success');
    loadCases();
  } catch (error) {
    showToast(`Failed to create case: ${error.message}`, 'error');
  }
}
window.createCase = createCase;

async function updateCaseStatus(id, status) {
  try {
    await fetchJson(`/api/v1/cases/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status }),
    }, 10000);
    showToast('Case updated', 'success');
    loadCases();
  } catch (error) {
    showToast(`Failed to update case: ${error.message}`, 'error');
  }
}
window.updateCaseStatus = updateCaseStatus;

async function deleteCase(id) {
  try {
    await fetchJson(`/api/v1/cases/${id}`, { method: 'DELETE' }, 10000);
    showToast('Case deleted', 'success');
    loadCases();
  } catch (error) {
    showToast(`Failed to delete case: ${error.message}`, 'error');
  }
}
window.deleteCase = deleteCase;

function saveToCase() {
  const payload = lastAnalysis || lastFusion?.text_analysis || lastWebTrace;
  if (!payload) {
    showToast('No analysis available to save', 'warning');
    return;
  }
  const inputValue = currentMode === 'website'
    ? (document.getElementById('websiteInput')?.value?.trim() || '')
    : (document.getElementById('fileHashInput')?.value?.trim() || document.getElementById('textInput')?.value?.trim() || '');
  const tags = (payload.top_flags || []).slice(0, 5).map((flag) => String(flag).split(' ')[0].toLowerCase());
  post('/api/v1/cases', {
    title: `Scan: ${inputValue.slice(0, 60) || (payload.risk_level || 'risk').toUpperCase()}`,
    source_type: currentMode,
    source_value: inputValue,
    severity: payload.risk_level === 'critical' ? 'critical' : payload.risk_level === 'high' ? 'high' : payload.risk_level === 'medium' ? 'medium' : 'low',
    status: 'new',
    findings: payload,
    recommendations: payload.recommendations || [],
    ioc_type: currentMode,
    ioc_value: inputValue,
    risk_score: payload.score || payload.risk_score || 0,
    scan_result: payload,
    tags,
  }).then(() => {
    showToast('Case saved successfully', 'success');
    activateTab('cases');
    loadCases();
  }).catch((error) => {
    showToast(`Failed to save case: ${error.message}`, 'error');
  });
}
window.saveToCase = saveToCase;

function buildTextSummary(payload) {
  if (payload?.site_verdict) {
    return `Website verdict: ${payload.site_verdict}\nScam risk: ${payload.scam_likelihood}%\nMalware risk: ${payload.malware_likelihood}%\nPages crawled: ${payload.pages_crawled}`;
  }
  return `Risk score: ${payload?.score ?? 0}/100 (${payload?.risk_level || 'low'})\nConfidence: ${payload?.confidence ?? '--'}%\n${payload?.plain_verdict || ''}`;
}

function copyReport() {
  const payload = lastFusion?.text_analysis || lastAnalysis || lastWebTrace;
  if (!payload) {
    showToast('No report available to copy', 'warning');
    return;
  }
  const summary = buildTextSummary(payload);
  navigator.clipboard?.writeText(summary).then(() => {
    showToast('Summary copied', 'success');
  }).catch(() => {
    const textarea = document.createElement('textarea');
    textarea.value = summary;
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    textarea.remove();
    showToast('Summary copied', 'success');
  });
}
window.copyReport = copyReport;

function downloadReport() {
  const payload = lastFusion || lastAnalysis || lastWebTrace;
  if (!payload) {
    showToast('No report available to download', 'warning');
    return;
  }
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = Object.assign(document.createElement('a'), { href: url, download: `crie-report-${Date.now()}.json` });
  anchor.click();
  URL.revokeObjectURL(url);
}
window.downloadReport = downloadReport;

function esc(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function normalizeUrl(input) {
  const raw = String(input || '').trim();
  if (!raw) return '';
  if (/^https?:\/\//i.test(raw)) return raw;
  if (/^[a-z0-9.-]+\.[a-z]{2,}/i.test(raw)) return `https://${raw}`;
  return raw;
}

function looksLikeUrl(input) {
  const value = String(input || '').trim();
  return /^(https?:\/\/|www\.)/i.test(value) || /^[a-z0-9.-]+\.[a-z]{2,}(\/.*)?$/i.test(value);
}

function setButtonLoading(button, text) {
  if (!button) return;
  button.disabled = true;
  button.classList.add('loading');
  button.dataset.originalText = button.querySelector('.btn-label')?.textContent || button.textContent;
  const label = button.querySelector('.btn-label');
  if (label) {
    label.textContent = text;
  } else {
    button.textContent = text;
  }
}

function resetButton(button, fallback) {
  if (!button) return;
  button.disabled = false;
  button.classList.remove('loading');
  const label = button.querySelector('.btn-label');
  if (label) {
    label.textContent = button.dataset.originalText || fallback;
  } else {
    button.textContent = button.dataset.originalText || fallback;
  }
}

function clearAll() {
  const text = document.getElementById('textInput');
  const url = document.getElementById('websiteInput');
  const hash = document.getElementById('fileHashInput');
  if (text) text.value = '';
  if (url) url.value = '';
  if (hash) hash.value = '';
  document.getElementById('charCount').textContent = '0';
  document.getElementById('quickExtract')?.classList.add('hidden');
  document.getElementById('quickIocList').innerHTML = '';
}
window.clearAll = clearAll;

function showToast(message, type = 'success') {
  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = message;
  document.body.appendChild(toast);
  requestAnimationFrame(() => toast.classList.add('toast-show'));
  setTimeout(() => {
    toast.classList.remove('toast-show');
    setTimeout(() => toast.remove(), 280);
  }, 2800);
}

checkHealth();
setInterval(checkHealth, 30000);
renderRecentScans();
setMode('text');
switchResultTab('overview');
connectFeedsLive();
