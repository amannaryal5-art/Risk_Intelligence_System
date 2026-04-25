'use strict';

const scamInput = document.getElementById('scamInput');
const scamCheckBtn = document.getElementById('scamCheckBtn');
const resultCard = document.getElementById('shieldResult');
const verdictBadge = document.getElementById('shieldVerdictBadge');
const summaryEl = document.getElementById('shieldSummary');
const detailsTable = document.getElementById('shieldDetailsTable');
const jsonEl = document.getElementById('shieldJson');
const errorEl = document.getElementById('shieldError');
const toggleJsonBtn = document.getElementById('toggleJsonBtn');
const shareWarningBtn = document.getElementById('shareWarningBtn');
const checkAnotherBtn = document.getElementById('checkAnotherBtn');

let lastResult = null;

const patterns = {
  ip: /^(?:\d{1,3}\.){3}\d{1,3}$/,
  email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  phone: /^(?:\+91[-\s]?)?[6-9]\d{9}$/,
  upi: /^[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}$/,
};

function detectType(value) {
  const input = String(value || '').trim();
  if (/^https?:\/\//i.test(input)) return 'url';
  if (patterns.ip.test(input)) return 'ip';
  if (patterns.email.test(input)) return 'email';
  if (patterns.phone.test(input.replace(/\s+/g, ''))) return 'phone';
  if (patterns.upi.test(input)) return 'upi';
  return 'text';
}

function setButtonLoading(active) {
  if (!scamCheckBtn) return;
  scamCheckBtn.disabled = active;
  scamCheckBtn.classList.toggle('loading', active);
  const label = scamCheckBtn.querySelector('.btn-label');
  if (label) label.textContent = active ? 'Checking...' : 'Check Now';
}

function setError(message = '') {
  if (!errorEl) return;
  errorEl.textContent = message;
  errorEl.classList.toggle('hidden', !message);
}

function esc(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

async function runScamCheck() {
  const input = scamInput?.value?.trim() || '';
  if (!input) {
    setError('Paste something to check first.');
    return;
  }

  const detectedType = detectType(input);
  setError('');
  setButtonLoading(true);

  try {
    const response = await fetch('/api/v1/scamcheck', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ input, detectedType }),
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload?.detail || 'Unable to check this input right now.');
    lastResult = payload;
    renderResult(payload, detectedType);
  } catch (error) {
    setError(error.message || 'Something went wrong while checking that input.');
  } finally {
    setButtonLoading(false);
  }
}

function renderResult(result, detectedType) {
  if (!resultCard || !verdictBadge || !summaryEl || !detailsTable || !jsonEl) return;

  resultCard.classList.remove('hidden');
  const verdict = String(result.verdict || 'SAFE').toLowerCase();
  verdictBadge.textContent = String(result.verdict || 'SAFE').toUpperCase();
  verdictBadge.className = `shield-verdict ${verdict}`;
  summaryEl.textContent = result.summary || 'No summary available.';

  const details = result.details || {};
  const rows = [
    ['Detected as', detectedType],
    ['What was found', details.whatWasFound || result.input || '-'],
    ['Where it is hosted', details.isp || details.hostedOn || details.country || '-'],
    ['Domain age', details.domainAge || '-'],
    ['VirusTotal detections', details.vtDetections ?? 0],
    ['AbuseIPDB score', details.abuseConfidence ?? 0],
    ['OTX pulse count', details.otxPulses ?? 0],
    ['Country', details.country || '-'],
    ['ISP', details.isp || '-'],
    ['Checked at', result.scannedAt || '-'],
  ];
  detailsTable.innerHTML = rows.map(([label, value]) => `
    <tr>
      <th>${esc(label)}</th>
      <td>${esc(value)}</td>
    </tr>
  `).join('');

  jsonEl.textContent = JSON.stringify(result.rawResults || {}, null, 2);
}

function copyWarning() {
  if (!lastResult) return;
  const message = `ScamShield India warning\nVerdict: ${lastResult.verdict}\nSummary: ${lastResult.summary}\nChecked input: ${lastResult.input}`;
  navigator.clipboard.writeText(message).then(() => {
    shareWarningBtn.textContent = 'Copied';
    window.setTimeout(() => { shareWarningBtn.textContent = 'Share Warning'; }, 1600);
  });
}

function toggleJson() {
  if (!jsonEl) return;
  jsonEl.classList.toggle('hidden');
  toggleJsonBtn.textContent = jsonEl.classList.contains('hidden') ? 'Full Technical Report' : 'Hide Technical Report';
}

function resetForm() {
  if (scamInput) scamInput.value = '';
  resultCard?.classList.add('hidden');
  jsonEl?.classList.add('hidden');
  setError('');
  toggleJsonBtn.textContent = 'Full Technical Report';
  lastResult = null;
  scamInput?.focus();
}

scamCheckBtn?.addEventListener('click', runScamCheck);
shareWarningBtn?.addEventListener('click', copyWarning);
toggleJsonBtn?.addEventListener('click', toggleJson);
checkAnotherBtn?.addEventListener('click', resetForm);
scamInput?.addEventListener('keydown', (event) => {
  if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') runScamCheck();
});
