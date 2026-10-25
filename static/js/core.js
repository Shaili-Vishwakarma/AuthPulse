/* ============================================================
   AuthPulse – Core: shared state, API helpers, utilities, router
   ============================================================ */

export const PAGES = [
  'overview', 'message-lab', 'attack-simulator', 'protocol-visualizer',
  'logs', 'playground', 'how-it-works',
];

export const PAGE_TITLES = {
  'overview': 'Overview',
  'message-lab': 'Message Lab',
  'attack-simulator': 'Attack Simulator',
  'protocol-visualizer': 'Protocol Visualizer',
  'logs': 'Verification Logs',
  'playground': 'API Playground',
  'how-it-works': 'How It Works',
};

// --- Shared mutable state -------------------------------------------
export const state = {
  // Logs
  logsState: { page: 1, pageSize: 20, q: '', result: 'all', reason: 'all', sort: 'created_at', order: 'desc' },
  logsData: null,
  logsLiveTimer: null,
  logsExpandedRow: null,

  // Overview
  overviewLiveTimer: null,
  overviewLive: false,

  // Message Lab
  labSignedMsg: null,
  labOriginal: {},
  labCurrentResult: null,

  // Playground
  pgHistory: [],
};

// --- API helpers ----------------------------------------------------
export async function api(path, method, body) {
  const opts = { method: method || 'GET', headers: {} };
  if (body) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const resp = await fetch(path, opts);
  const ct = resp.headers.get('content-type') || '';
  if (!ct.includes('application/json')) {
    throw new Error('Server returned a non-JSON response (' + resp.status + '). Is the backend running?');
  }
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.error || data.detail || 'Request failed (' + resp.status + ')');
  return data;
}

// --- UI utilities ---------------------------------------------------
export function showToast(msg, type) {
  const c = document.getElementById('toast-container');
  const t = document.createElement('div');
  t.className = 'toast ' + (type || '');
  t.textContent = msg;
  c.appendChild(t);
  setTimeout(() => t.remove(), 3500);
}

export function icon(name) {
  return `<i data-lucide="${name}" aria-hidden="true"></i>`;
}

export function refreshIcons() {
  if (window.lucide) window.lucide.createIcons();
}

export function timeAgo(iso) {
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 0) return 'just now';
  if (diff < 60) return Math.floor(diff) + 's ago';
  if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
  if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
  return Math.floor(diff / 86400) + 'd ago';
}

export function reasonBadge(reason) {
  const map = {
    'ok': '<span class="badge badge-ok">OK</span>',
    'tamper': '<span class="badge badge-tamper">Tamper</span>',
    'expired': '<span class="badge badge-expired">Expired</span>',
    'replay': '<span class="badge badge-replay">Replay</span>',
  };
  return map[reason] || reason;
}

export function resultBadge(result) {
  return result === 'accepted'
    ? '<span class="badge badge-accepted">Accepted</span>'
    : '<span class="badge badge-rejected">Rejected</span>';
}

export function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

export function escapeAttr(str) {
  return String(str).replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

export function renderCheckItem(c) {
  return `<div class="trace-item ${c.status}">
    <div class="trace-icon">${c.status === 'pass' ? icon('check') : icon('x')}</div>
    <div class="trace-body">
      <div class="trace-label">${c.label}</div>
      <div class="trace-detail">${c.detail}</div>
      ${c.expected ? `<div class="trace-mono">Expected: ${c.expected}</div>` : ''}
      ${c.received ? `<div class="trace-mono">Received: ${c.received}</div>` : ''}
      ${c.nonce ? `<div class="trace-mono">Nonce: ${c.nonce}</div>` : ''}
      ${c.age_seconds !== undefined ? `<div class="trace-mono">Age: ${c.age_seconds}s · Window: ±${c.window_seconds}s</div>` : ''}
    </div>
  </div>`;
}

export function renderChecks(data) {
  return `<div class="trace-list">${data.checks.map(c => renderCheckItem(c)).join('')}</div>`;
}

export function renderSignedBlock(signed) {
  return `<div class="signed-block">
    <div class="sb-row-with-copy"><span class="sb-label">Payload</span><span class="sb-value">${escapeHtml(JSON.stringify(signed.payload))}</span><button class="copy-btn" data-copy="${escapeAttr(JSON.stringify(signed.payload))}">${icon('copy')}Copy</button></div>
    <div class="sb-row-with-copy"><span class="sb-label">Timestamp</span><span class="sb-value">${signed.timestamp}</span><button class="copy-btn" data-copy="${signed.timestamp}">${icon('copy')}Copy</button></div>
    <div class="sb-row-with-copy"><span class="sb-label">Nonce</span><span class="sb-value">${signed.nonce}</span><button class="copy-btn" data-copy="${signed.nonce}">${icon('copy')}Copy</button></div>
    <div class="sb-row-with-copy"><span class="sb-label">HMAC Tag</span><span class="sb-value">${signed.tag}</span><button class="copy-btn" data-copy="${signed.tag}">${icon('copy')}Copy</button></div>
    ${signed.signing_string ? `<div class="signing-string-preview"><span class="ss-label">Signing String</span>${escapeHtml(signed.signing_string)}</div>` : ''}
  </div>`;
}

export function renderPayloadDiff(original, tampered) {
  const allKeys = new Set([...Object.keys(original), ...Object.keys(tampered)]);
  let html = '<div style="margin-bottom:16px;padding:12px;border:1px solid var(--border);border-radius:var(--radius-md)"><div class="section-title" style="margin-bottom:8px">Payload Changes</div>';
  let hasDiff = false;
  for (const key of allKeys) {
    const oldVal = JSON.stringify(original[key]);
    const newVal = JSON.stringify(tampered[key]);
    if (oldVal !== newVal) {
      hasDiff = true;
      html += `<div class="diff-row">
        <span class="diff-key">"${key}":</span>
        <span class="diff-old">${escapeHtml(oldVal)}</span>
        ${icon('arrow-right')}
        <span class="diff-new">${escapeHtml(newVal)}</span>
      </div>`;
    }
  }
  if (!hasDiff) html += '<div style="font-size:13px;color:var(--text-tertiary);padding:8px 0">No changes detected.</div>';
  html += '</div>';
  return html;
}

export function advanceStepper(stepperId, fromStep, toStep) {
  const stepper = document.getElementById(stepperId);
  if (!stepper) return;
  const fromDot = stepper.querySelector(`[data-step="${fromStep}"]`);
  const toDot = stepper.querySelector(`[data-step="${toStep}"]`);
  if (fromDot) { fromDot.classList.remove('active'); fromDot.classList.add('done'); }
  const line = fromDot ? fromDot.nextElementSibling : null;
  if (line && line.classList.contains('step-line')) line.classList.add('done');
  if (toDot) toDot.classList.add('active');
  refreshIcons();
}

export function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
