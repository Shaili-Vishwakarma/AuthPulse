/* ============================================================
   AuthPulse – Frontend logic
   Single-page app with 6 interactive pages, all data from real backend.

   Overview:        live auto-refresh, clickable metric cards, quick test
   Message Lab:     sign → quick-tamper buttons → live diff → verify
   Attack Simulator: custom params (which field, how old) + step flow
   Verification Logs: live poll toggle, inline row expand, JSON export
   API Playground:  preset templates, query param builder, request history
   ============================================================ */

(function () {
  'use strict';

  // --- State ---------------------------------------------------------
  const PAGES = ['overview', 'message-lab', 'attack-simulator', 'logs', 'playground', 'how-it-works'];
  const PAGE_TITLES = {
    'overview': 'Overview',
    'message-lab': 'Message Lab',
    'attack-simulator': 'Attack Simulator',
    'logs': 'Verification Logs',
    'playground': 'API Playground',
    'how-it-works': 'How It Works',
  };

  let logsState = { page: 1, pageSize: 20, q: '', result: 'all', reason: 'all', sort: 'created_at', order: 'desc' };
  let logsData = null;
  let logsLiveTimer = null;
  let logsExpandedRow = null;

  let overviewLiveTimer = null;
  let overviewLive = false;

  // Message Lab state
  let labSignedMsg = null;
  let labOriginal = {};
  let labCurrentResult = null;

  // Playground state
  let pgHistory = [];

  // --- API helpers ---------------------------------------------------
  async function api(path, method, body) {
    const opts = { method: method || 'GET', headers: {} };
    if (body) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    const resp = await fetch(path, opts);
    // Guard against non-JSON responses (e.g. HTML error pages from server)
    const ct = resp.headers.get('content-type') || '';
    if (!ct.includes('application/json')) {
      throw new Error('Server returned a non-JSON response (' + resp.status + '). Is the backend running?');
    }
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || data.detail || 'Request failed (' + resp.status + ')');
    return data;
  }

  function showToast(msg, type) {
    const c = document.getElementById('toast-container');
    const t = document.createElement('div');
    t.className = 'toast ' + (type || '');
    t.textContent = msg;
    c.appendChild(t);
    setTimeout(() => t.remove(), 3500);
  }

  function icon(name) {
    return `<i data-lucide="${name}" aria-hidden="true"></i>`;
  }

  function refreshIcons() {
    if (window.lucide) window.lucide.createIcons();
  }

  function timeAgo(iso) {
    const diff = (Date.now() - new Date(iso).getTime()) / 1000;
    if (diff < 0) return 'just now';
    if (diff < 60) return Math.floor(diff) + 's ago';
    if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    return Math.floor(diff / 86400) + 'd ago';
  }

  function reasonBadge(reason) {
    const map = {
      'ok': '<span class="badge badge-ok">OK</span>',
      'tamper': '<span class="badge badge-tamper">Tamper</span>',
      'expired': '<span class="badge badge-expired">Expired</span>',
      'replay': '<span class="badge badge-replay">Replay</span>',
    };
    return map[reason] || reason;
  }

  function resultBadge(result) {
    return result === 'accepted'
      ? '<span class="badge badge-accepted">Accepted</span>'
      : '<span class="badge badge-rejected">Rejected</span>';
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  function escapeAttr(str) {
    return String(str).replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function renderCheckItem(c) {
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

  function renderChecks(data) {
    return `<div class="trace-list">${data.checks.map(c => renderCheckItem(c)).join('')}</div>`;
  }

  function renderSignedBlock(signed) {
    return `<div class="signed-block">
      <div class="sb-row-with-copy"><span class="sb-label">Payload</span><span class="sb-value">${escapeHtml(JSON.stringify(signed.payload))}</span><button class="copy-btn" data-copy="${escapeAttr(JSON.stringify(signed.payload))}">${icon('copy')}Copy</button></div>
      <div class="sb-row-with-copy"><span class="sb-label">Timestamp</span><span class="sb-value">${signed.timestamp}</span><button class="copy-btn" data-copy="${signed.timestamp}">${icon('copy')}Copy</button></div>
      <div class="sb-row-with-copy"><span class="sb-label">Nonce</span><span class="sb-value">${signed.nonce}</span><button class="copy-btn" data-copy="${signed.nonce}">${icon('copy')}Copy</button></div>
      <div class="sb-row-with-copy"><span class="sb-label">HMAC Tag</span><span class="sb-value">${signed.tag}</span><button class="copy-btn" data-copy="${signed.tag}">${icon('copy')}Copy</button></div>
      ${signed.signing_string ? `<div class="signing-string-preview"><span class="ss-label">Signing String</span>${escapeHtml(signed.signing_string)}</div>` : ''}
    </div>`;
  }

  function renderPayloadDiff(original, tampered) {
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

  function advanceStepper(stepperId, fromStep, toStep) {
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

  // Wire up copy buttons globally via event delegation
  document.addEventListener('click', function (e) {
    const btn = e.target.closest('.copy-btn');
    if (!btn) return;
    e.stopPropagation();
    const text = btn.dataset.copy;
    navigator.clipboard.writeText(text).then(() => {
      btn.classList.add('copied');
      btn.innerHTML = icon('check') + 'Copied';
      setTimeout(() => { btn.classList.remove('copied'); btn.innerHTML = icon('copy') + 'Copy'; }, 1500);
      refreshIcons();
    });
  });

  // --- Router ---------------------------------------------------------
  function navigate(page) {
    if (!PAGES.includes(page)) page = 'overview';
    // stop any timers from previous pages
    if (overviewLiveTimer) { clearInterval(overviewLiveTimer); overviewLiveTimer = null; overviewLive = false; }
    if (logsLiveTimer) { clearInterval(logsLiveTimer); logsLiveTimer = null; }

    document.querySelectorAll('.nav-item').forEach(el => {
      el.classList.toggle('active', el.dataset.page === page);
    });
    document.getElementById('page-title').textContent = PAGE_TITLES[page] || page;
    const content = document.getElementById('page-content');
    content.innerHTML = '';
    switch (page) {
      case 'overview': renderOverview(content); break;
      case 'message-lab': renderMessageLab(content); break;
      case 'attack-simulator': renderAttackSim(content); break;
      case 'logs': renderLogs(content); break;
      case 'playground': renderPlayground(content); break;
      case 'how-it-works': renderHowItWorks(content); break;
    }
    refreshIcons();
    closeSidebar();
    location.hash = page;
  }

  // --- Overview page (INTERACTIVE: live refresh, clickable cards, quick test) ---
  async function renderOverview(root) {
    root.innerHTML = `<div id="ov-loading" class="state-box"><div class="spinner"></div>Loading…</div>`;
    await loadOverviewData(root);
  }

  async function loadOverviewData(root) {
    try {
      const [stats, events] = await Promise.all([
        api('/api/stats'),
        api('/api/events?page=1&page_size=50&order=desc')
      ]);
      const items = events.items || [];

      const chartItems = items.slice(0, 10).reverse();
      const maxChecks = Math.max(...chartItems.map(e => e.checks.length), 1);
      let chartHtml = '';
      for (const e of chartItems) {
        const acc = e.checks.filter(c => c.status === 'pass').length;
        const rej = e.checks.filter(c => c.status === 'fail').length;
        const accH = (acc / maxChecks) * 150;
        const rejH = (rej / maxChecks) * 150;
        chartHtml += `<div class="bar-wrap" title="${e.result} — ${e.reason}">
            <div class="bar-stack" style="height:${accH + rejH}px">
              ${rej > 0 ? `<div class="bar-rejected" style="height:${rejH}px"></div>` : ''}
              ${acc > 0 ? `<div class="bar-accepted" style="height:${accH}px"></div>` : ''}
            </div>
            <div class="bar-label">${timeAgo(e.created_at)}</div>
          </div>`;
      }

      const total = stats.total || 0;
      const accPct = total ? (stats.accepted / total) * 100 : 0;
      const rejPct = total ? (stats.rejected / total) * 100 : 0;
      const accDash = accPct * 2.513;
      const rejDash = rejPct * 2.513;

      const recentHtml = items.slice(0, 6).map(e => `
        <tr>
          <td class="mono">${e.request_id.slice(0, 8)}</td>
          <td>${resultBadge(e.result)}</td>
          <td>${reasonBadge(e.reason)}</td>
          <td class="mono hide-mobile">${timeAgo(e.created_at)}</td>
        </tr>`).join('') || '<tr><td colspan="4" style="text-align:center;color:var(--text-tertiary);padding:24px">No events yet</td></tr>';

      root.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
          <span class="live-pulse" style="${overviewLive ? '' : 'display:none'}"><span class="pulse-dot"></span>Live</span>
          <button id="ov-live-toggle" class="live-toggle ${overviewLive ? 'active' : ''}">${icon('radio')} Auto-refresh (5s)</button>
        </div>
        <div class="metric-grid">
          <div class="metric-card primary clickable" data-filter="all">
            <div class="icon-wrap">${icon('shield')}</div>
            <div class="label">Total Verifications</div>
            <div class="value">${stats.total}</div><div class="sub">All-time — click to view all</div>
          </div>
          <div class="metric-card accepted clickable" data-filter="accepted">
            <div class="icon-wrap">${icon('check-circle')}</div>
            <div class="label">Accepted</div>
            <div class="value">${stats.accepted}</div><div class="sub">${stats.accept_rate}% accept rate — click to filter</div>
          </div>
          <div class="metric-card rejected clickable" data-filter="rejected">
            <div class="icon-wrap">${icon('x-circle')}</div>
            <div class="label">Rejected</div>
            <div class="value">${stats.rejected}</div><div class="sub">Tamper: ${stats.tamper} · Replay: ${stats.replay} — click to filter</div>
          </div>
          <div class="metric-card amber clickable" data-filter="expired">
            <div class="icon-wrap">${icon('clock')}</div>
            <div class="label">Expired</div>
            <div class="value">${stats.expired}</div><div class="sub">Outside 60s window — click to filter</div>
          </div>
        </div>
        <div class="chart-row">
          <div class="card">
            <div class="card-title">Recent Activity</div>
            ${chartItems.length ? `
              <div class="bar-chart">${chartHtml}</div>
              <div class="chart-legend">
                <span><span class="legend-dot" style="background:var(--green)"></span>Passed checks</span>
                <span><span class="legend-dot" style="background:var(--red)"></span>Failed checks</span>
              </div>` : '<div class="state-box"><p>No events yet.</p></div>'}
          </div>
          <div class="card">
            <div class="card-title">Outcome Distribution</div>
            <div class="donut-wrap">
              <svg width="120" height="120" viewBox="0 0 120 120">
                <circle cx="60" cy="60" r="40" fill="none" stroke="#E5E8ED" stroke-width="16"/>
                <circle cx="60" cy="60" r="40" fill="none" stroke="#16A34A" stroke-width="16"
                  stroke-dasharray="${accDash} 251.3" stroke-dashoffset="0" transform="rotate(-90 60 60)"/>
                <circle cx="60" cy="60" r="40" fill="none" stroke="#DC2626" stroke-width="16"
                  stroke-dasharray="${rejDash} 251.3" stroke-dashoffset="${-accDash}" transform="rotate(-90 60 60)"/>
                <text x="60" y="56" text-anchor="middle" font-size="20" font-weight="700" fill="#1A1F2E">${total}</text>
                <text x="60" y="72" text-anchor="middle" font-size="10" fill="#9CA3AF">events</text>
              </svg>
            </div>
            <div class="donut-legend">
              <div class="donut-legend-item"><span class="legend-dot" style="background:var(--green)"></span>Accepted (${stats.accepted})</div>
              <div class="donut-legend-item"><span class="legend-dot" style="background:var(--red)"></span>Rejected (${stats.rejected})</div>
            </div>
          </div>
        </div>
        <div class="card" style="margin-bottom:16px">
          <div class="card-title">Quick Test — Sign &amp; Verify</div>
          <p style="font-size:13px;color:var(--text-secondary);margin-bottom:12px">Type a payload and run a full sign+verify cycle right from the dashboard.</p>
          <div class="quick-test">
            <div class="input-group" style="flex:1">
              <textarea id="ov-quick-payload" class="code-input" spellcheck="false" style="min-height:60px">{ "message": "hello from dashboard" }</textarea>
            </div>
            <button id="ov-quick-run" class="btn btn-primary">${icon('play')} Sign &amp; Verify</button>
          </div>
          <div id="ov-quick-result" style="margin-top:12px"></div>
        </div>
        <div class="card">
          <div class="card-title">Recent Events</div>
          <div class="table-wrap"><table>
            <thead><tr><th>Request ID</th><th>Result</th><th>Reason</th><th class="hide-mobile">Time</th></tr></thead>
            <tbody>${recentHtml}</tbody>
          </table></div>
        </div>`;

      refreshIcons();

      // Wire live toggle
      document.getElementById('ov-live-toggle').addEventListener('click', () => {
        overviewLive = !overviewLive;
        if (overviewLive) {
          overviewLiveTimer = setInterval(() => loadOverviewData(root), 5000);
          showToast('Live refresh enabled (every 5s)', 'success');
        } else {
          clearInterval(overviewLiveTimer);
          overviewLiveTimer = null;
          showToast('Live refresh disabled', '');
        }
        // update visual
        const btn = document.getElementById('ov-live-toggle');
        btn.classList.toggle('active', overviewLive);
        const pulse = document.querySelector('.live-pulse');
        if (pulse) pulse.style.display = overviewLive ? '' : 'none';
      });

      // Wire clickable metric cards
      document.querySelectorAll('.metric-card.clickable').forEach(card => {
        card.addEventListener('click', () => {
          const filter = card.dataset.filter;
          if (filter === 'all') {
            navigate('logs');
          } else if (filter === 'accepted') {
            logsState.result = 'accepted'; logsState.reason = 'all'; logsState.page = 1;
            navigate('logs');
          } else if (filter === 'rejected') {
            logsState.result = 'rejected'; logsState.reason = 'all'; logsState.page = 1;
            navigate('logs');
          } else if (filter === 'expired') {
            logsState.result = 'all'; logsState.reason = 'expired'; logsState.page = 1;
            navigate('logs');
          }
        });
      });

      // Wire quick test
      document.getElementById('ov-quick-run').addEventListener('click', ovQuickTest);
    } catch (e) {
      root.innerHTML = `<div class="state-box error-text">${icon('wifi-off')}<p>Failed to load overview: ${e.message}</p></div>`;
      refreshIcons();
    }
  }

  async function ovQuickTest() {
    const ta = document.getElementById('ov-quick-payload');
    const resultEl = document.getElementById('ov-quick-result');
    const btn = document.getElementById('ov-quick-run');
    let payload;
    try { payload = JSON.parse(ta.value); }
    catch (e) { showToast('Invalid JSON: ' + e.message, 'error'); return; }

    btn.disabled = true;
    btn.innerHTML = '<div class="spinner" style="width:16px;height:16px;border-width:2px"></div>';
    resultEl.innerHTML = '<div class="state-box"><div class="spinner"></div>Signing and verifying…</div>';

    try {
      const signed = await api('/api/sign', 'POST', { payload });
      const result = await api('/api/verify', 'POST', {
        request_id: signed.request_id,
        payload: signed.payload,
        timestamp: signed.timestamp,
        nonce: signed.nonce,
        tag: signed.tag,
      });
      const accepted = result.result === 'accepted';
      resultEl.innerHTML = `
        <div class="verdict-banner ${result.result}">
          ${accepted ? icon('check-circle') : icon('x-circle')}
          ${accepted ? 'Accepted' : 'Rejected'} — ${result.reason}
        </div>
        <div class="trace-list">${result.checks.map(c => renderCheckItem(c)).join('')}</div>`;
      refreshIcons();
    } catch (e) {
      resultEl.innerHTML = `<div class="state-box error-text">${icon('alert-triangle')}<p>${e.message}</p></div>`;
      refreshIcons();
    } finally {
      btn.disabled = false;
      btn.innerHTML = icon('play') + ' Sign &amp; Verify';
      refreshIcons();
    }
  }

  // --- Message Lab page (INTERACTIVE: quick actions, live diff, copy, signing string) ---
  function renderMessageLab(root) {
    const defaultPayload = JSON.stringify({ "amount": 100, "recipient": "alice", "currency": "USD" }, null, 2);
    root.innerHTML = `
      <div class="page-intro">
        <strong>Message Lab</strong> is your free-form sandbox. Compose any payload, sign it, then manually
        tweak individual fields — or use the quick-action buttons — to see what breaks. Try the challenges
        below to learn by doing.
      </div>
      <div class="challenge-hints">
        <div class="challenge-hints-title">${icon('target')} Try these challenges</div>
        <div class="challenge-item" data-challenge="tamper"><span class="challenge-num">1</span><span class="challenge-text">Sign a message, then change one value in the payload — which check catches it?</span></div>
        <div class="challenge-item" data-challenge="age"><span class="challenge-num">2</span><span class="challenge-text">Sign a message, then age the timestamp by 120s — does the HMAC still pass?</span></div>
        <div class="challenge-item" data-challenge="reuse"><span class="challenge-num">3</span><span class="challenge-text">Sign a message, verify it, then verify again without changing anything — what happens?</span></div>
        <div class="challenge-item" data-challenge="corrupt"><span class="challenge-num">4</span><span class="challenge-text">Corrupt just one character of the tag — does hmac.compare_digest still catch it?</span></div>
        <div class="challenge-item" data-challenge="combot"><span class="challenge-num">5</span><span class="challenge-text">Can you make the HMAC pass but the timestamp fail? (hint: change only the timestamp)</span></div>
      </div>
      <div class="lab-layout">
        <div>
          <div class="card">
            <div class="card-title">1. Compose &amp; Sign</div>
            <div class="input-group">
              <label class="input-label" for="lab-payload">Payload (JSON)</label>
              <textarea id="lab-payload" class="code-input" spellcheck="false">${defaultPayload}</textarea>
            </div>
            <div class="action-row">
              <button id="lab-sign" class="btn btn-primary">${icon('pen-tool')} Sign Message</button>
            </div>
          </div>
          <div id="lab-signed-display" style="display:none">
            <div class="card" style="margin-top:16px">
              <div class="card-title">2. Signed Message — Edit to Tamper</div>
              <div class="quick-actions" id="lab-quick-actions" style="display:none">
                <button class="quick-action-btn" data-action="tamper">${icon('pencil')} Tamper Payload</button>
                <button class="quick-action-btn" data-action="age">${icon('clock')} Age Timestamp</button>
                <button class="quick-action-btn" data-action="corrupt">${icon('shuffle')} Corrupt Tag</button>
                <button class="quick-action-btn" data-action="reuse">${icon('repeat')} Reuse Nonce</button>
                <button class="quick-action-btn" data-action="reset-all">${icon('rotate-ccw')} Reset All</button>
              </div>
              <div id="lab-fields"></div>
              <div id="lab-live-diff"></div>
              <div class="action-row">
                <button id="lab-verify" class="btn btn-primary">${icon('shield-check')} Verify Message</button>
                <button id="lab-reset" class="btn">${icon('rotate-ccw')} Reset to Original</button>
              </div>
            </div>
          </div>
        </div>
        <div>
          <div class="card">
            <div class="card-title">3. Verification Result</div>
            <div id="lab-result">
              <div class="state-box">${icon('inbox')}<p>Sign a message, then verify it. Edit any field to see what breaks.</p></div>
            </div>
          </div>
        </div>
      </div>`;
    refreshIcons();
    document.getElementById('lab-sign').addEventListener('click', labDoSign);
  }

  async function labDoSign() {
    const ta = document.getElementById('lab-payload');
    const signedDisplay = document.getElementById('lab-signed-display');
    const resultEl = document.getElementById('lab-result');
    const signBtn = document.getElementById('lab-sign');
    let payload;
    try { payload = JSON.parse(ta.value); }
    catch (e) { showToast('Invalid JSON: ' + e.message, 'error'); return; }

    signBtn.disabled = true;
    signBtn.innerHTML = '<div class="spinner" style="width:16px;height:16px;border-width:2px"></div> Signing…';
    try {
      const signed = await api('/api/sign', 'POST', { payload });
      labSignedMsg = signed;
      labOriginal = {
        payload: JSON.stringify(signed.payload, null, 2),
        timestamp: String(signed.timestamp),
        nonce: signed.nonce,
        tag: signed.tag,
      };
      labCurrentResult = null;

      const fieldsEl = document.getElementById('lab-fields');
      if (!fieldsEl) { showToast('UI not ready, try again', 'error'); return; }
      fieldsEl.innerHTML = `
        <div class="field-row" id="fr-payload">
          <div class="field-label">Payload</div>
          <div class="field-input">
            <textarea id="lab-edit-payload" spellcheck="false">${escapeHtml(labOriginal.payload)}</textarea>
            <div class="field-meta">JSON payload — modify a value to simulate tampering</div>
          </div>
        </div>
        <div class="field-row" id="fr-timestamp">
          <div class="field-label">Timestamp</div>
          <div class="field-input">
            <input type="text" id="lab-edit-timestamp" value="${labOriginal.timestamp}" />
            <div class="field-meta">Unix epoch seconds — change to simulate an expired message</div>
          </div>
        </div>
        <div class="field-row" id="fr-nonce">
          <div class="field-label">Nonce</div>
          <div class="field-input">
            <input type="text" id="lab-edit-nonce" value="${labOriginal.nonce}" />
            <div class="field-meta">Unique per message — reuse to simulate a replay</div>
          </div>
        </div>
        <div class="field-row" id="fr-tag">
          <div class="field-label">HMAC Tag</div>
          <div class="field-input">
            <input type="text" id="lab-edit-tag" value="${labOriginal.tag}" />
            <div class="field-meta">HMAC-SHA256 hex digest — modify to break integrity</div>
          </div>
        </div>`;
      if (signedDisplay) signedDisplay.style.display = 'block';
      const qa = document.getElementById('lab-quick-actions');
      if (qa) qa.style.display = 'flex';

      resultEl.innerHTML = `<div class="state-box">${icon('shield-check')}<p>Message signed. Use quick actions or edit fields, then click Verify.</p></div>`;

      // Track modifications
      ['payload', 'timestamp', 'nonce', 'tag'].forEach(field => {
        const el = document.getElementById('lab-edit-' + field);
        if (!el) return;
        el.addEventListener('input', () => {
          const row = document.getElementById('fr-' + field);
          if (row) {
            if (el.value !== labOriginal[field]) row.classList.add('modified');
            else row.classList.remove('modified');
          }
          updateLabDiff();
        });
      });

      // Wire quick actions
      document.querySelectorAll('#lab-quick-actions .quick-action-btn').forEach(btn => {
        btn.addEventListener('click', () => labQuickAction(btn.dataset.action));
      });

      const verifyBtn = document.getElementById('lab-verify');
      const resetBtn = document.getElementById('lab-reset');
      if (verifyBtn) verifyBtn.addEventListener('click', labDoVerify);
      if (resetBtn) resetBtn.addEventListener('click', labDoReset);
      updateLabDiff();
      refreshIcons();
    } catch (e) {
      showToast(e.message, 'error');
      resultEl.innerHTML = `<div class="state-box error-text">${icon('alert-triangle')}<p>${e.message}</p></div>`;
      refreshIcons();
    } finally {
      if (signBtn) { signBtn.disabled = false; signBtn.innerHTML = icon('pen-tool') + ' Sign Message'; }
      refreshIcons();
    }
  }

  function updateLabDiff() {
    const diffEl = document.getElementById('lab-live-diff');
    if (!diffEl) return;
    const fields = ['payload', 'timestamp', 'nonce', 'tag'];
    let modified = [];
    fields.forEach(f => {
      const el = document.getElementById('lab-edit-' + f);
      if (el && el.value !== labOriginal[f]) modified.push(f);
    });
    if (modified.length === 0) {
      diffEl.innerHTML = `<div class="live-diff clean">${icon('shield-check')} No modifications — message matches original signature</div>`;
    } else {
      diffEl.innerHTML = `<div class="live-diff modified">${icon('alert-triangle')} Modified: ${modified.join(', ')} — verification should ${modified.includes('payload') || modified.includes('tag') ? 'fail HMAC' : modified.includes('timestamp') ? 'fail timestamp' : 'fail nonce'}</div>`;
    }
    refreshIcons();
  }

  function labQuickAction(action) {
    const payloadEl = document.getElementById('lab-edit-payload');
    const tsEl = document.getElementById('lab-edit-timestamp');
    const nonceEl = document.getElementById('lab-edit-nonce');
    const tagEl = document.getElementById('lab-edit-tag');

    if (!payloadEl || !tsEl || !nonceEl || !tagEl) { showToast('Sign a message first', 'error'); return; }

    if (action === 'tamper') {
      try {
        const p = JSON.parse(payloadEl.value);
        const keys = Object.keys(p);
        if (keys.length > 0) {
          const k = keys[0];
          if (typeof p[k] === 'number') p[k] = p[k] + 1000;
          else if (typeof p[k] === 'string') p[k] = p[k] + '_TAMPERED';
          else p[k] = 'TAMPERED';
        }
        payloadEl.value = JSON.stringify(p, null, 2);
        showToast('Payload modified — HMAC will fail', '');
      } catch (e) { showToast('Cannot tamper: invalid JSON', 'error'); }
    } else if (action === 'age') {
      const ts = parseFloat(tsEl.value);
      tsEl.value = String(ts - 120);
      showToast('Timestamp aged by 120s — should fail timestamp check', '');
    } else if (action === 'corrupt') {
      let tag = tagEl.value;
      tagEl.value = (tag[0] === 'a' ? 'b' : 'a') + tag.slice(1);
      showToast('Tag corrupted — HMAC will fail', '');
    } else if (action === 'reuse') {
      nonceEl.value = labOriginal.nonce;
      showToast('Nonce reset to original — verify twice to trigger replay', '');
    } else if (action === 'reset-all') {
      labDoReset();
      return;
    }

    // Re-check modifications
    ['payload', 'timestamp', 'nonce', 'tag'].forEach(f => {
      const el = document.getElementById('lab-edit-' + f);
      const row = document.getElementById('fr-' + f);
      if (el.value !== labOriginal[f]) row.classList.add('modified');
      else row.classList.remove('modified');
    });
    updateLabDiff();
  }

  async function labDoVerify() {
    const resultEl = document.getElementById('lab-result');
    const verifyBtn = document.getElementById('lab-verify');
    if (!resultEl || !verifyBtn) return;
    if (!labSignedMsg) { showToast('Sign a message first', 'error'); return; }

    const payloadEl = document.getElementById('lab-edit-payload');
    const tsEl = document.getElementById('lab-edit-timestamp');
    const nonceEl = document.getElementById('lab-edit-nonce');
    const tagEl = document.getElementById('lab-edit-tag');
    if (!payloadEl || !tsEl || !nonceEl || !tagEl) { showToast('Sign a message first', 'error'); return; }

    let payload;
    try { payload = JSON.parse(payloadEl.value); }
    catch (e) { showToast('Payload is not valid JSON: ' + e.message, 'error'); return; }
    const timestamp = parseFloat(tsEl.value);
    const nonce = nonceEl.value;
    const tag = tagEl.value;
    if (isNaN(timestamp)) { showToast('Timestamp must be a number', 'error'); return; }

    verifyBtn.disabled = true;
    verifyBtn.innerHTML = '<div class="spinner" style="width:16px;height:16px;border-width:2px"></div> Verifying…';
    try {
      const result = await api('/api/verify', 'POST', { request_id: labSignedMsg.request_id, payload, timestamp, nonce, tag });
      labCurrentResult = result;
      const accepted = result.result === 'accepted';
      resultEl.innerHTML = `
        <div class="verdict-banner ${result.result}">
          ${accepted ? icon('check-circle') : icon('x-circle')}
          ${accepted ? 'Accepted' : 'Rejected'} — ${result.reason}
        </div>
        <div class="trace-list">${result.checks.map(c => renderCheckItem(c)).join('')}</div>`;
      refreshIcons();
    } catch (e) {
      resultEl.innerHTML = `<div class="state-box error-text">${icon('alert-triangle')}<p>${e.message}</p></div>`;
      showToast(e.message, 'error');
      refreshIcons();
    } finally {
      verifyBtn.disabled = false;
      verifyBtn.innerHTML = icon('shield-check') + ' Verify Message';
      refreshIcons();
    }
  }

  function labDoReset() {
    if (!labSignedMsg) return;
    ['payload', 'timestamp', 'nonce', 'tag'].forEach(f => {
      const el = document.getElementById('lab-edit-' + f);
      const row = document.getElementById('fr-' + f);
      if (el) el.value = labOriginal[f];
      if (row) row.classList.remove('modified');
    });
    updateLabDiff();
    showToast('Fields reset to original signed values', 'success');
  }

  // --- Attack Simulator (VISUAL PIPELINE: watch the message flow) ---
  function renderAttackSim(root) {
    root.innerHTML = `
      <div class="page-intro">
        <strong>Attack Simulator</strong> is a visual playground. Pick an attack type, configure the
        parameters, hit "Run Attack Simulation", and watch the message travel through the pipeline in
        real time — from sender to wire to receiver, with each check lighting up as it passes or fails.
        Every result comes from the real backend. Try different parameter combinations to see how the
        checks react.
      </div>
      <div class="tabs">
        <button class="tab active" data-sim="tamper">${icon('pencil')} Tamper</button>
        <button class="tab" data-sim="replay">${icon('repeat')} Replay</button>
        <button class="tab" data-sim="expired">${icon('clock')} Expired</button>
      </div>
      <div id="sim-content"></div>`;
    refreshIcons();
    const tabs = root.querySelectorAll('.tab');
    tabs.forEach(t => {
      t.addEventListener('click', () => {
        tabs.forEach(x => x.classList.remove('active'));
        t.classList.add('active');
        loadSim(t.dataset.sim);
      });
    });
    loadSim('tamper');
  }

  async function loadSim(type) {
    const container = document.getElementById('sim-content');
    if (type === 'tamper') renderTamperSim(container);
    else if (type === 'replay') renderReplaySim(container);
    else renderExpiredSim(container);
    refreshIcons();
  }

  // Shared: renders the visual pipeline skeleton
  function renderPipelineSkeleton(steps) {
    return steps.map((s, i) => {
      const connector = i < steps.length - 1 ? `<div class="pipeline-connector" data-connector="${i}"></div>` : '';
      return `<div class="pipeline-node" data-node="${i}">
        <div class="pipeline-node-icon">${icon(s.icon)}</div>
        <div class="pipeline-node-body">
          <div class="pipeline-node-title">${s.title}</div>
          <div class="pipeline-node-desc">${s.desc}</div>
          <div class="pipeline-node-detail" data-detail="${i}"></div>
        </div>
        <div class="pipeline-check-result pending" data-badge="${i}">${icon('loader')} pending</div>
      </div>${connector}`;
    }).join('');
  }

  // Animates a pipeline node to active/done/fail and fills its detail
  function setPipelineNode(index, state, detail, badgeText, badgeIcon) {
    const node = document.querySelector(`[data-node="${index}"]`);
    if (!node) return;
    node.classList.remove('active', 'done', 'fail');
    node.classList.add(state);
    if (detail !== undefined) {
      const el = node.querySelector('[data-detail]');
      if (el) el.textContent = detail;
    }
    if (badgeText !== undefined) {
      const badge = node.querySelector(`[data-badge="${index}"]`);
      if (badge) {
        badge.className = 'pipeline-check-result ' + (state === 'fail' ? 'fail' : state === 'done' ? 'pass' : 'pending');
        badge.innerHTML = (badgeIcon || icon('loader')) + ' ' + badgeText;
      }
    }
    // Activate connector above
    if (index > 0) {
      const conn = document.querySelector(`[data-connector="${index - 1}"]`);
      if (conn) { conn.classList.remove('active', 'done'); conn.classList.add(state === 'done' ? 'done' : 'active'); }
    }
    refreshIcons();
  }

  function resetPipeline(steps) {
    steps.forEach((_, i) => {
      const node = document.querySelector(`[data-node="${i}"]`);
      if (node) {
        node.classList.remove('active', 'done', 'fail');
        const el = node.querySelector('[data-detail]'); if (el) el.textContent = '';
        const badge = node.querySelector(`[data-badge="${i}"]`);
        if (badge) { badge.className = 'pipeline-check-result pending'; badge.innerHTML = icon('loader') + ' pending'; }
      }
      const conn = document.querySelector(`[data-connector="${i}"]`);
      if (conn) conn.classList.remove('active', 'done');
    });
    refreshIcons();
  }

  function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

  // -- TAMPER: watch a message get signed, tampered in transit, then fail HMAC --
  function renderTamperSim(container) {
    const defaultPayload = JSON.stringify({ "amount": 1000, "recipient": "bob", "currency": "USD" }, null, 2);
    container.innerHTML = `
      <div class="card">
        <div class="section-title">Configure the Attack</div>
        <div class="tab-tip">
          ${icon('lightbulb')}
          <span><strong>Tamper attack:</strong> The attacker modifies the payload after it's signed, but the HMAC tag stays the same. Try tampering different fields (first, last, all) and different values to see how the HMAC check always catches it — no matter how small the change.</span>
        </div>
        <div class="sim-params">
          <div class="param-row">
            <span class="param-label">Tamper which field:</span>
            <div class="radio-group" id="tamper-field-group">
              <label class="radio-btn active" data-field="first">First field</label>
              <label class="radio-btn" data-field="last">Last field</label>
              <label class="radio-btn" data-field="all">All fields</label>
            </div>
          </div>
          <div class="param-row">
            <span class="param-label">Replacement value:</span>
            <input type="text" id="tamper-value" class="select" value="999" style="width:120px;font-family:var(--font-mono)">
          </div>
        </div>

        <div class="input-group" style="margin-top:16px">
          <label class="input-label">Payload (JSON)</label>
          <textarea id="tamper-payload" class="code-input" spellcheck="false">${defaultPayload}</textarea>
        </div>
        <div class="action-row">
          <button id="tamper-run" class="btn btn-primary">${icon('play')} Run Attack Simulation</button>
        </div>

        <div id="tamper-visual" style="display:none">
          <div class="endpoint-visual">
            <div class="endpoint-box sender">
              <div class="ep-label">Sender</div>
              <div class="ep-name">Signs &amp; sends</div>
            </div>
            <div class="wire-visual"><div class="wire-line" id="tamper-wire"></div></div>
            <div class="endpoint-box receiver" id="tamper-receiver">
              <div class="ep-label">Receiver</div>
              <div class="ep-name">Verifies</div>
            </div>
          </div>

          <div class="pipeline-legend">
            <span><span class="legend-node-dot pending"></span>Pending</span>
            <span><span class="legend-node-dot active"></span>In progress</span>
            <span><span class="legend-node-dot done"></span>Passed</span>
            <span><span class="legend-node-dot fail"></span>Failed</span>
          </div>

          <div class="pipeline" id="tamper-pipeline">
            ${renderPipelineSkeleton([
              { icon: 'pen-tool', title: '1. Sign Message (Sender)', desc: 'Sender computes HMAC-SHA256 over payload + timestamp + nonce' },
              { icon: 'arrow-right', title: '2. Transmit Message', desc: 'Message travels over the wire to the receiver' },
              { icon: 'pencil', title: '3. Tamper in Transit', desc: 'Attacker modifies the payload before it reaches the receiver' },
              { icon: 'shield-check', title: '4. Check HMAC Integrity', desc: 'Receiver recomputes HMAC and compares with received tag' },
              { icon: 'check-circle', title: '5. Final Verdict', desc: 'Message accepted or rejected' },
            ])}
          </div>

          <div id="tamper-result-area"></div>
          <div class="action-row">
            <button id="tamper-restart-btn" class="btn">${icon('rotate-ccw')} Run Again</button>
          </div>
        </div>
      </div>`;
    refreshIcons();

    document.querySelectorAll('#tamper-field-group .radio-btn').forEach(lbl => {
      lbl.addEventListener('click', () => {
        document.querySelectorAll('#tamper-field-group .radio-btn').forEach(l => l.classList.remove('active'));
        lbl.classList.add('active');
      });
    });

    document.getElementById('tamper-run').addEventListener('click', runTamperSim);
    document.getElementById('tamper-restart-btn').addEventListener('click', () => loadSim('tamper'));
  }

  async function runTamperSim() {
    const btn = document.getElementById('tamper-run');
    const visual = document.getElementById('tamper-visual');
    let payload;
    try { payload = JSON.parse(document.getElementById('tamper-payload').value); }
    catch (e) { showToast('Invalid JSON: ' + e.message, 'error'); return; }

    const tamperField = document.querySelector('#tamper-field-group .radio-btn.active').dataset.field;
    const tamperValue = document.getElementById('tamper-value').value;

    btn.disabled = true;
    visual.style.display = 'block';
    resetPipeline([0,1,2,3,4]);

    // Step 1: Sign
    setPipelineNode(0, 'active', '', 'signing…');
    await sleep(300);
    try {
      const signed = await api('/api/sign', 'POST', { payload });
      setPipelineNode(0, 'done', 'Tag: ' + signed.tag.slice(0, 24) + '…', 'signed', icon('check'));
      await sleep(400);

      // Step 2: Transmit
      setPipelineNode(1, 'active', '', 'transmitting…');
      document.getElementById('tamper-wire').classList.add('active');
      await sleep(600);
      document.getElementById('tamper-wire').classList.remove('active');
      setPipelineNode(1, 'done', 'Payload + timestamp + nonce + tag sent', 'delivered', icon('check'));
      await sleep(300);

      // Step 3: Tamper in transit
      setPipelineNode(2, 'active', '', 'intercepting…');
      await sleep(400);
      const tamperedPayload = JSON.parse(JSON.stringify(signed.payload));
      const keys = Object.keys(tamperedPayload);
      if (tamperField === 'first' && keys.length > 0) {
        tamperedPayload[keys[0]] = isNaN(tamperValue) ? tamperValue : Number(tamperValue);
      } else if (tamperField === 'last' && keys.length > 0) {
        tamperedPayload[keys[keys.length - 1]] = isNaN(tamperValue) ? tamperValue : Number(tamperValue);
      } else if (tamperField === 'all') {
        keys.forEach(k => { tamperedPayload[k] = isNaN(tamperValue) ? tamperValue : Number(tamperValue); });
      }
      const diffHtml = renderPayloadDiff(signed.payload, tamperedPayload);
      setPipelineNode(2, 'done', 'Payload modified — tag unchanged', 'tampered', icon('alert-triangle'));
      await sleep(400);

      // Step 4: HMAC check
      setPipelineNode(3, 'active', '', 'checking…');
      document.getElementById('tamper-receiver').classList.add('active');
      await sleep(300);
      const result = await api('/api/verify', 'POST', {
        request_id: signed.request_id,
        payload: tamperedPayload,
        timestamp: signed.timestamp,
        nonce: signed.nonce,
        tag: signed.tag,
      });
      const hmacCheck = result.checks[0];
      if (hmacCheck.status === 'fail') {
        setPipelineNode(3, 'fail', 'Expected: ' + hmacCheck.expected.slice(0, 24) + '…\nReceived: ' + hmacCheck.received.slice(0, 24) + '…', 'FAIL', icon('x'));
        document.getElementById('tamper-receiver').classList.remove('active');
        document.getElementById('tamper-receiver').classList.add('fail');
      } else {
        setPipelineNode(3, 'done', 'Tags match', 'pass', icon('check'));
      }
      await sleep(400);

      // Step 5: Verdict
      setPipelineNode(4, 'active', '', 'deciding…');
      await sleep(300);
      const accepted = result.result === 'accepted';
      setPipelineNode(4, accepted ? 'done' : 'fail', result.result.toUpperCase() + ' — ' + result.reason, result.reason, accepted ? icon('check-circle') : icon('x-circle'));

      // Show full result
      document.getElementById('tamper-result-area').innerHTML = `
        ${diffHtml}
        <div class="verdict-banner ${result.result}">
          ${accepted ? icon('check-circle') : icon('x-circle')}
          ${accepted ? 'Accepted' : 'Rejected'} — ${result.reason}
        </div>
        <div class="trace-list">${result.checks.map(c => renderCheckItem(c)).join('')}</div>`;
      refreshIcons();
    } catch (e) {
      showToast(e.message, 'error');
    } finally {
      btn.disabled = false;
      refreshIcons();
    }
  }

  // -- REPLAY: watch first request pass, then second fail at nonce --
  function renderReplaySim(container) {
    const defaultPayload = JSON.stringify({ "action": "transfer", "amount": 500, "to": "charlie" }, null, 2);
    container.innerHTML = `
      <div class="card">
        <div class="section-title">Configure the Attack</div>
        <div class="tab-tip">
          ${icon('lightbulb')}
          <span><strong>Replay attack:</strong> The attacker captures a valid signed message and resends it. The first request passes all checks, but the second fails the nonce uniqueness check. Try increasing the replay count to 5 and watch each attempt animate through the pipeline — only the first succeeds.</span>
        </div>
        <div class="sim-params">
          <div class="param-row">
            <span class="param-label">Replay count:</span>
            <input type="range" id="replay-count" min="1" max="5" value="2">
            <span class="param-value" id="replay-count-val">2</span>
          </div>
          <div class="param-row">
            <span class="param-label">Delay between sends:</span>
            <input type="range" id="replay-delay" min="0" max="2000" value="500" step="100">
            <span class="param-value" id="replay-delay-val">500ms</span>
          </div>
        </div>

        <div class="input-group" style="margin-top:16px">
          <label class="input-label">Payload (JSON)</label>
          <textarea id="replay-payload" class="code-input" spellcheck="false">${defaultPayload}</textarea>
        </div>
        <div class="action-row">
          <button id="replay-run" class="btn btn-primary">${icon('play')} Run Attack Simulation</button>
        </div>

        <div id="replay-visual" style="display:none">
          <div class="endpoint-visual">
            <div class="endpoint-box sender">
              <div class="ep-label">Attacker</div>
              <div class="ep-name">Captures &amp; resends</div>
            </div>
            <div class="wire-visual"><div class="wire-line" id="replay-wire"></div></div>
            <div class="endpoint-box receiver" id="replay-receiver">
              <div class="ep-label">Receiver</div>
              <div class="ep-name">Verifies each attempt</div>
            </div>
          </div>
          <div id="replay-attempts"></div>
          <div class="action-row">
            <button id="replay-restart-btn" class="btn">${icon('rotate-ccw')} Run Again</button>
          </div>
        </div>
      </div>`;
    refreshIcons();

    document.getElementById('replay-count').addEventListener('input', (e) => {
      document.getElementById('replay-count-val').textContent = e.target.value;
    });
    document.getElementById('replay-delay').addEventListener('input', (e) => {
      document.getElementById('replay-delay-val').textContent = e.target.value + 'ms';
    });

    document.getElementById('replay-run').addEventListener('click', runReplaySim);
    document.getElementById('replay-restart-btn').addEventListener('click', () => loadSim('replay'));
  }

  async function runReplaySim() {
    const btn = document.getElementById('replay-run');
    const visual = document.getElementById('replay-visual');
    const count = parseInt(document.getElementById('replay-count').value);
    const delay = parseInt(document.getElementById('replay-delay').value);
    let payload;
    try { payload = JSON.parse(document.getElementById('replay-payload').value); }
    catch (e) { showToast('Invalid JSON: ' + e.message, 'error'); return; }

    btn.disabled = true;
    visual.style.display = 'block';
    document.getElementById('replay-attempts').innerHTML = '';
    document.getElementById('replay-receiver').classList.remove('fail', 'active');

    // Sign once
    const signed = await api('/api/sign', 'POST', { payload });

    for (let i = 0; i < count; i++) {
      const attemptEl = document.createElement('div');
      attemptEl.className = 'card';
      attemptEl.style.marginBottom = '12px';
      attemptEl.innerHTML = `
        <div class="section-title">Attempt ${i + 1} of ${count}</div>
        <div class="pipeline" id="replay-pipeline-${i}">
          ${renderPipelineSkeleton([
            { icon: 'send', title: 'Send Message', desc: i === 0 ? 'Original request' : 'Replay — same nonce, tag, everything' },
            { icon: 'shield-check', title: 'HMAC Check', desc: 'Recompute and compare tag' },
            { icon: 'clock', title: 'Timestamp Check', desc: 'Verify within 60s window' },
            { icon: 'key', title: 'Nonce Check', desc: 'Is this nonce already in the database?' },
            { icon: 'check-circle', title: 'Verdict', desc: 'Final decision' },
          ])}
        </div>
        <div id="replay-result-${i}"></div>`;
      document.getElementById('replay-attempts').appendChild(attemptEl);
      refreshIcons();

      // Animate this attempt
      const pipeId = `replay-pipeline-${i}`;
      // Use scoped pipeline manipulation
      await animateReplayAttempt(pipeId, i, signed, count, delay);
      if (delay > 0 && i < count - 1) await sleep(delay);
    }

    btn.disabled = false;
    refreshIcons();
  }

  async function animateReplayAttempt(pipeId, attemptIdx, signed, totalCount, delay) {
    // Local node selectors within this pipeline
    const nodes = document.querySelectorAll(`#${pipeId} .pipeline-node`);
    const conns = document.querySelectorAll(`#${pipeId} .pipeline-connector`);
    const badges = document.querySelectorAll(`#${pipeId} .pipeline-check-result`);

    function setLocal(idx, state, detail, badgeText, badgeIcon) {
      const node = nodes[idx]; if (!node) return;
      node.classList.remove('active', 'done', 'fail'); node.classList.add(state);
      if (detail !== undefined) { const el = node.querySelector('.pipeline-node-detail'); if (el) el.textContent = detail; }
      if (badgeText !== undefined) {
        const badge = badges[idx];
        badge.className = 'pipeline-check-result ' + (state === 'fail' ? 'fail' : state === 'done' ? 'pass' : 'pending');
        badge.innerHTML = (badgeIcon || icon('loader')) + ' ' + badgeText;
      }
      if (idx > 0) { const c = conns[idx - 1]; if (c) { c.classList.remove('active', 'done'); c.classList.add(state === 'done' ? 'done' : 'active'); } }
      refreshIcons();
    }

    // Step 0: Send
    setLocal(0, 'active', '', 'sending…');
    document.getElementById('replay-wire').classList.add('active');
    await sleep(500);
    document.getElementById('replay-wire').classList.remove('active');
    setLocal(0, 'done', 'Nonce: ' + signed.nonce.slice(0, 16) + '…', 'sent', icon('check'));
    await sleep(300);

    // Actually verify
    const result = await api('/api/verify', 'POST', {
      request_id: signed.request_id,
      payload: signed.payload,
      timestamp: signed.timestamp,
      nonce: signed.nonce,
      tag: signed.tag,
    });

    // Animate each check
    for (let c = 0; c < result.checks.length; c++) {
      const check = result.checks[c];
      const nodeIdx = c + 1;
      setLocal(nodeIdx, 'active', '', 'checking…');
      await sleep(400);
      if (check.status === 'pass') {
        setLocal(nodeIdx, 'done', check.detail, 'pass', icon('check'));
      } else {
        setLocal(nodeIdx, 'fail', check.detail, 'FAIL', icon('x'));
        document.getElementById('replay-receiver').classList.add('fail');
      }
      await sleep(300);
    }

    // Verdict node
    const verdictIdx = result.checks.length + 1;
    const accepted = result.result === 'accepted';
    setLocal(verdictIdx, 'active', '', 'deciding…');
    await sleep(300);
    setLocal(verdictIdx, accepted ? 'done' : 'fail', result.result.toUpperCase() + ' — ' + result.reason, result.reason, accepted ? icon('check-circle') : icon('x-circle'));

    // Show trace
    const resultEl = document.getElementById(`replay-result-${attemptIdx}`);
    if (resultEl) {
      resultEl.innerHTML = `
        <div class="verdict-banner ${result.result}" style="margin-top:12px">
          ${accepted ? icon('check-circle') : icon('x-circle')}
          Attempt ${attemptIdx + 1}: ${accepted ? 'Accepted' : 'Rejected'} — ${result.reason}
        </div>
        <div class="trace-list">${result.checks.map(c => renderCheckItem(c)).join('')}</div>`;
    }
    refreshIcons();
  }

  // -- EXPIRED: watch message pass HMAC but fail timestamp --
  function renderExpiredSim(container) {
    const defaultPayload = JSON.stringify({ "action": "ping", "server": "node-1" }, null, 2);
    container.innerHTML = `
      <div class="card">
        <div class="section-title">Configure the Attack</div>
        <div class="tab-tip">
          ${icon('lightbulb')}
          <span><strong>Expired message:</strong> The sender signs with an old timestamp, so the HMAC tag is valid (it was correctly computed), but the timestamp window check fails. Try sliding the age to under 60s — the message should pass! Then push it to 600s and watch it fail harder.</span>
        </div>
        <div class="sim-params">
          <div class="param-row">
            <span class="param-label">Timestamp age:</span>
            <input type="range" id="expired-age" min="10" max="600" value="120" step="10">
            <span class="param-value" id="expired-age-val">120s</span>
          </div>
          <div class="param-row">
            <span class="param-label" style="color:var(--text-tertiary)">Window is ±60s — anything above 60s will fail the timestamp check</span>
          </div>
        </div>

        <div class="input-group" style="margin-top:16px">
          <label class="input-label">Payload (JSON)</label>
          <textarea id="expired-payload" class="code-input" spellcheck="false">${defaultPayload}</textarea>
        </div>
        <div class="action-row">
          <button id="expired-run" class="btn btn-primary">${icon('play')} Run Attack Simulation</button>
        </div>

        <div id="expired-visual" style="display:none">
          <div class="endpoint-visual">
            <div class="endpoint-box sender">
              <div class="ep-label">Sender</div>
              <div class="ep-name">Signs with old clock</div>
            </div>
            <div class="wire-visual"><div class="wire-line" id="expired-wire"></div></div>
            <div class="endpoint-box receiver" id="expired-receiver">
              <div class="ep-label">Receiver</div>
              <div class="ep-name">Verifies</div>
            </div>
          </div>
          <div class="pipeline-legend">
            <span><span class="legend-node-dot pending"></span>Pending</span>
            <span><span class="legend-node-dot active"></span>In progress</span>
            <span><span class="legend-node-dot done"></span>Passed</span>
            <span><span class="legend-node-dot fail"></span>Failed</span>
          </div>
          <div class="pipeline" id="expired-pipeline">
            ${renderPipelineSkeleton([
              { icon: 'pen-tool', title: '1. Sign with Old Timestamp', desc: 'Sender signs with a timestamp from the past' },
              { icon: 'arrow-right', title: '2. Transmit Message', desc: 'Message travels to the receiver' },
              { icon: 'shield-check', title: '3. Check HMAC Integrity', desc: 'Tag is valid — it was correctly computed' },
              { icon: 'clock', title: '4. Check Timestamp Window', desc: 'Receiver checks if timestamp is within ±60s' },
              { icon: 'check-circle', title: '5. Final Verdict', desc: 'Message accepted or rejected' },
            ])}
          </div>
          <div id="expired-result-area"></div>
          <div class="action-row">
            <button id="expired-restart-btn" class="btn">${icon('rotate-ccw')} Run Again</button>
          </div>
        </div>
      </div>`;
    refreshIcons();

    document.getElementById('expired-age').addEventListener('input', (e) => {
      document.getElementById('expired-age-val').textContent = e.target.value + 's';
    });

    document.getElementById('expired-run').addEventListener('click', runExpiredSim);
    document.getElementById('expired-restart-btn').addEventListener('click', () => loadSim('expired'));
  }

  async function runExpiredSim() {
    const btn = document.getElementById('expired-run');
    const visual = document.getElementById('expired-visual');
    let payload;
    try { payload = JSON.parse(document.getElementById('expired-payload').value); }
    catch (e) { showToast('Invalid JSON: ' + e.message, 'error'); return; }

    const ageSeconds = parseInt(document.getElementById('expired-age').value);

    btn.disabled = true;
    visual.style.display = 'block';
    resetPipeline([0,1,2,3,4]);
    document.getElementById('expired-receiver').classList.remove('fail', 'active');

    // Step 1: Sign with old timestamp
    setPipelineNode(0, 'active', '', 'signing…');
    await sleep(300);
    const oldTs = (Date.now() / 1000) - ageSeconds;
    const signed = await api('/api/sign', 'POST', { payload, timestamp: oldTs });
    setPipelineNode(0, 'done', 'Timestamp: ' + oldTs.toFixed(1) + ' (' + ageSeconds + 's old)', 'signed', icon('check'));
    await sleep(400);

    // Step 2: Transmit
    setPipelineNode(1, 'active', '', 'transmitting…');
    document.getElementById('expired-wire').classList.add('active');
    await sleep(600);
    document.getElementById('expired-wire').classList.remove('active');
    setPipelineNode(1, 'done', 'Message delivered', 'delivered', icon('check'));
    await sleep(300);

    // Verify
    document.getElementById('expired-receiver').classList.add('active');
    const result = await api('/api/verify', 'POST', {
      request_id: signed.request_id,
      payload: signed.payload,
      timestamp: signed.timestamp,
      nonce: signed.nonce,
      tag: signed.tag,
    });

    // Step 3: HMAC check (will pass — tag is valid)
    setPipelineNode(2, 'active', '', 'checking…');
    await sleep(400);
    const hmacCheck = result.checks[0];
    setPipelineNode(2, hmacCheck.status === 'pass' ? 'done' : 'fail', hmacCheck.detail, hmacCheck.status, hmacCheck.status === 'pass' ? icon('check') : icon('x'));
    await sleep(400);

    // Step 4: Timestamp check (will fail)
    if (result.checks.length > 1) {
      setPipelineNode(3, 'active', '', 'checking…');
      await sleep(400);
      const tsCheck = result.checks[1];
      setPipelineNode(3, tsCheck.status === 'pass' ? 'done' : 'fail', tsCheck.detail, tsCheck.status, tsCheck.status === 'pass' ? icon('check') : icon('x'));
      if (tsCheck.status === 'fail') {
        document.getElementById('expired-receiver').classList.remove('active');
        document.getElementById('expired-receiver').classList.add('fail');
      }
      await sleep(400);
    }

    // Step 5: Verdict
    setPipelineNode(4, 'active', '', 'deciding…');
    await sleep(300);
    const accepted = result.result === 'accepted';
    setPipelineNode(4, accepted ? 'done' : 'fail', result.result.toUpperCase() + ' — ' + result.reason, result.reason, accepted ? icon('check-circle') : icon('x-circle'));

    document.getElementById('expired-result-area').innerHTML = `
      <div class="verdict-banner ${result.result}">
        ${accepted ? icon('check-circle') : icon('x-circle')}
        ${accepted ? 'Accepted' : 'Rejected'} — ${result.reason}
      </div>
      <div class="trace-list">${result.checks.map(c => renderCheckItem(c)).join('')}</div>`;
    refreshIcons();
    btn.disabled = false;
  }

  // --- Verification Logs (INTERACTIVE: live poll, inline expand, export) ---
  function renderLogs(root) {
    root.innerHTML = `
      <div class="page-intro">
        <strong>Verification Logs</strong> is the complete audit trail — every sign, verify, and simulation
        from every page ends up here. Search, filter by result or reason, sort, and click any row to see
        the full check trace. Turn on live polling to watch new events appear in real time as you
        experiment in other tabs.
      </div>
      <div class="card">
        <div class="logs-toolbar-top">
          <div class="table-toolbar" style="flex:1">
            <input type="text" id="logs-search" class="search-input" placeholder="Search by request ID, payload, or nonce…" value="${logsState.q}" />
            <select id="logs-filter-result" class="select">
              <option value="all">All Results</option>
              <option value="accepted">Accepted</option>
              <option value="rejected">Rejected</option>
            </select>
            <select id="logs-filter-reason" class="select">
              <option value="all">All Reasons</option>
              <option value="ok">OK</option>
              <option value="tamper">Tamper</option>
              <option value="expired">Expired</option>
              <option value="replay">Replay</option>
            </select>
            <select id="logs-sort" class="select">
              <option value="created_at">Sort: Created</option>
              <option value="timestamp">Sort: Timestamp</option>
            </select>
            <select id="logs-order" class="select">
              <option value="desc">Desc</option>
              <option value="asc">Asc</option>
            </select>
          </div>
          <div class="logs-actions">
            <button id="logs-live-toggle" class="live-toggle">${icon('radio')} Live</button>
            <button id="logs-export" class="btn">${icon('download')} Export JSON</button>
          </div>
        </div>
        <div id="logs-body"></div>
        <div id="logs-pagination"></div>
      </div>`;
    refreshIcons();

    document.getElementById('logs-filter-result').value = logsState.result;
    document.getElementById('logs-filter-reason').value = logsState.reason;
    document.getElementById('logs-sort').value = logsState.sort;
    document.getElementById('logs-order').value = logsState.order;

    let searchTimer;
    document.getElementById('logs-search').addEventListener('input', (e) => {
      clearTimeout(searchTimer);
      searchTimer = setTimeout(() => { logsState.q = e.target.value; logsState.page = 1; loadLogs(); }, 300);
    });
    document.getElementById('logs-filter-result').addEventListener('change', (e) => { logsState.result = e.target.value; logsState.page = 1; loadLogs(); });
    document.getElementById('logs-filter-reason').addEventListener('change', (e) => { logsState.reason = e.target.value; logsState.page = 1; loadLogs(); });
    document.getElementById('logs-sort').addEventListener('change', (e) => { logsState.sort = e.target.value; loadLogs(); });
    document.getElementById('logs-order').addEventListener('change', (e) => { logsState.order = e.target.value; loadLogs(); });

    document.getElementById('logs-live-toggle').addEventListener('click', () => {
      if (logsLiveTimer) {
        clearInterval(logsLiveTimer);
        logsLiveTimer = null;
        document.getElementById('logs-live-toggle').classList.remove('active');
        showToast('Live polling disabled', '');
      } else {
        logsLiveTimer = setInterval(loadLogs, 5000);
        document.getElementById('logs-live-toggle').classList.add('active');
        showToast('Live polling enabled (every 5s)', 'success');
      }
    });

    document.getElementById('logs-export').addEventListener('click', () => {
      if (!logsData || !logsData.items.length) { showToast('No data to export', 'error'); return; }
      const blob = new Blob([JSON.stringify(logsData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `authpulse-events-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
      showToast('Exported ' + logsData.items.length + ' events', 'success');
    });

    loadLogs();
  }

  async function loadLogs() {
    const body = document.getElementById('logs-body');
    const pagEl = document.getElementById('logs-pagination');
    if (!body) return;
    body.innerHTML = '<div class="state-box"><div class="spinner"></div>Loading…</div>';

    const params = new URLSearchParams({ page: logsState.page, page_size: logsState.pageSize, order: logsState.order, sort: logsState.sort });
    if (logsState.q) params.set('q', logsState.q);
    if (logsState.result !== 'all') params.set('result', logsState.result);
    if (logsState.reason !== 'all') params.set('reason', logsState.reason);

    try {
      const data = await api('/api/events?' + params.toString());
      logsData = data;
      logsExpandedRow = null;

      if (!data.items.length) {
        body.innerHTML = `<div class="state-box">${icon('inbox')}<p>No events found. Try adjusting filters or run a test from the Message Lab.</p></div>`;
        pagEl.innerHTML = '';
        refreshIcons();
        return;
      }

      body.innerHTML = `<div class="table-wrap" style="border:none"><table id="logs-table">
        <thead><tr><th>Request ID</th><th>Result</th><th>Reason</th><th>Payload</th><th class="hide-mobile">Time</th></tr></thead>
        <tbody id="logs-tbody"></tbody>
      </table></div>`;

      const tbody = document.getElementById('logs-tbody');
      data.items.forEach((e, i) => {
        const tr = document.createElement('tr');
        tr.dataset.id = e.id;
        tr.tabIndex = 0;
        tr.innerHTML = `
          <td class="mono">${e.request_id.slice(0, 12)}</td>
          <td>${resultBadge(e.result)}</td>
          <td>${reasonBadge(e.reason)}</td>
          <td class="mono" style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(e.payload)}</td>
          <td class="mono hide-mobile">${timeAgo(e.created_at)}</td>`;
        tr.addEventListener('click', () => toggleRowExpand(e.id, e));
        tr.addEventListener('keydown', (ev) => {
          if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); toggleRowExpand(e.id, e); }
        });
        tbody.appendChild(tr);
      });

      const totalPages = data.total_pages || 1;
      pagEl.innerHTML = `<div class="pagination">
        <span>Showing ${(data.page - 1) * data.page_size + 1}–${Math.min(data.page * data.page_size, data.total)} of ${data.total}</span>
        <div class="page-btns">
          <button class="btn" id="pg-prev" ${data.page <= 1 ? 'disabled' : ''}>${icon('chevron-left')}</button>
          <span style="padding:8px 4px;font-size:13px">${data.page} / ${totalPages}</span>
          <button class="btn" id="pg-next" ${data.page >= totalPages ? 'disabled' : ''}>${icon('chevron-right')}</button>
        </div>
      </div>`;
      const prev = document.getElementById('pg-prev');
      const next = document.getElementById('pg-next');
      if (prev) prev.addEventListener('click', () => { logsState.page--; loadLogs(); });
      if (next) next.addEventListener('click', () => { logsState.page++; loadLogs(); });
      refreshIcons();
    } catch (e) {
      body.innerHTML = `<div class="state-box error-text">${icon('wifi-off')}<p>Failed to load logs: ${e.message}</p></div>`;
      refreshIcons();
    }
  }

  function toggleRowExpand(id, event) {
    const tbody = document.getElementById('logs-tbody');
    if (!tbody) return;

    // Collapse existing
    const existing = tbody.querySelector('.inline-expand');
    if (existing) {
      const existingId = existing.dataset.expandId;
      existing.remove();
      if (existingId == id) {
        logsExpandedRow = null;
        return; // toggle off
      }
    }

    // Find the row and insert expansion after it
    const row = tbody.querySelector(`tr[data-id="${id}"]`);
    if (!row) return;

    const expandRow = document.createElement('tr');
    expandRow.className = 'inline-expand';
    expandRow.dataset.expandId = id;
    expandRow.innerHTML = `<td colspan="5"><div class="expand-detail">
      <dl class="kv-grid">
        <dt>Request ID</dt><dd>${event.request_id}</dd>
        <dt>Result</dt><dd>${resultBadge(event.result)}</dd>
        <dt>Reason</dt><dd>${reasonBadge(event.reason)}</dd>
        <dt>Timestamp</dt><dd>${event.timestamp}</dd>
        <dt>Nonce</dt><dd>${event.nonce}</dd>
        <dt>HMAC Tag</dt><dd>${event.tag}</dd>
        <dt>Created At</dt><dd>${event.created_at}</dd>
        <dt>Payload</dt><dd>${escapeHtml(event.payload)}</dd>
      </dl>
      <div class="section-title" style="margin-top:12px">Check Trace</div>
      <div class="trace-list">${event.checks.map(c => renderCheckItem(c)).join('')}</div>
    </div></td>`;
    row.after(expandRow);
    logsExpandedRow = id;
    refreshIcons();
  }

  // --- API Playground (INTERACTIVE: presets, query builder, history) ---
  function renderPlayground(root) {
    root.innerHTML = `
      <div class="page-intro">
        <strong>API Playground</strong> lets you call every backend endpoint directly. Pick a scenario,
        tweak the request, and see the raw JSON response — the same API the other pages use under the hood.
        Use it to understand the request/response format, test edge cases, or debug.
      </div>
      <div class="lab-layout"><div>
      <div class="card">
        <div class="card-title">Request Builder</div>
        <div class="scenario-row" id="pg-scenarios">
          <span class="scenario-chip" data-scenario="sign">${icon('pen-tool')} Sign a message</span>
          <span class="scenario-chip" data-scenario="verify">${icon('shield-check')} Verify (valid)</span>
          <span class="scenario-chip" data-scenario="verify-fail">${icon('x-circle')} Verify (invalid)</span>
          <span class="scenario-chip" data-scenario="tamper">${icon('pencil')} Simulate tamper</span>
          <span class="scenario-chip" data-scenario="replay">${icon('repeat')} Simulate replay</span>
          <span class="scenario-chip" data-scenario="expired">${icon('clock')} Simulate expired</span>
          <span class="scenario-chip" data-scenario="browse">${icon('list')} Browse events</span>
          <span class="scenario-chip" data-scenario="stats">${icon('bar-chart-3')} Stats</span>
        </div>
        <div class="scenario-desc" id="pg-scenario-desc"></div>
        <div class="preset-row" id="pg-presets"></div>
        <div class="input-group">
          <label class="input-label" for="pg-endpoint">Endpoint</label>
          <select id="pg-endpoint" class="select">
            <option value="/api/sign">POST /api/sign</option>
            <option value="/api/verify">POST /api/verify</option>
            <option value="/api/simulate/tamper">POST /api/simulate/tamper</option>
            <option value="/api/simulate/replay">POST /api/simulate/replay</option>
            <option value="/api/simulate/expired">POST /api/simulate/expired</option>
            <option value="/api/events">GET /api/events</option>
            <option value="/api/stats">GET /api/stats</option>
            <option value="/api/health">GET /api/health</option>
          </select>
        </div>
        <div class="input-group" id="pg-body-group">
          <label class="input-label" for="pg-body">Request Body (JSON)</label>
          <textarea id="pg-body" class="code-input" spellcheck="false">{
  "payload": { "message": "hello" }
}</textarea>
        </div>
        <div id="pg-query-group" style="display:none">
          <label class="input-label">Query Parameters</label>
          <div class="query-param-builder" id="pg-query-params"></div>
          <button id="pg-add-param" class="btn" style="font-size:12px;padding:4px 10px">${icon('plus')} Add Parameter</button>
        </div>
        <div class="action-row" style="margin-top:12px">
          <button id="pg-send" class="btn btn-primary">${icon('play')} Send Request</button>
          <button id="pg-clear-history" class="btn">${icon('trash-2')} Clear History</button>
        </div>
      </div>
    </div><div>
      <div class="card">
        <div class="card-title">Response</div>
        <div id="pg-response" class="playground-response" style="min-height:200px">Pick a scenario above, then click "Send Request" to see the raw response.</div>
      </div>
      <div class="card" style="margin-top:16px">
        <div class="card-title">Request History</div>
        <div id="pg-history-list"><div class="state-box" style="padding:16px">${icon('history')}<p style="font-size:12px">No requests sent yet.</p></div></div>
      </div>
    </div></div>`;
    refreshIcons();

    // Declare all DOM refs first to avoid TDZ issues
    const endpointSel = document.getElementById('pg-endpoint');
    const bodyGroup = document.getElementById('pg-body-group');
    const queryGroup = document.getElementById('pg-query-group');
    const bodyTa = document.getElementById('pg-body');

    // Learning scenarios — these pre-fill the form so users learn by doing
    const scenarios = {
      sign: {
        endpoint: '/api/sign',
        body: '{ "payload": { "amount": 100, "recipient": "alice" } }',
        desc: 'The /api/sign endpoint acts as a demo sender. It takes a payload, computes the HMAC-SHA256 tag using the server-side secret, and returns the tag + timestamp + nonce. The secret never appears in the response. This response will be "accepted" because it is just signing — no verification happens here.',
      },
      'verify-valid': {
        endpoint: '/api/verify',
        body: '{ "payload": { "amount": 100, "recipient": "alice" }, "timestamp": 0, "nonce": "temp", "tag": "temp" }',
        desc: 'The /api/verify endpoint runs the full 3-check pipeline. This scenario has placeholder values — you need to first call /api/sign, then copy the returned timestamp, nonce, and tag into this body. When all three match, the response is "accepted". If any field is wrong, you will see which check failed.',
      },
      'verify-fail': {
        endpoint: '/api/verify',
        body: '{ "payload": { "amount": 100, "recipient": "alice" }, "timestamp": 0, "nonce": "test-nonce", "tag": "0000000000000000000000000000000000000000000000000000000000000000" }',
        desc: 'This scenario uses a deliberately fake tag (all zeros). The HMAC check will FAIL because the computed tag will not match. The response should be "rejected" with reason "tamper". This proves the HMAC check catches forged tags.',
      },
      tamper: {
        endpoint: '/api/simulate/tamper',
        body: '{ "payload": { "amount": 500, "recipient": "bob" } }',
        desc: 'This endpoint signs a payload, tampers it (modifies a value), then verifies the tampered version. The response should be "rejected" with reason "tamper" — the HMAC check fails because the tag was computed over the original payload, not the tampered one.',
      },
      replay: {
        endpoint: '/api/simulate/replay',
        body: '{ "payload": { "action": "transfer", "amount": 999 } }',
        desc: 'This endpoint sends the same signed message twice. The first attempt response should be "accepted", the second should be "rejected" with reason "replay" — the nonce uniqueness check fails because the same nonce was already used.',
      },
      expired: {
        endpoint: '/api/simulate/expired',
        body: '{ "payload": { "action": "ping" } }',
        desc: 'This endpoint signs with a timestamp 120 seconds in the past, then verifies. The response should be "rejected" with reason "expired" — the HMAC passes (the tag is valid) but the timestamp window check fails because the message is too old.',
      },
      browse: {
        endpoint: '/api/events',
        body: null,
        params: [{ key: 'page', value: '1' }, { key: 'page_size', value: '10' }],
        desc: 'The /api/events endpoint returns all verification attempts. Add query params like result=rejected or reason=tamper to filter. Try sorting with sort=timestamp&order=asc.',
      },
      stats: {
        endpoint: '/api/stats',
        body: null,
        params: [],
        desc: 'The /api/stats endpoint returns aggregate metrics: total verifications, accepted count, rejected count, and breakdown by reason (tamper, expired, replay).',
      },
    };

    document.querySelectorAll('#pg-scenarios .scenario-chip').forEach(chip => {
      chip.addEventListener('click', () => {
        const s = scenarios[chip.dataset.scenario];
        if (!s) return;
        document.querySelectorAll('#pg-scenarios .scenario-chip').forEach(c => c.classList.remove('active'));
        chip.classList.add('active');
        endpointSel.value = s.endpoint;
        if (s.body !== null) {
          bodyTa.value = s.body;
        }
        const descEl = document.getElementById('pg-scenario-desc');
        descEl.textContent = s.desc;
        descEl.classList.add('visible');
        if (s.params) {
          renderQueryParams(s.params);
        }
        updateBodyVisibility();
      });
    });

    const presets = {
      '/api/sign': [
        { label: 'Simple', body: '{ "payload": { "message": "hello" } }' },
        { label: 'Transfer', body: '{ "payload": { "amount": 500, "recipient": "alice" } }' },
        { label: 'With custom nonce', body: '{ "payload": { "action": "test" }, "nonce": "my-nonce-123" }' },
      ],
      '/api/verify': [
        { label: 'Template', body: '{ "payload": { "message": "hello" }, "timestamp": 0, "nonce": "", "tag": "" }' },
      ],
      '/api/simulate/tamper': [
        { label: 'Amount', body: '{ "payload": { "amount": 100 } }' },
        { label: 'Multi-field', body: '{ "payload": { "amount": 100, "recipient": "bob" } }' },
      ],
      '/api/simulate/replay': [
        { label: 'Transfer', body: '{ "payload": { "action": "transfer" } }' },
      ],
      '/api/simulate/expired': [
        { label: 'Ping', body: '{ "payload": { "action": "ping" } }' },
      ],
      '/api/events': [
        { label: 'All', body: null, params: [] },
        { label: 'Rejected only', body: null, params: [{ key: 'result', value: 'rejected' }] },
        { label: 'Page 1, size 5', body: null, params: [{ key: 'page', value: '1' }, { key: 'page_size', value: '5' }] },
      ],
      '/api/stats': [{ label: 'Default', body: null, params: [] }],
      '/api/health': [{ label: 'Default', body: null, params: [] }],
    };

    function renderPresets() {
      const ep = endpointSel.value;
      const list = presets[ep] || [];
      const presetEl = document.getElementById('pg-presets');
      presetEl.innerHTML = list.map((p, i) => `<span class="preset-chip" data-idx="${i}">${p.label}</span>`).join('');
      presetEl.querySelectorAll('.preset-chip').forEach((chip, i) => {
        chip.addEventListener('click', () => {
          const preset = list[i];
          if (preset.body !== null) {
            document.getElementById('pg-body').value = preset.body;
          }
          if (preset.params) {
            renderQueryParams(preset.params);
          }
          presetEl.querySelectorAll('.preset-chip').forEach(c => c.classList.remove('active'));
          chip.classList.add('active');
        });
      });
    }

    function renderQueryParams(params) {
      const container = document.getElementById('pg-query-params');
      container.innerHTML = '';
      params.forEach(p => addQueryParamRow(p.key, p.value));
    }

    function addQueryParamRow(key, value) {
      const container = document.getElementById('pg-query-params');
      const row = document.createElement('div');
      row.className = 'query-param-row';
      row.innerHTML = `
        <input type="text" placeholder="key" value="${key || ''}" class="qp-key">
        <input type="text" placeholder="value" value="${value || ''}" class="qp-val">
        <button class="icon-btn qp-remove" style="width:24px;height:24px">${icon('x')}</button>`;
      row.querySelector('.qp-remove').addEventListener('click', () => row.remove());
      container.appendChild(row);
      refreshIcons();
    }

    function updateBodyVisibility() {
      const isGet = endpointSel.value.startsWith('GET');
      bodyGroup.style.display = isGet ? 'none' : '';
      queryGroup.style.display = isGet ? '' : 'none';
      renderPresets();
      // Auto-add default params for GET
      if (isGet && document.getElementById('pg-query-params').children.length === 0) {
        renderQueryParams([]);
      }
    }

    endpointSel.addEventListener('change', updateBodyVisibility);
    document.getElementById('pg-add-param').addEventListener('click', () => addQueryParamRow('', ''));
    updateBodyVisibility();

    document.getElementById('pg-send').addEventListener('click', async () => {
      const respEl = document.getElementById('pg-response');
      respEl.textContent = 'Sending…';
      const ep = endpointSel.value;
      const method = ep.startsWith('GET') ? 'GET' : 'POST';

      let url = ep;
      let body = null;

      if (method === 'POST') {
        try { body = JSON.parse(document.getElementById('pg-body').value); }
        catch (e) { respEl.textContent = 'Invalid JSON: ' + e.message; return; }
      } else {
        // Collect query params
        const params = [];
        document.querySelectorAll('.query-param-row').forEach(row => {
          const k = row.querySelector('.qp-key').value.trim();
          const v = row.querySelector('.qp-val').value.trim();
          if (k) params.push(k + '=' + encodeURIComponent(v));
        });
        if (params.length) url += '?' + params.join('&');
      }

      const startTime = Date.now();
      try {
        const data = await api(url, method, body);
        const elapsed = Date.now() - startTime;
        const jsonStr = JSON.stringify(data, null, 2);
        const statusClass = 'ok';
        respEl.innerHTML = `<div class="pg-status-line">
          <span class="pg-status-code ${statusClass}">${method}</span>
          <span style="font-family:var(--font-mono);font-size:11px">${escapeHtml(url)}</span>
          <span style="color:var(--text-tertiary);font-size:11px">${elapsed}ms</span>
        </div>`;
        const bodyEl = document.createElement('div');
        bodyEl.className = 'pg-response-block';
        bodyEl.textContent = jsonStr;
        respEl.appendChild(bodyEl);
        pgHistory.unshift({ method, url, time: new Date().toLocaleTimeString(), status: 'ok' });
      } catch (e) {
        respEl.innerHTML = `<div class="pg-status-line">
          <span class="pg-status-code error">${method}</span>
          <span style="font-family:var(--font-mono);font-size:11px">${escapeHtml(url)}</span>
          <span style="color:var(--red);font-size:11px">ERROR</span>
        </div>`;
        const bodyEl = document.createElement('div');
        bodyEl.className = 'pg-response-block';
        bodyEl.textContent = 'Error: ' + e.message;
        respEl.appendChild(bodyEl);
        pgHistory.unshift({ method, url, time: new Date().toLocaleTimeString(), status: 'error' });
      }
      renderHistory();
    });

    function renderHistory() {
      const list = document.getElementById('pg-history-list');
      if (!pgHistory.length) {
        list.innerHTML = `<div class="state-box" style="padding:16px">${icon('history')}<p style="font-size:12px">No requests sent yet.</p></div>`;
        refreshIcons();
        return;
      }
      list.innerHTML = pgHistory.slice(0, 10).map(h => `
        <div class="history-item" data-url="${escapeAttr(h.url)}" data-method="${h.method}">
          <span class="method-badge ${h.method}">${h.method}</span>
          <span style="font-family:var(--font-mono);font-size:11px">${escapeHtml(h.url)}</span>
          <span class="time">${h.time}</span>
        </div>`).join('');
      list.querySelectorAll('.history-item').forEach(item => {
        item.addEventListener('click', () => {
          const url = item.dataset.url;
          // Set the endpoint selector
          for (const opt of endpointSel.options) {
            if (url.startsWith(opt.value)) { endpointSel.value = opt.value; updateBodyVisibility(); break; }
          }
        });
      });
      refreshIcons();
    }

    document.getElementById('pg-clear-history').addEventListener('click', () => {
      pgHistory = [];
      renderHistory();
      showToast('History cleared', '');
    });

    renderHistory();
  }

  // --- How It Works page ---------------------------------------------
  function renderHowItWorks(root) {
    const steps = [
      { title: '1. Canonicalize the Payload', body: 'The sender serializes the JSON payload with sorted keys and compact separators (no spaces). This ensures both sides compute the same signing string.' },
      { title: '2. Build the Signing String', body: 'Concatenate timestamp, nonce, and canonical payload as "{timestamp}.{nonce}.{canonical_json}". All three components are included in what gets signed.' },
      { title: '3. Compute HMAC-SHA256', body: 'The signing string is passed through HMAC-SHA256 using a shared secret key. The output hex digest is the authentication tag.' },
      { title: '4. Attach Metadata', body: 'The sender transmits the payload, timestamp, nonce, and tag to the receiver. The secret key never leaves the sender.' },
      { title: '5. Recompute the HMAC', body: 'The receiver reconstructs the same signing string from the received payload, timestamp, and nonce, then computes its own HMAC tag.' },
      { title: '6. Compare Tags (Tamper Detection)', body: 'The receiver compares the recomputed tag with the received tag using hmac.compare_digest (constant-time comparison). A mismatch means the payload was altered.' },
      { title: '7. Check Timestamp Window', body: 'The receiver verifies the timestamp is within a 60-second window of the current time. This prevents old messages from being reused.' },
      { title: '8. Check Nonce Uniqueness (Replay Prevention)', body: 'The receiver stores each nonce in a database with a UNIQUE constraint. If the nonce already exists, the request is a replay and is rejected.' },
      { title: '9. Accept or Reject', body: 'Only if all three checks pass (HMAC, timestamp, nonce) is the message accepted. The result and per-check trace are stored and returned.' },
    ];
    root.innerHTML = `<div class="card">
      <div class="card-title">The 9-Step Message Authentication Protocol</div>
      <div class="step-list">
        ${steps.map(s => `<div class="step">
          <div class="step-number">${s.title.split('.')[0]}</div>
          <div class="step-content">
            <h3>${s.title.split('. ').slice(1).join('. ')}</h3>
            <p>${s.body}</p>
          </div>
        </div>`).join('')}
      </div>
      <div class="callout">
        <strong>Important limitations:</strong>
        HMAC alone does not stop replay attacks — an attacker who captures a valid message can resend it.
        That is why we combine HMAC with a nonce uniqueness check and a timestamp window.
        HMAC also does not encrypt the payload — the message content is sent in the clear.
        For confidentiality, use TLS in transit or encrypt the payload separately.
      </div>
    </div>`;
    refreshIcons();
  }

  // --- Sidebar / mobile drawer ---------------------------------------
  function openSidebar() {
    document.getElementById('sidebar').classList.add('open');
    document.getElementById('sidebar-overlay').classList.add('active');
  }
  function closeSidebar() {
    document.getElementById('sidebar').classList.remove('open');
    document.getElementById('sidebar-overlay').classList.remove('active');
  }

  // --- Health check --------------------------------------------------
  async function checkHealth() {
    const badge = document.getElementById('health-badge');
    const text = document.getElementById('health-text');
    try {
      await api('/api/health');
      badge.classList.add('healthy');
      text.textContent = 'Backend Online';
    } catch (e) {
      text.textContent = 'Backend Offline';
    }
  }

  // --- Init -----------------------------------------------------------
  function init() {
    document.body.style.display = 'flex';
    document.querySelectorAll('.nav-item').forEach(el => {
      el.addEventListener('click', (e) => { e.preventDefault(); navigate(el.dataset.page); });
    });
    document.getElementById('menu-toggle').addEventListener('click', openSidebar);
    document.getElementById('sidebar-close').addEventListener('click', closeSidebar);
    document.getElementById('sidebar-overlay').addEventListener('click', closeSidebar);
    const hash = location.hash.replace('#', '');
    navigate(PAGES.includes(hash) ? hash : 'overview');
    checkHealth();
    setInterval(checkHealth, 30000);
    refreshIcons();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
