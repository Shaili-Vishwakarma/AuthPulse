/* AuthPulse – Attack Simulator page */
import { api, icon, refreshIcons, showToast, renderCheckItem, renderPayloadDiff, sleep } from './core.js';

export function renderAttackSim(root) {
  root.innerHTML = `
    <div class="page-intro">
      <strong>Attack Simulator</strong> is a visual playground. Pick an attack type, configure the
      parameters, hit "Run Attack Simulation", and watch the message travel through the pipeline in
      real time — from sender to wire to receiver, with each check lighting up as it passes or fails.
      Every result comes from the real backend. Try different parameter combinations.
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

function loadSim(type) {
  const container = document.getElementById('sim-content');
  if (type === 'tamper') renderTamperSim(container);
  else if (type === 'replay') renderReplaySim(container);
  else renderExpiredSim(container);
  refreshIcons();
}

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

function setPipelineNode(index, nodeState, detail, badgeText, badgeIcon) {
  const node = document.querySelector(`[data-node="${index}"]`);
  if (!node) return;
  node.classList.remove('active', 'done', 'fail');
  node.classList.add(nodeState);
  if (detail !== undefined) { const el = node.querySelector('[data-detail]'); if (el) el.textContent = detail; }
  if (badgeText !== undefined) {
    const badge = node.querySelector(`[data-badge="${index}"]`);
    if (badge) {
      badge.className = 'pipeline-check-result ' + (nodeState === 'fail' ? 'fail' : nodeState === 'done' ? 'pass' : 'pending');
      badge.innerHTML = (badgeIcon || icon('loader')) + ' ' + badgeText;
    }
  }
  if (index > 0) {
    const conn = document.querySelector(`[data-connector="${index - 1}"]`);
    if (conn) { conn.classList.remove('active', 'done'); conn.classList.add(nodeState === 'done' ? 'done' : 'active'); }
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

// ---- TAMPER ----
function renderTamperSim(container) {
  const defaultPayload = JSON.stringify({ "amount": 1000, "recipient": "bob", "currency": "USD" }, null, 2);
  container.innerHTML = `
    <div class="card">
      <div class="section-title">Configure the Attack</div>
      <div class="tab-tip">
        ${icon('lightbulb')}
        <span><strong>Tamper attack:</strong> The attacker modifies the payload after it's signed, but the HMAC tag stays the same. Try tampering different fields and values to see how the HMAC check always catches it.</span>
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
          <div class="endpoint-box sender"><div class="ep-label">Sender</div><div class="ep-name">Signs &amp; sends</div></div>
          <div class="wire-visual"><div class="wire-line" id="tamper-wire"></div></div>
          <div class="endpoint-box receiver" id="tamper-receiver"><div class="ep-label">Receiver</div><div class="ep-name">Verifies</div></div>
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
        <div class="action-row"><button id="tamper-restart-btn" class="btn">${icon('rotate-ccw')} Run Again</button></div>
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

  setPipelineNode(0, 'active', '', 'signing…');
  await sleep(300);
  try {
    const signed = await api('/api/sign', 'POST', { payload });
    setPipelineNode(0, 'done', 'Tag: ' + signed.tag.slice(0, 24) + '…', 'signed', icon('check'));
    await sleep(400);

    setPipelineNode(1, 'active', '', 'transmitting…');
    document.getElementById('tamper-wire').classList.add('active');
    await sleep(600);
    document.getElementById('tamper-wire').classList.remove('active');
    setPipelineNode(1, 'done', 'Payload + timestamp + nonce + tag sent', 'delivered', icon('check'));
    await sleep(300);

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

    setPipelineNode(3, 'active', '', 'checking…');
    document.getElementById('tamper-receiver').classList.add('active');
    await sleep(300);
    const result = await api('/api/verify', 'POST', {
      request_id: signed.request_id, payload: tamperedPayload,
      timestamp: signed.timestamp, nonce: signed.nonce, tag: signed.tag,
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

    setPipelineNode(4, 'active', '', 'deciding…');
    await sleep(300);
    const accepted = result.result === 'accepted';
    setPipelineNode(4, accepted ? 'done' : 'fail', result.result.toUpperCase() + ' — ' + result.reason, result.reason, accepted ? icon('check-circle') : icon('x-circle'));

    document.getElementById('tamper-result-area').innerHTML = `
      ${diffHtml}
      <div class="verdict-banner ${result.result}">
        ${accepted ? icon('check-circle') : icon('x-circle')}
        ${accepted ? 'Accepted' : 'Rejected'} — ${result.reason}
      </div>
      <div class="trace-list">${result.checks.map(c => renderCheckItem(c)).join('')}</div>`;
    refreshIcons();
  } catch (e) { showToast(e.message, 'error'); }
  finally { btn.disabled = false; refreshIcons(); }
}

// ---- REPLAY ----
function renderReplaySim(container) {
  const defaultPayload = JSON.stringify({ "action": "transfer", "amount": 500, "to": "charlie" }, null, 2);
  container.innerHTML = `
    <div class="card">
      <div class="section-title">Configure the Attack</div>
      <div class="tab-tip">
        ${icon('lightbulb')}
        <span><strong>Replay attack:</strong> The attacker captures a valid signed message and resends it. The first request passes all checks, but the second fails the nonce uniqueness check. Try replay count 5 to watch each attempt animate — only the first succeeds.</span>
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
          <div class="endpoint-box sender"><div class="ep-label">Attacker</div><div class="ep-name">Captures &amp; resends</div></div>
          <div class="wire-visual"><div class="wire-line" id="replay-wire"></div></div>
          <div class="endpoint-box receiver" id="replay-receiver"><div class="ep-label">Receiver</div><div class="ep-name">Verifies each attempt</div></div>
        </div>
        <div id="replay-attempts"></div>
        <div class="action-row"><button id="replay-restart-btn" class="btn">${icon('rotate-ccw')} Run Again</button></div>
      </div>
    </div>`;
  refreshIcons();

  document.getElementById('replay-count').addEventListener('input', e => { document.getElementById('replay-count-val').textContent = e.target.value; });
  document.getElementById('replay-delay').addEventListener('input', e => { document.getElementById('replay-delay-val').textContent = e.target.value + 'ms'; });
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
    await animateReplayAttempt(`replay-pipeline-${i}`, i, signed);
    if (delay > 0 && i < count - 1) await sleep(delay);
  }
  btn.disabled = false;
  refreshIcons();
}

async function animateReplayAttempt(pipeId, attemptIdx, signed) {
  const nodes = document.querySelectorAll(`#${pipeId} .pipeline-node`);
  const conns = document.querySelectorAll(`#${pipeId} .pipeline-connector`);
  const badges = document.querySelectorAll(`#${pipeId} .pipeline-check-result`);

  function setLocal(idx, s, detail, badgeText, badgeIcon) {
    const node = nodes[idx]; if (!node) return;
    node.classList.remove('active', 'done', 'fail'); node.classList.add(s);
    if (detail !== undefined) { const el = node.querySelector('.pipeline-node-detail'); if (el) el.textContent = detail; }
    if (badgeText !== undefined) {
      const badge = badges[idx];
      badge.className = 'pipeline-check-result ' + (s === 'fail' ? 'fail' : s === 'done' ? 'pass' : 'pending');
      badge.innerHTML = (badgeIcon || icon('loader')) + ' ' + badgeText;
    }
    if (idx > 0) { const c = conns[idx - 1]; if (c) { c.classList.remove('active', 'done'); c.classList.add(s === 'done' ? 'done' : 'active'); } }
    refreshIcons();
  }

  setLocal(0, 'active', '', 'sending…');
  document.getElementById('replay-wire').classList.add('active');
  await sleep(500);
  document.getElementById('replay-wire').classList.remove('active');
  setLocal(0, 'done', 'Nonce: ' + signed.nonce.slice(0, 16) + '…', 'sent', icon('check'));
  await sleep(300);

  const result = await api('/api/verify', 'POST', {
    request_id: signed.request_id, payload: signed.payload,
    timestamp: signed.timestamp, nonce: signed.nonce, tag: signed.tag,
  });

  for (let c = 0; c < result.checks.length; c++) {
    const check = result.checks[c];
    setLocal(c + 1, 'active', '', 'checking…');
    await sleep(400);
    if (check.status === 'pass') {
      setLocal(c + 1, 'done', check.detail, 'pass', icon('check'));
    } else {
      setLocal(c + 1, 'fail', check.detail, 'FAIL', icon('x'));
      document.getElementById('replay-receiver').classList.add('fail');
    }
    await sleep(300);
  }

  const verdictIdx = result.checks.length + 1;
  const accepted = result.result === 'accepted';
  setLocal(verdictIdx, 'active', '', 'deciding…');
  await sleep(300);
  setLocal(verdictIdx, accepted ? 'done' : 'fail', result.result.toUpperCase() + ' — ' + result.reason, result.reason, accepted ? icon('check-circle') : icon('x-circle'));

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

// ---- EXPIRED ----
function renderExpiredSim(container) {
  const defaultPayload = JSON.stringify({ "action": "ping", "server": "node-1" }, null, 2);
  container.innerHTML = `
    <div class="card">
      <div class="section-title">Configure the Attack</div>
      <div class="tab-tip">
        ${icon('lightbulb')}
        <span><strong>Expired message:</strong> The HMAC tag is valid, but the timestamp window check fails. Try sliding the age to under 60s — the message should pass!</span>
      </div>
      <div class="sim-params">
        <div class="param-row">
          <span class="param-label">Timestamp age:</span>
          <input type="range" id="expired-age" min="10" max="600" value="120" step="10">
          <span class="param-value" id="expired-age-val">120s</span>
        </div>
        <div class="param-row">
          <span class="param-label" style="color:var(--text-tertiary)">Window is ±60s — anything above 60s will fail</span>
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
          <div class="endpoint-box sender"><div class="ep-label">Sender</div><div class="ep-name">Signs with old clock</div></div>
          <div class="wire-visual"><div class="wire-line" id="expired-wire"></div></div>
          <div class="endpoint-box receiver" id="expired-receiver"><div class="ep-label">Receiver</div><div class="ep-name">Verifies</div></div>
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
        <div class="action-row"><button id="expired-restart-btn" class="btn">${icon('rotate-ccw')} Run Again</button></div>
      </div>
    </div>`;
  refreshIcons();

  document.getElementById('expired-age').addEventListener('input', e => { document.getElementById('expired-age-val').textContent = e.target.value + 's'; });
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

  setPipelineNode(0, 'active', '', 'signing…');
  await sleep(300);
  const oldTs = (Date.now() / 1000) - ageSeconds;
  const signed = await api('/api/sign', 'POST', { payload, timestamp: oldTs });
  setPipelineNode(0, 'done', 'Timestamp: ' + oldTs.toFixed(1) + ' (' + ageSeconds + 's old)', 'signed', icon('check'));
  await sleep(400);

  setPipelineNode(1, 'active', '', 'transmitting…');
  document.getElementById('expired-wire').classList.add('active');
  await sleep(600);
  document.getElementById('expired-wire').classList.remove('active');
  setPipelineNode(1, 'done', 'Message delivered', 'delivered', icon('check'));
  await sleep(300);

  document.getElementById('expired-receiver').classList.add('active');
  const result = await api('/api/verify', 'POST', {
    request_id: signed.request_id, payload: signed.payload,
    timestamp: signed.timestamp, nonce: signed.nonce, tag: signed.tag,
  });

  setPipelineNode(2, 'active', '', 'checking…');
  await sleep(400);
  const hmacCheck = result.checks[0];
  setPipelineNode(2, hmacCheck.status === 'pass' ? 'done' : 'fail', hmacCheck.detail, hmacCheck.status, hmacCheck.status === 'pass' ? icon('check') : icon('x'));
  await sleep(400);

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
