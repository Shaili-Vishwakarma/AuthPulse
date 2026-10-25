/* AuthPulse – Protocol Visualizer page */
import { api, icon, refreshIcons, escapeHtml } from './core.js';

export function renderProtocolVisualizer(root) {
  root.innerHTML = `
    <div class="pv-header">
      <div>
        <h2>Protocol Visualizer</h2>
        <div class="pv-subtitle">Watch how AuthPulse authenticates messages, detects tampering, and prevents replay attacks.</div>
      </div>
      <span class="pv-badge">HMAC-SHA256</span>
    </div>

    <div class="pv-scenario-row">
      <button class="scenario-chip active" data-pv-scenario="valid">${icon('check-circle')} Valid Message</button>
      <button class="scenario-chip" data-pv-scenario="tamper">${icon('pencil')} Message Tampering</button>
      <button class="scenario-chip" data-pv-scenario="replay">${icon('repeat')} Replay Attack</button>
    </div>

    <div class="pv-progress" id="pv-progress"></div>

    <div class="pv-diagram" id="pv-diagram">
      <div class="pv-region sender">
        <div class="pv-region-header">
          <div class="pv-region-icon">${icon('monitor')}</div>
          <div><div class="pv-region-title">SENDER</div><div class="pv-region-sub">Client-side operations</div></div>
        </div>
        <div class="pv-comp code-editor" data-comp="payload">
          <div class="pv-comp-row"><div class="pv-comp-icon">${icon('file-text')}</div><div class="pv-comp-title">Message Payload</div><div class="pv-comp-status waiting" data-status="payload">Waiting</div></div>
          <div class="pv-comp-value" id="pv-payload"></div>
        </div>
        <div class="pv-connector"></div>
        <div class="pv-comp" data-comp="canonical">
          <div class="pv-comp-row"><div class="pv-comp-icon">${icon('list')}</div><div class="pv-comp-title">Canonicalize</div><div class="pv-comp-status waiting" data-status="canonical">Waiting</div></div>
          <div class="pv-comp-value" id="pv-canonical"></div>
        </div>
        <div class="pv-connector"></div>
        <div class="pv-comp" data-comp="signing-string">
          <div class="pv-comp-row"><div class="pv-comp-icon">${icon('link')}</div><div class="pv-comp-title">Signing String</div><div class="pv-comp-status waiting" data-status="signing-string">Waiting</div></div>
          <div class="pv-comp-value" id="pv-signing-string"></div>
        </div>
        <div class="pv-connector"></div>
        <div class="pv-comp" data-comp="hmac">
          <div class="pv-comp-row"><div class="pv-comp-icon">${icon('key')}</div><div class="pv-comp-title">HMAC-SHA256 Generation</div><div class="pv-comp-status waiting" data-status="hmac">Waiting</div></div>
          <div class="pv-comp-value" id="pv-hmac-tag"></div>
        </div>
        <div class="pv-secret">${icon('key-round')}<span>Shared Secret:</span><span class="pv-secret-val">••••••••••••</span></div>
      </div>

      <div class="pv-network">
        <div class="pv-network-label">Network</div>
        <div class="pv-wire-vert" id="pv-wire-vert"></div>
        <div class="pv-wire-arrow"></div>
        <div class="pv-packet" id="pv-packet">
          <div>REQUEST</div>
          <div style="font-size:8px;color:#8a93a0;margin-top:2px">payload · ts · nonce · tag</div>
        </div>
      </div>

      <div class="pv-region receiver">
        <div class="pv-region-header">
          <div class="pv-region-icon">${icon('server')}</div>
          <div><div class="pv-region-title">RECEIVER</div><div class="pv-region-sub">Server-side verification</div></div>
        </div>
        <div class="pv-comp" data-comp="received">
          <div class="pv-comp-row"><div class="pv-comp-icon">${icon('inbox')}</div><div class="pv-comp-title">Received Message</div><div class="pv-comp-status waiting" data-status="received">Waiting</div></div>
          <div class="pv-comp-value" id="pv-received"></div>
        </div>
        <div class="pv-connector"></div>
        <div class="pv-comp" data-comp="recompute">
          <div class="pv-comp-row"><div class="pv-comp-icon">${icon('refresh-cw')}</div><div class="pv-comp-title">Recompute HMAC</div><div class="pv-comp-status waiting" data-status="recompute">Waiting</div></div>
          <div class="pv-comp-value" id="pv-recompute"></div>
        </div>
        <div class="pv-connector"></div>
        <div class="pv-comp" data-comp="compare">
          <div class="pv-comp-row"><div class="pv-comp-icon">${icon('git-compare')}</div><div class="pv-comp-title">Compare Tags</div><div class="pv-comp-status waiting" data-status="compare">Waiting</div></div>
          <div class="pv-comp-value" id="pv-compare"></div>
        </div>
        <div class="pv-connector"></div>
        <div class="pv-comp" data-comp="timestamp-check">
          <div class="pv-comp-row"><div class="pv-comp-icon">${icon('clock')}</div><div class="pv-comp-title">Timestamp Window (±60s)</div><div class="pv-comp-status waiting" data-status="timestamp-check">Waiting</div></div>
          <div class="pv-comp-value" id="pv-timestamp-check"></div>
        </div>
        <div class="pv-connector"></div>
        <div class="pv-comp" data-comp="nonce-check">
          <div class="pv-comp-row"><div class="pv-comp-icon">${icon('fingerprint')}</div><div class="pv-comp-title">Nonce Uniqueness</div><div class="pv-comp-status waiting" data-status="nonce-check">Waiting</div></div>
          <div class="pv-comp-value" id="pv-nonce-check"></div>
        </div>
        <div class="pv-connector"></div>
        <div class="pv-comp" data-comp="verdict">
          <div class="pv-comp-row"><div class="pv-comp-icon">${icon('shield-check')}</div><div class="pv-comp-title">Final Decision</div><div class="pv-comp-status waiting" data-status="verdict">Waiting</div></div>
          <div class="pv-comp-value" id="pv-verdict"></div>
        </div>
        <div class="pv-secret">${icon('key-round')}<span>Shared Secret:</span><span class="pv-secret-val">••••••••••••</span></div>
      </div>
    </div>

    <div class="pv-inspector" id="pv-inspector">
      <div class="pv-loading">Select a scenario and click Next to begin.</div>
    </div>

    <div class="pv-controls">
      <span class="pv-position" id="pv-position">STEP 01 OF 09</span>
      <button class="btn" id="pv-prev">${icon('chevron-left')} Previous</button>
      <button class="btn btn-primary" id="pv-play">${icon('play')} Play</button>
      <button class="btn" id="pv-pause" style="display:none">${icon('pause')} Pause</button>
      <button class="btn" id="pv-restart">${icon('rotate-ccw')} Restart</button>
      <button class="btn" id="pv-replay">${icon('repeat-2')} Replay Step</button>
      <button class="btn btn-primary" id="pv-next">Next ${icon('chevron-right')}</button>
    </div>`;
  refreshIcons();

  const STEP_COUNT = 9;
  const stepDefs = [
    { title: 'Canonicalize the Payload', icon: 'list', desc: 'The sender serializes the JSON payload with sorted keys and compact separators (no spaces).', significance: 'JSON objects can be serialized differently. Canonicalization ensures both parties calculate the same tag.' },
    { title: 'Build the Signing String', icon: 'link', desc: 'Concatenate timestamp, nonce, and canonical payload as "{timestamp}.{nonce}.{canonical_json}".', significance: 'If the timestamp or nonce changes, the reconstructed signing string changes, causing HMAC verification to fail.' },
    { title: 'Compute HMAC-SHA256', icon: 'key', desc: 'The signing string is passed through HMAC-SHA256 using the shared secret key. The secret key never leaves the sender.', significance: 'HMAC combines a cryptographic hash with a secret key. The secret is not transmitted.' },
    { title: 'Attach Metadata & Transmit', icon: 'send', desc: 'The sender assembles payload, timestamp, nonce, and tag, then sends them to the receiver.', significance: 'The receiver gets the message and metadata, but not the secret. HMAC does not encrypt — use HTTPS/TLS for confidentiality.' },
    { title: 'Recompute HMAC at Receiver', icon: 'refresh-cw', desc: 'The receiver canonicalizes the received payload, reconstructs the signing string, and calculates the expected HMAC independently.', significance: 'The receiver must verify independently rather than trusting the sender\'s tag.' },
    { title: 'Compare Tags & Detect Tampering', icon: 'git-compare', desc: 'The receiver compares the recomputed tag with the received tag using hmac.compare_digest (constant-time comparison).', significance: 'A matching HMAC proves the message came from someone with the secret and was not modified. A valid HMAC does not prove freshness.' },
    { title: 'Check Timestamp Freshness', icon: 'clock', desc: 'The receiver checks if the timestamp is within ±60 seconds of the current time.', significance: 'Timestamp validation rejects old requests. It cannot prevent replay alone — an attacker may resend while the timestamp is still valid.' },
    { title: 'Check Nonce Uniqueness', icon: 'fingerprint', desc: 'The receiver checks if the nonce has already been used. A duplicate means a replay attempt.', significance: 'Once a request passes validation, its nonce is recorded. The database prevents two concurrent requests with the same nonce from both being accepted.' },
    { title: 'Accept or Reject', icon: 'check-circle', desc: 'The message is accepted only when HMAC, timestamp, and nonce uniqueness all pass.', significance: 'The final decision and verification trace are recorded in the event log.' },
  ];

  let pvState = {
    step: 0, scenario: 'valid', playing: false, playTimer: null,
    completedSteps: new Set(), failedStep: null, signedMsg: null, verifyResult: null,
  };

  async function runScenario(scenario) {
    const payload = { amount: 1000, action: 'transfer', sender: 'Client-A' };
    const signed = await api('/api/sign', 'POST', { payload });
    pvState.signedMsg = signed;
    if (scenario === 'valid') {
      pvState.verifyResult = await api('/api/verify', 'POST', { request_id: signed.request_id, payload: signed.payload, timestamp: signed.timestamp, nonce: signed.nonce, tag: signed.tag });
    } else if (scenario === 'tamper') {
      const tampered = { ...signed.payload, amount: 99999 };
      pvState.verifyResult = await api('/api/verify', 'POST', { request_id: signed.request_id, payload: tampered, timestamp: signed.timestamp, nonce: signed.nonce, tag: signed.tag });
    } else if (scenario === 'replay') {
      await api('/api/verify', 'POST', { request_id: signed.request_id, payload: signed.payload, timestamp: signed.timestamp, nonce: signed.nonce, tag: signed.tag });
      pvState.verifyResult = await api('/api/verify', 'POST', { request_id: signed.request_id, payload: signed.payload, timestamp: signed.timestamp, nonce: signed.nonce, tag: signed.tag });
    }
  }

  function canonicalJsonFrontend(obj) {
    if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
    const keys = Object.keys(obj).sort();
    return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJsonFrontend(obj[k])).join(',') + '}';
  }

  function fillDiagramValues() {
    const s = pvState.signedMsg, r = pvState.verifyResult;
    if (!s) return;
    document.getElementById('pv-payload').textContent = JSON.stringify(s.payload, null, 2);
    document.getElementById('pv-canonical').textContent = canonicalJsonFrontend(s.payload);
    document.getElementById('pv-signing-string').textContent = s.signing_string;
    document.getElementById('pv-hmac-tag').textContent = s.tag;
    document.getElementById('pv-received').textContent = pvState.scenario === 'tamper' ? JSON.stringify({ amount: 99999, action: 'transfer', sender: 'Client-A' }, null, 2) : JSON.stringify(s.payload, null, 2);
    if (r && r.checks[0]) document.getElementById('pv-recompute').textContent = r.checks[0].expected;
    if (r && r.checks[0]) document.getElementById('pv-compare').textContent = r.checks[0].status === 'pass' ? 'MATCH — tags are identical' : 'MISMATCH — expected: ' + r.checks[0].expected.slice(0, 20) + '… received: ' + r.checks[0].received.slice(0, 20) + '…';
    document.getElementById('pv-timestamp-check').textContent = (r && r.checks.length > 1 && r.checks[1]) ? r.checks[1].detail : 'Not reached';
    document.getElementById('pv-nonce-check').textContent = (r && r.checks.length > 2 && r.checks[2]) ? r.checks[2].detail : 'Not reached';
    if (r) document.getElementById('pv-verdict').textContent = r.result.toUpperCase() + ' — ' + r.reason;
  }

  function setStatus(compName, cls, text) {
    const el = document.querySelector(`[data-status="${compName}"]`);
    if (el) { el.className = 'pv-comp-status ' + cls; el.textContent = text; }
  }

  function highlightComp(name) {
    const el = document.querySelector(`[data-comp="${name}"]`); if (el) el.classList.add('highlighted');
  }

  function colorCheckComp(compName, checkIdx) {
    if (!pvState.verifyResult) return;
    const check = pvState.verifyResult.checks[checkIdx]; if (!check) return;
    const el = document.querySelector(`[data-comp="${compName}"]`);
    if (el) el.classList.add(check.status === 'pass' ? 'pass' : 'fail');
  }

  function activateConnector(idx) {
    const connectors = document.querySelectorAll('.pv-region.sender .pv-connector');
    if (connectors[idx]) connectors[idx].classList.add('active');
  }

  function highlightStep(step) {
    document.querySelectorAll('.pv-comp').forEach(el => el.classList.remove('highlighted', 'pass', 'fail'));
    document.querySelectorAll('.pv-comp-status').forEach(el => { el.className = 'pv-comp-status waiting'; el.textContent = 'Waiting'; });
    document.querySelectorAll('.pv-connector').forEach(el => el.classList.remove('active'));
    const wireVert = document.getElementById('pv-wire-vert');
    const packet = document.getElementById('pv-packet');
    if (wireVert) wireVert.style.background = '#e2e6ed';
    if (packet) packet.classList.remove('visible');

    const completedMap = ['payload', 'canonical', 'signing-string', 'hmac', 'received', 'recompute', 'compare', 'timestamp-check', 'nonce-check', 'verdict'];
    pvState.completedSteps.forEach(s => {
      const compName = completedMap[s]; if (!compName) return;
      const statusEl = document.querySelector(`[data-status="${compName}"]`);
      if (statusEl && s !== step) {
        const r = pvState.verifyResult;
        if (s === 5 && r && r.checks[0]) { statusEl.className = 'pv-comp-status ' + r.checks[0].status; statusEl.textContent = r.checks[0].status === 'pass' ? 'Passed' : 'Failed'; }
        else if (s === 6 && r && r.checks[1]) { statusEl.className = 'pv-comp-status ' + r.checks[1].status; statusEl.textContent = r.checks[1].status === 'pass' ? 'Passed' : 'Failed'; }
        else if (s === 7 && r && r.checks[2]) { statusEl.className = 'pv-comp-status ' + r.checks[2].status; statusEl.textContent = r.checks[2].status === 'pass' ? 'Passed' : 'Failed'; }
        else if (s === 8 && r) { statusEl.className = 'pv-comp-status ' + (r.result === 'accepted' ? 'pass' : 'fail'); statusEl.textContent = r.result === 'accepted' ? 'Accepted' : 'Rejected'; }
        else { statusEl.className = 'pv-comp-status pass'; statusEl.textContent = 'Done'; }
      }
    });

    if (pvState.failedStep !== null) {
      for (let i = pvState.failedStep + 1; i < STEP_COUNT; i++) {
        const statusEl = document.querySelector(`[data-status="${completedMap[i]}"]`);
        if (statusEl) { statusEl.className = 'pv-comp-status notreached'; statusEl.textContent = 'Not reached'; }
      }
    }

    const actions = [
      () => { highlightComp('payload'); setStatus('payload', 'active', 'In progress'); highlightComp('canonical'); setStatus('canonical', 'active', 'In progress'); activateConnector(0); },
      () => { highlightComp('signing-string'); setStatus('signing-string', 'active', 'In progress'); highlightComp('canonical'); setStatus('canonical', 'active', 'Done'); activateConnector(1); },
      () => { highlightComp('hmac'); setStatus('hmac', 'active', 'In progress'); activateConnector(2); },
      () => { highlightComp('received'); setStatus('received', 'active', 'Receiving'); if (wireVert) wireVert.style.background = '#2457D6'; if (packet) packet.classList.add('visible'); activateConnector(3); },
      () => { highlightComp('recompute'); setStatus('recompute', 'active', 'In progress'); activateConnector(4); },
      () => { highlightComp('compare'); setStatus('compare', 'active', 'Checking'); colorCheckComp('compare', 0); activateConnector(5); },
      () => { highlightComp('timestamp-check'); setStatus('timestamp-check', 'active', 'Checking'); colorCheckComp('timestamp-check', 1); activateConnector(6); },
      () => { highlightComp('nonce-check'); setStatus('nonce-check', 'active', 'Checking'); colorCheckComp('nonce-check', 2); activateConnector(7); },
      () => {
        highlightComp('verdict'); setStatus('verdict', 'active', 'Deciding');
        if (pvState.verifyResult) {
          const vc = document.querySelector('[data-comp="verdict"]');
          if (vc) vc.classList.add(pvState.verifyResult.result === 'accepted' ? 'pass' : 'fail');
          const vs = document.querySelector('[data-status="verdict"]');
          if (vs) { vs.className = 'pv-comp-status ' + (pvState.verifyResult.result === 'accepted' ? 'pass' : 'fail'); vs.textContent = pvState.verifyResult.result === 'accepted' ? 'Accepted' : 'Rejected'; }
        }
      },
    ];
    if (actions[step]) actions[step]();
    const posEl = document.getElementById('pv-position');
    if (posEl) posEl.textContent = `STEP ${String(step + 1).padStart(2, '0')} OF 09`;
  }

  function renderInspector(step) {
    const def = stepDefs[step], r = pvState.verifyResult;
    let inputHtml = '', operationHtml = '', outputHtml = '';
    if (step === 0 && pvState.signedMsg) { inputHtml = `<div class="pv-ins-code">${JSON.stringify(pvState.signedMsg.payload, null, 2)}</div>`; operationHtml = 'Sort keys, compact separators (no whitespace)'; outputHtml = `<div class="pv-ins-code">${canonicalJsonFrontend(pvState.signedMsg.payload)}</div>`; }
    else if (step === 1 && pvState.signedMsg) { inputHtml = 'Timestamp, Nonce, Canonical JSON'; operationHtml = 'Concatenate as {timestamp}.{nonce}.{canonical_json}'; outputHtml = `<div class="pv-ins-code">${escapeHtml(pvState.signedMsg.signing_string)}</div>`; }
    else if (step === 2 && pvState.signedMsg) { inputHtml = 'Canonical signing string + Shared secret (server-side)'; operationHtml = 'HMAC-SHA256'; outputHtml = `<div class="pv-ins-code">${pvState.signedMsg.tag}</div>`; }
    else if (step === 3 && pvState.signedMsg) { inputHtml = 'Payload, timestamp, nonce, tag'; operationHtml = 'Assemble request envelope and transmit'; outputHtml = `<div class="pv-ins-code">{"payload":{...},"timestamp":${pvState.signedMsg.timestamp},"nonce":"${pvState.signedMsg.nonce.slice(0,16)}...","tag":"${pvState.signedMsg.tag.slice(0,20)}..."}</div>`; }
    else if (step === 4 && r && r.checks[0]) { inputHtml = 'Received payload + Shared secret'; operationHtml = 'Recompute HMAC-SHA256 independently'; outputHtml = `<div class="pv-ins-code">${r.checks[0].expected}</div>`; }
    else if (step === 5 && r && r.checks[0]) { const c = r.checks[0]; inputHtml = `Received: ${c.received.slice(0,24)}…\nExpected: ${c.expected.slice(0,24)}…`; operationHtml = 'hmac.compare_digest (constant-time)'; outputHtml = `<div class="pv-ins-result ${c.status}">${c.status === 'pass' ? icon('check') : icon('x')} ${c.status === 'pass' ? 'MATCH' : 'MISMATCH'} — ${c.detail}</div>`; }
    else if (step === 6 && r) { const c = r.checks[1]; if (c) { inputHtml = 'Request timestamp vs server time'; operationHtml = 'abs(now - timestamp) <= 60s'; outputHtml = `<div class="pv-ins-result ${c.status}">${c.status === 'pass' ? icon('check') : icon('x')} ${c.detail}</div>`; } else { inputHtml = 'Not reached — HMAC failed first'; operationHtml = 'Skipped'; outputHtml = `<div class="pv-ins-result fail">${icon('x')} Not executed</div>`; } }
    else if (step === 7 && r) { const c = r.checks[2]; if (c) { inputHtml = `Nonce: ${c.nonce || 'N/A'}`; operationHtml = 'SQLite UNIQUE constraint insert'; outputHtml = `<div class="pv-ins-result ${c.status}">${c.status === 'pass' ? icon('check') : icon('x')} ${c.detail}</div>`; } else { inputHtml = 'Not reached — earlier check failed'; operationHtml = 'Skipped'; outputHtml = `<div class="pv-ins-result fail">${icon('x')} Not executed</div>`; } }
    else if (step === 8 && r) { const accepted = r.result === 'accepted'; inputHtml = `HMAC: ${r.checks[0]?.status || 'N/A'} · Timestamp: ${r.checks[1]?.status || 'N/A'} · Nonce: ${r.checks[2]?.status || 'N/A'}`; operationHtml = 'Combine all check results'; outputHtml = `<div class="pv-ins-result ${accepted ? 'pass' : 'fail'}">${accepted ? icon('check-circle') : icon('x-circle')} ${r.result.toUpperCase()} — ${r.reason}</div>`; }

    let html = `<div class="pv-ins-header"><span class="pv-ins-step">STEP ${String(step + 1).padStart(2, '0')} / 09</span><span class="pv-ins-title">${def.title.toUpperCase()}</span></div><div class="pv-ins-body">${def.desc}</div>`;
    if (inputHtml || operationHtml || outputHtml) {
      html += `<div class="pv-ins-grid"><div class="pv-ins-section"><div class="pv-ins-section-label">Input</div><div class="pv-ins-body">${inputHtml}</div></div><div class="pv-ins-section"><div class="pv-ins-section-label">Operation</div><div class="pv-ins-body">${operationHtml}</div></div><div class="pv-ins-section"><div class="pv-ins-section-label">Output</div>${outputHtml}</div><div class="pv-ins-section"><div class="pv-ins-section-label">Security Purpose</div><div class="pv-ins-body">${def.significance}</div></div></div>`;
    } else {
      html += `<div class="pv-ins-section"><div class="pv-ins-section-label">Security Significance</div><div class="pv-ins-body">${def.significance}</div></div>`;
    }
    document.getElementById('pv-inspector').innerHTML = html;
    refreshIcons();
  }

  function renderProgress() {
    const progress = document.getElementById('pv-progress');
    const labels = ['Payload', 'Signing', 'HMAC', 'Transmit', 'Recompute', 'Compare', 'Timestamp', 'Nonce', 'Decision'];
    let html = '';
    for (let i = 0; i < STEP_COUNT; i++) {
      const cls = ['pv-step-dot', pvState.completedSteps.has(i) ? 'completed' : '', i === pvState.step ? 'active' : '', pvState.failedStep === i ? 'failed' : ''].filter(Boolean).join(' ');
      html += `<div class="${cls}" data-step="${i}"><div class="pv-step-circle">${String(i + 1).padStart(2, '0')}</div><div class="pv-step-label">${labels[i]}</div></div>`;
      if (i < STEP_COUNT - 1) html += `<div class="pv-step-connector ${pvState.completedSteps.has(i) ? 'done' : ''}"></div>`;
    }
    progress.innerHTML = html;
    progress.querySelectorAll('.pv-step-dot').forEach(dot => dot.addEventListener('click', () => goToStep(parseInt(dot.dataset.step))));
    refreshIcons();
  }

  function goToStep(step) {
    if (step < 0 || step >= STEP_COUNT) return;
    if (pvState.failedStep !== null && step > pvState.failedStep) return;
    pvState.step = step;
    for (let i = 0; i < step; i++) { if (pvState.failedStep !== i) pvState.completedSteps.add(i); }
    if (pvState.verifyResult) {
      const r = pvState.verifyResult;
      if (step === 5 && r.checks[0] && r.checks[0].status === 'fail') pvState.failedStep = 5;
      else if (step === 6 && r.checks[1] && r.checks[1].status === 'fail') pvState.failedStep = 6;
      else if (step === 7 && r.checks[2] && r.checks[2].status === 'fail') pvState.failedStep = 7;
    }
    highlightStep(step); renderInspector(step); renderProgress();
  }

  function startPlayback() {
    pvState.playing = true;
    document.getElementById('pv-play').style.display = 'none';
    document.getElementById('pv-pause').style.display = 'inline-flex';
    pvState.playTimer = setInterval(() => { if (pvState.step < STEP_COUNT - 1) goToStep(pvState.step + 1); else stopPlayback(); }, 2500);
  }

  function stopPlayback() {
    pvState.playing = false;
    document.getElementById('pv-play').style.display = 'inline-flex';
    document.getElementById('pv-pause').style.display = 'none';
    if (pvState.playTimer) { clearInterval(pvState.playTimer); pvState.playTimer = null; }
  }

  document.getElementById('pv-prev').addEventListener('click', () => { if (pvState.step > 0) goToStep(pvState.step - 1); });
  document.getElementById('pv-next').addEventListener('click', () => { if (pvState.step < STEP_COUNT - 1) goToStep(pvState.step + 1); else stopPlayback(); });
  document.getElementById('pv-play').addEventListener('click', startPlayback);
  document.getElementById('pv-pause').addEventListener('click', stopPlayback);
  document.getElementById('pv-restart').addEventListener('click', () => { stopPlayback(); pvState.step = 0; pvState.completedSteps.clear(); pvState.failedStep = null; goToStep(0); });
  document.getElementById('pv-replay').addEventListener('click', () => goToStep(pvState.step));

  document.querySelectorAll('[data-pv-scenario]').forEach(btn => {
    btn.addEventListener('click', async () => {
      document.querySelectorAll('[data-pv-scenario]').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      pvState.scenario = btn.dataset.pvScenario;
      pvState.step = 0; pvState.completedSteps.clear(); pvState.failedStep = null;
      stopPlayback();
      document.getElementById('pv-inspector').innerHTML = '<div class="pv-loading"><div class="spinner"></div> Running simulation…</div>';
      try { await runScenario(pvState.scenario); fillDiagramValues(); goToStep(0); }
      catch (e) { document.getElementById('pv-inspector').innerHTML = `<div class="pv-loading" style="color:var(--red)">${icon('alert-triangle')} ${e.message}</div>`; refreshIcons(); }
    });
  });

  (async () => {
    try { await runScenario('valid'); fillDiagramValues(); goToStep(0); }
    catch (e) { document.getElementById('pv-inspector').innerHTML = `<div class="pv-loading" style="color:var(--red)">${icon('alert-triangle')} ${e.message}</div>`; refreshIcons(); }
  })();
}
