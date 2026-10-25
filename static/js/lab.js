/* AuthPulse – Message Lab page */
import { api, state, icon, refreshIcons, showToast, escapeHtml, renderCheckItem } from './core.js';

export function renderMessageLab(root) {
  const defaultPayload = JSON.stringify({ "amount": 100, "recipient": "alice", "currency": "USD" }, null, 2);
  root.innerHTML = `
    <div class="page-intro">
      <strong>Message Lab</strong> is your free-form sandbox. Compose any payload, sign it, then manually
      tweak individual fields — or use the quick-action buttons — to see what breaks. Try the challenges
      below to learn by doing.
    </div>
    <div class="challenge-hints">
      <div class="challenge-hints-title">${icon('target')} Try these challenges</div>
      <div class="challenge-item"><span class="challenge-num">1</span><span class="challenge-text">Sign a message, then change one value in the payload — which check catches it?</span></div>
      <div class="challenge-item"><span class="challenge-num">2</span><span class="challenge-text">Sign a message, then age the timestamp by 120s — does the HMAC still pass?</span></div>
      <div class="challenge-item"><span class="challenge-num">3</span><span class="challenge-text">Sign a message, verify it, then verify again without changing anything — what happens?</span></div>
      <div class="challenge-item"><span class="challenge-num">4</span><span class="challenge-text">Corrupt just one character of the tag — does hmac.compare_digest still catch it?</span></div>
      <div class="challenge-item"><span class="challenge-num">5</span><span class="challenge-text">Can you make the HMAC pass but the timestamp fail? (hint: change only the timestamp)</span></div>
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
    state.labSignedMsg = signed;
    state.labOriginal = {
      payload: JSON.stringify(signed.payload, null, 2),
      timestamp: String(signed.timestamp),
      nonce: signed.nonce,
      tag: signed.tag,
    };
    state.labCurrentResult = null;

    const fieldsEl = document.getElementById('lab-fields');
    if (!fieldsEl) { showToast('UI not ready, try again', 'error'); return; }
    fieldsEl.innerHTML = `
      <div class="field-row" id="fr-payload">
        <div class="field-label">Payload</div>
        <div class="field-input">
          <textarea id="lab-edit-payload" spellcheck="false">${escapeHtml(state.labOriginal.payload)}</textarea>
          <div class="field-meta">JSON payload — modify a value to simulate tampering</div>
        </div>
      </div>
      <div class="field-row" id="fr-timestamp">
        <div class="field-label">Timestamp</div>
        <div class="field-input">
          <input type="text" id="lab-edit-timestamp" value="${state.labOriginal.timestamp}" />
          <div class="field-meta">Unix epoch seconds — change to simulate an expired message</div>
        </div>
      </div>
      <div class="field-row" id="fr-nonce">
        <div class="field-label">Nonce</div>
        <div class="field-input">
          <input type="text" id="lab-edit-nonce" value="${state.labOriginal.nonce}" />
          <div class="field-meta">Unique per message — reuse to simulate a replay</div>
        </div>
      </div>
      <div class="field-row" id="fr-tag">
        <div class="field-label">HMAC Tag</div>
        <div class="field-input">
          <input type="text" id="lab-edit-tag" value="${state.labOriginal.tag}" />
          <div class="field-meta">HMAC-SHA256 hex digest — modify to break integrity</div>
        </div>
      </div>`;
    if (signedDisplay) signedDisplay.style.display = 'block';
    const qa = document.getElementById('lab-quick-actions');
    if (qa) qa.style.display = 'flex';
    resultEl.innerHTML = `<div class="state-box">${icon('shield-check')}<p>Message signed. Use quick actions or edit fields, then click Verify.</p></div>`;

    ['payload', 'timestamp', 'nonce', 'tag'].forEach(field => {
      const el = document.getElementById('lab-edit-' + field);
      if (!el) return;
      el.addEventListener('input', () => {
        const row = document.getElementById('fr-' + field);
        if (row) {
          if (el.value !== state.labOriginal[field]) row.classList.add('modified');
          else row.classList.remove('modified');
        }
        updateLabDiff();
      });
    });

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
  const modified = ['payload', 'timestamp', 'nonce', 'tag'].filter(f => {
    const el = document.getElementById('lab-edit-' + f);
    return el && el.value !== state.labOriginal[f];
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
    tsEl.value = String(parseFloat(tsEl.value) - 120);
    showToast('Timestamp aged by 120s — should fail timestamp check', '');
  } else if (action === 'corrupt') {
    const tag = tagEl.value;
    tagEl.value = (tag[0] === 'a' ? 'b' : 'a') + tag.slice(1);
    showToast('Tag corrupted — HMAC will fail', '');
  } else if (action === 'reuse') {
    nonceEl.value = state.labOriginal.nonce;
    showToast('Nonce reset to original — verify twice to trigger replay', '');
  } else if (action === 'reset-all') {
    labDoReset(); return;
  }

  ['payload', 'timestamp', 'nonce', 'tag'].forEach(f => {
    const el = document.getElementById('lab-edit-' + f);
    const row = document.getElementById('fr-' + f);
    if (el && row) {
      if (el.value !== state.labOriginal[f]) row.classList.add('modified');
      else row.classList.remove('modified');
    }
  });
  updateLabDiff();
}

async function labDoVerify() {
  const resultEl = document.getElementById('lab-result');
  const verifyBtn = document.getElementById('lab-verify');
  if (!resultEl || !verifyBtn) return;
  if (!state.labSignedMsg) { showToast('Sign a message first', 'error'); return; }

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
    const result = await api('/api/verify', 'POST', { request_id: state.labSignedMsg.request_id, payload, timestamp, nonce, tag });
    state.labCurrentResult = result;
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
  if (!state.labSignedMsg) return;
  ['payload', 'timestamp', 'nonce', 'tag'].forEach(f => {
    const el = document.getElementById('lab-edit-' + f);
    const row = document.getElementById('fr-' + f);
    if (el) el.value = state.labOriginal[f];
    if (row) row.classList.remove('modified');
  });
  updateLabDiff();
  showToast('Fields reset to original signed values', 'success');
}
