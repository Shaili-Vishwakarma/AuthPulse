/* AuthPulse – API Playground page */
import { api, state, icon, refreshIcons, showToast, escapeHtml, escapeAttr } from './core.js';

export function renderPlayground(root) {
  root.innerHTML = `
    <div class="page-intro">
      <strong>API Playground</strong> is a raw API explorer. Step 1: call <code>/api/sign</code> to get a tag.
      A "Copy to Verify" button appears. Click it to auto-fill Step 2. Then tweak any field in the verify
      body and resend to see which check fails. Green = accepted, Red = rejected. Click history items to
      restore both request and response.
    </div>
    <div class="lab-layout"><div>
    <div class="card">
      <div class="card-title">Request</div>
      <div style="margin-bottom:12px">
        <label class="input-label" style="margin-bottom:6px">Quick start:</label>
        <div class="scenario-row" id="pg-quickstart">
          <span class="scenario-chip active" data-qs="sign">${icon('pen-tool')} Step 1: Sign</span>
          <span class="scenario-chip" data-qs="verify">${icon('shield-check')} Step 2: Verify</span>
          <span class="scenario-chip" data-qs="browse">${icon('list')} Browse events</span>
          <span class="scenario-chip" data-qs="stats">${icon('bar-chart-3')} Stats</span>
        </div>
        <div class="scenario-desc visible" id="pg-qs-desc">Step 1: Call /api/sign. The server signs your payload and returns a timestamp, nonce, and HMAC tag. After the response, click "Copy to Verify" to auto-fill Step 2.</div>
      </div>
      <div class="input-group">
        <label class="input-label" for="pg-endpoint">Endpoint</label>
        <select id="pg-endpoint" class="select">
          <option value="/api/sign">POST /api/sign</option>
          <option value="/api/verify">POST /api/verify</option>
          <option value="/api/events">GET /api/events</option>
          <option value="/api/stats">GET /api/stats</option>
          <option value="/api/health">GET /api/health</option>
        </select>
      </div>
      <div class="input-group" id="pg-body-group">
        <label class="input-label" for="pg-body">Request Body (JSON)</label>
        <textarea id="pg-body" class="code-input" spellcheck="false">{
  "payload": { "amount": 100, "recipient": "alice" }
}</textarea>
      </div>
      <div id="pg-query-group" style="display:none">
        <label class="input-label">Query Parameters</label>
        <div class="query-param-builder" id="pg-query-params"></div>
        <button id="pg-add-param" class="btn" style="font-size:12px;padding:4px 10px">${icon('plus')} Add Parameter</button>
      </div>
      <div class="action-row" style="margin-top:12px">
        <button id="pg-send" class="btn btn-primary">${icon('play')} Send Request</button>
        <button id="pg-copy-to-verify" class="btn" style="display:none">${icon('arrow-right')} Use in Verify</button>
        <button id="pg-clear-history" class="btn">${icon('trash-2')} Clear History</button>
      </div>
    </div>
  </div><div>
    <div class="card">
      <div class="card-title">Response</div>
      <div id="pg-response" class="playground-response" style="min-height:200px">Click "Send Request" to see the response here.</div>
    </div>
    <div class="card" style="margin-top:16px">
      <div class="card-title">Request History <span style="font-size:11px;font-weight:400;color:var(--text-tertiary)">(click to restore request + response)</span></div>
      <div id="pg-history-list"><div class="state-box" style="padding:16px">${icon('history')}<p style="font-size:12px">No requests sent yet.</p></div></div>
    </div>
  </div></div>`;
  refreshIcons();

  const endpointSel = document.getElementById('pg-endpoint');
  const bodyGroup = document.getElementById('pg-body-group');
  const queryGroup = document.getElementById('pg-query-group');
  const bodyTa = document.getElementById('pg-body');
  const copyToVerifyBtn = document.getElementById('pg-copy-to-verify');
  const respEl = document.getElementById('pg-response');
  let lastSignResponse = null;

  const quickstarts = {
    sign: { endpoint: '/api/sign', body: '{ "payload": { "amount": 100, "recipient": "alice" } }', desc: 'Step 1: Call /api/sign. The server signs your payload and returns a timestamp, nonce, and HMAC tag. After the response comes back, the "Copy to Verify" button becomes active — click it to auto-fill Step 2.' },
    verify: { endpoint: '/api/verify', body: '{\n  "payload": { "amount": 100, "recipient": "alice" },\n  "timestamp": 0,\n  "nonce": "PASTE_FROM_SIGN",\n  "tag": "PASTE_FROM_SIGN"\n}', desc: 'Step 2: Call /api/verify with the values from /api/sign. Use "Copy to Verify" after Step 1 to auto-fill. If all values match, result is "accepted" (green). Change any field to see it rejected (red).' },
    browse: { endpoint: '/api/events', body: null, params: [{ key: 'page', value: '1' }, { key: 'page_size', value: '10' }], desc: 'Browse all verification attempts. Add query params: result=accepted, result=rejected, reason=tamper, reason=replay, reason=expired, sort=timestamp, order=asc.' },
    stats: { endpoint: '/api/stats', body: null, params: [], desc: 'Get aggregate metrics: total verifications, accepted, rejected, and breakdown by reason.' },
  };

  document.querySelectorAll('#pg-quickstart .scenario-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const qs = quickstarts[chip.dataset.qs]; if (!qs) return;
      document.querySelectorAll('#pg-quickstart .scenario-chip').forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
      endpointSel.value = qs.endpoint;
      if (qs.body !== null) bodyTa.value = qs.body;
      document.getElementById('pg-qs-desc').textContent = qs.desc;
      document.getElementById('pg-qs-desc').classList.add('visible');
      if (qs.params) renderQueryParams(qs.params);
      if (chip.dataset.qs !== 'verify') updateCopyBtn();
      updateBodyVisibility();
    });
  });

  function renderQueryParams(params) {
    const container = document.getElementById('pg-query-params');
    container.innerHTML = '';
    params.forEach(p => addQueryParamRow(p.key, p.value));
  }

  function addQueryParamRow(key, value) {
    const container = document.getElementById('pg-query-params');
    const row = document.createElement('div');
    row.className = 'query-param-row';
    row.innerHTML = `<input type="text" placeholder="key" value="${key || ''}" class="qp-key">
      <input type="text" placeholder="value" value="${value || ''}" class="qp-val">
      <button class="icon-btn qp-remove" style="width:24px;height:24px">${icon('x')}</button>`;
    row.querySelector('.qp-remove').addEventListener('click', () => row.remove());
    container.appendChild(row);
    refreshIcons();
  }

  // Get HTTP method from the selected option's displayed text (e.g. "GET /api/events")
  function getSelectedMethod() {
    const optText = endpointSel.options[endpointSel.selectedIndex].text;
    return optText.startsWith('GET') ? 'GET' : 'POST';
  }

  function updateBodyVisibility() {
    const isGet = getSelectedMethod() === 'GET';
    bodyGroup.style.display = isGet ? 'none' : '';
    queryGroup.style.display = isGet ? '' : 'none';
  }

  function updateCopyBtn() {
    // Only show and enable on the /api/sign endpoint, only after we have a sign response
    const onSignEndpoint = endpointSel.value === '/api/sign';
    copyToVerifyBtn.style.display = onSignEndpoint ? 'inline-flex' : 'none';
    copyToVerifyBtn.disabled = !lastSignResponse;
    copyToVerifyBtn.style.opacity = lastSignResponse ? '1' : '.5';
  }

  function renderResponse(method, url, elapsed, data, error) {
    if (error) {
      respEl.innerHTML = `<div class="pg-status-line"><span class="pg-status-code error">${method}</span><span style="font-family:var(--font-mono);font-size:11px">${escapeHtml(url)}</span><span style="color:var(--red);font-size:11px">ERROR</span></div>`;
      const b = document.createElement('div'); b.className = 'pg-response-block'; b.style.borderColor = 'var(--red)'; b.style.background = 'var(--red-bg)'; b.textContent = 'Error: ' + error; respEl.appendChild(b);
      return;
    }
    let resultColor = 'ok', resultText = method + ' OK';
    if (data.result === 'accepted') { resultColor = 'ok'; resultText = 'ACCEPTED'; }
    else if (data.result === 'rejected') { resultColor = 'error'; resultText = 'REJECTED'; }
    respEl.innerHTML = `<div class="pg-status-line"><span class="pg-status-code ${resultColor}">${resultText}</span><span style="font-family:var(--font-mono);font-size:11px">${escapeHtml(url)}</span><span style="color:var(--text-tertiary);font-size:11px">${elapsed}ms</span></div>`;
    const b = document.createElement('div'); b.className = 'pg-response-block';
    if (data.result === 'rejected') { b.style.borderColor = 'var(--red)'; b.style.background = 'var(--red-bg)'; }
    else if (data.result === 'accepted') { b.style.borderColor = 'var(--green)'; b.style.background = 'var(--green-bg)'; }
    b.textContent = JSON.stringify(data, null, 2); respEl.appendChild(b);
  }

  endpointSel.addEventListener('change', () => { updateBodyVisibility(); updateCopyBtn(); });
  document.getElementById('pg-add-param').addEventListener('click', () => addQueryParamRow('', ''));
  updateBodyVisibility(); updateCopyBtn();

  document.getElementById('pg-send').addEventListener('click', async () => {
    respEl.textContent = 'Sending…';
    const ep = endpointSel.value;
    const method = getSelectedMethod();
    let url = ep, body = null;
    if (method === 'POST') {
      try { body = JSON.parse(bodyTa.value); } catch (e) { respEl.textContent = 'Invalid JSON: ' + e.message; return; }
    } else {
      const params = [];
      document.querySelectorAll('.query-param-row').forEach(row => {
        const k = row.querySelector('.qp-key').value.trim();
        const v = row.querySelector('.qp-val').value.trim();
        if (k) params.push(k + '=' + encodeURIComponent(v));
      });
      if (params.length) url += '?' + params.join('&');
    }
    const t0 = Date.now();
    try {
      const data = await api(url, method, body);
      if (ep === '/api/sign' && data.tag) { lastSignResponse = data; updateCopyBtn(); }
      renderResponse(method, url, Date.now() - t0, data, null);
      state.pgHistory.unshift({ method, url, time: new Date().toLocaleTimeString(), status: 'ok', response: data, requestBody: method === 'POST' ? bodyTa.value : null });
    } catch (e) {
      renderResponse(method, url, Date.now() - t0, null, e.message);
      state.pgHistory.unshift({ method, url, time: new Date().toLocaleTimeString(), status: 'error', requestBody: method === 'POST' ? bodyTa.value : null });
    }
    renderHistory();
  });

  copyToVerifyBtn.addEventListener('click', () => {
    if (!lastSignResponse) { showToast('Send a /api/sign request first', 'error'); return; }
    // Switch to verify endpoint and auto-fill body
    endpointSel.value = '/api/verify';
    document.querySelectorAll('#pg-quickstart .scenario-chip').forEach(c => c.classList.remove('active'));
    const verifyChip = document.querySelector('#pg-quickstart [data-qs="verify"]');
    if (verifyChip) verifyChip.classList.add('active');
    bodyTa.value = JSON.stringify({
      payload: lastSignResponse.payload,
      timestamp: lastSignResponse.timestamp,
      nonce: lastSignResponse.nonce,
      tag: lastSignResponse.tag,
    }, null, 2);
    document.getElementById('pg-qs-desc').textContent = quickstarts.verify.desc;
    updateBodyVisibility();
    updateCopyBtn(); // hide the button since we're now on /api/verify
    showToast('Signed values copied to /api/verify body — click Send Request', 'success');
    document.getElementById('pg-send').scrollIntoView({ behavior: 'smooth', block: 'center' });
  });

  function renderHistory() {
    const list = document.getElementById('pg-history-list');
    if (!state.pgHistory.length) { list.innerHTML = `<div class="state-box" style="padding:16px">${icon('history')}<p style="font-size:12px">No requests sent yet.</p></div>`; refreshIcons(); return; }
    list.innerHTML = state.pgHistory.slice(0, 10).map((h, i) => {
      let badge = '';
      if (h.response && h.response.result === 'accepted') badge = '<span class="badge badge-accepted" style="margin-left:4px">Accepted</span>';
      else if (h.response && h.response.result === 'rejected') badge = '<span class="badge badge-rejected" style="margin-left:4px">Rejected</span>';
      if (h.status === 'error') badge = '<span class="badge badge-rejected" style="margin-left:4px">Error</span>';
      return `<div class="history-item" data-idx="${i}" style="flex-wrap:wrap"><span class="method-badge ${h.method}">${h.method}</span><span style="font-family:var(--font-mono);font-size:11px">${escapeHtml(h.url)}</span>${badge}<span class="time">${h.time}</span></div>`;
    }).join('');
    list.querySelectorAll('.history-item').forEach(item => {
      item.addEventListener('click', () => {
        const h = state.pgHistory[parseInt(item.dataset.idx)]; if (!h) return;
        for (const opt of endpointSel.options) { if (h.url.split('?')[0] === opt.value) { endpointSel.value = opt.value; break; } }
        if (h.requestBody) bodyTa.value = h.requestBody;
        if (h.url.includes('?')) { renderQueryParams(h.url.split('?')[1].split('&').map(p => { const [k, v] = p.split('='); return { key: k, value: decodeURIComponent(v || '') }; })); }
        if (h.response) renderResponse(h.method, h.url, 0, h.response, null);
        else renderResponse(h.method, h.url, 0, null, 'No response saved');
        updateBodyVisibility(); updateCopyBtn();
      });
    });
    refreshIcons();
  }

  document.getElementById('pg-clear-history').addEventListener('click', () => { state.pgHistory = []; renderHistory(); showToast('History cleared', ''); });
  renderHistory();
}
