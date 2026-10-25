/* AuthPulse – Verification Logs page */
import { api, state, icon, refreshIcons, showToast, resultBadge, reasonBadge, escapeHtml, timeAgo, renderCheckItem } from './core.js';

export function renderLogs(root) {
  root.innerHTML = `
    <div class="page-intro">
      <strong>Verification Logs</strong> is the complete audit trail — every sign, verify, and simulation
      from every page ends up here. Search, filter by result or reason, sort, and click any row to see
      the full check trace. Turn on live polling to watch new events appear in real time.
    </div>
    <div class="card">
      <div class="logs-toolbar-top">
        <div class="table-toolbar" style="flex:1">
          <input type="text" id="logs-search" class="search-input" placeholder="Search by request ID, payload, or nonce…" value="${state.logsState.q}" />
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

  document.getElementById('logs-filter-result').value = state.logsState.result;
  document.getElementById('logs-filter-reason').value = state.logsState.reason;
  document.getElementById('logs-sort').value = state.logsState.sort;
  document.getElementById('logs-order').value = state.logsState.order;

  let searchTimer;
  document.getElementById('logs-search').addEventListener('input', e => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { state.logsState.q = e.target.value; state.logsState.page = 1; loadLogs(); }, 300);
  });
  document.getElementById('logs-filter-result').addEventListener('change', e => { state.logsState.result = e.target.value; state.logsState.page = 1; loadLogs(); });
  document.getElementById('logs-filter-reason').addEventListener('change', e => { state.logsState.reason = e.target.value; state.logsState.page = 1; loadLogs(); });
  document.getElementById('logs-sort').addEventListener('change', e => { state.logsState.sort = e.target.value; loadLogs(); });
  document.getElementById('logs-order').addEventListener('change', e => { state.logsState.order = e.target.value; loadLogs(); });

  document.getElementById('logs-live-toggle').addEventListener('click', () => {
    if (state.logsLiveTimer) {
      clearInterval(state.logsLiveTimer); state.logsLiveTimer = null;
      document.getElementById('logs-live-toggle').classList.remove('active');
      showToast('Live polling disabled', '');
    } else {
      state.logsLiveTimer = setInterval(loadLogs, 5000);
      document.getElementById('logs-live-toggle').classList.add('active');
      showToast('Live polling enabled (every 5s)', 'success');
    }
  });

  document.getElementById('logs-export').addEventListener('click', () => {
    if (!state.logsData || !state.logsData.items.length) { showToast('No data to export', 'error'); return; }
    const blob = new Blob([JSON.stringify(state.logsData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `authpulse-events-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Exported ' + state.logsData.items.length + ' events', 'success');
  });

  loadLogs();
}

export async function loadLogs() {
  const body = document.getElementById('logs-body');
  const pagEl = document.getElementById('logs-pagination');
  if (!body) return;
  body.innerHTML = '<div class="state-box"><div class="spinner"></div>Loading…</div>';

  const { logsState } = state;
  const params = new URLSearchParams({ page: logsState.page, page_size: logsState.pageSize, order: logsState.order, sort: logsState.sort });
  if (logsState.q) params.set('q', logsState.q);
  if (logsState.result !== 'all') params.set('result', logsState.result);
  if (logsState.reason !== 'all') params.set('reason', logsState.reason);

  try {
    const data = await api('/api/events?' + params.toString());
    state.logsData = data;
    state.logsExpandedRow = null;

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
    data.items.forEach(e => {
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
      tr.addEventListener('keydown', ev => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); toggleRowExpand(e.id, e); } });
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
    if (prev) prev.addEventListener('click', () => { state.logsState.page--; loadLogs(); });
    if (next) next.addEventListener('click', () => { state.logsState.page++; loadLogs(); });
    refreshIcons();
  } catch (e) {
    body.innerHTML = `<div class="state-box error-text">${icon('wifi-off')}<p>Failed to load logs: ${e.message}</p></div>`;
    refreshIcons();
  }
}

function toggleRowExpand(id, event) {
  const tbody = document.getElementById('logs-tbody');
  if (!tbody) return;

  const existing = tbody.querySelector('.inline-expand');
  if (existing) {
    const existingId = existing.dataset.expandId;
    existing.remove();
    if (existingId == id) { state.logsExpandedRow = null; return; }
  }

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
  state.logsExpandedRow = id;
  refreshIcons();
}
