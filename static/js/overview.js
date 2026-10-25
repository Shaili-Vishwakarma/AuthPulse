/* AuthPulse – Overview page */
import { api, state, icon, refreshIcons, showToast, timeAgo, resultBadge, reasonBadge, renderCheckItem } from './core.js';

export async function renderOverview(root) {
  root.innerHTML = `<div id="ov-loading" class="state-box"><div class="spinner"></div>Loading…</div>`;
  await loadOverviewData(root);
}

export async function loadOverviewData(root) {
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
        <span class="live-pulse" style="${state.overviewLive ? '' : 'display:none'}"><span class="pulse-dot"></span>Live</span>
        <button id="ov-live-toggle" class="live-toggle ${state.overviewLive ? 'active' : ''}">${icon('radio')} Auto-refresh (5s)</button>
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

    document.getElementById('ov-live-toggle').addEventListener('click', () => {
      state.overviewLive = !state.overviewLive;
      if (state.overviewLive) {
        state.overviewLiveTimer = setInterval(() => loadOverviewData(root), 5000);
        showToast('Live refresh enabled (every 5s)', 'success');
      } else {
        clearInterval(state.overviewLiveTimer);
        state.overviewLiveTimer = null;
        showToast('Live refresh disabled', '');
      }
      const btn = document.getElementById('ov-live-toggle');
      if (btn) btn.classList.toggle('active', state.overviewLive);
      const pulse = document.querySelector('.live-pulse');
      if (pulse) pulse.style.display = state.overviewLive ? '' : 'none';
    });

    document.querySelectorAll('.metric-card.clickable').forEach(card => {
      card.addEventListener('click', () => {
        const filter = card.dataset.filter;
        const nav = window._navigate;
        if (!nav) return;
        if (filter === 'all') { nav('logs'); }
        else if (filter === 'accepted') { state.logsState.result = 'accepted'; state.logsState.reason = 'all'; state.logsState.page = 1; nav('logs'); }
        else if (filter === 'rejected') { state.logsState.result = 'rejected'; state.logsState.reason = 'all'; state.logsState.page = 1; nav('logs'); }
        else if (filter === 'expired') { state.logsState.result = 'all'; state.logsState.reason = 'expired'; state.logsState.page = 1; nav('logs'); }
      });
    });

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
      request_id: signed.request_id, payload: signed.payload,
      timestamp: signed.timestamp, nonce: signed.nonce, tag: signed.tag,
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
