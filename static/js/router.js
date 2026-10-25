/* AuthPulse – Router: navigate between pages */
import { PAGES, PAGE_TITLES, state, refreshIcons } from './core.js';
import { renderOverview } from './overview.js';
import { renderMessageLab } from './lab.js';
import { renderAttackSim } from './simulator.js';
import { renderLogs } from './logs.js';
import { renderPlayground } from './playground.js';
import { renderProtocolVisualizer } from './visualizer.js';
import { renderHowItWorks } from './howItWorks.js';

export function navigate(page) {
  window._navigate = navigate; // expose for modules that can't directly import (circular deps)
  if (!PAGES.includes(page)) page = 'overview';

  // Stop timers from previous pages
  if (state.overviewLiveTimer) { clearInterval(state.overviewLiveTimer); state.overviewLiveTimer = null; state.overviewLive = false; }
  if (state.logsLiveTimer) { clearInterval(state.logsLiveTimer); state.logsLiveTimer = null; }

  document.querySelectorAll('.nav-item').forEach(el => {
    el.classList.toggle('active', el.dataset.page === page);
  });
  document.getElementById('page-title').textContent = PAGE_TITLES[page] || page;

  const content = document.getElementById('page-content');
  content.innerHTML = '';

  switch (page) {
    case 'overview':           renderOverview(content); break;
    case 'message-lab':        renderMessageLab(content); break;
    case 'attack-simulator':   renderAttackSim(content); break;
    case 'protocol-visualizer': renderProtocolVisualizer(content); break;
    case 'logs':               renderLogs(content); break;
    case 'playground':         renderPlayground(content); break;
    case 'how-it-works':       renderHowItWorks(content); break;
  }

  refreshIcons();
  closeSidebar();
  location.hash = page;
}

function closeSidebar() {
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('sidebar-overlay').classList.remove('active');
}
