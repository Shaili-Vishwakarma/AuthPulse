/* ============================================================
   AuthPulse – Entry point
   Imports all modules and boots the application.
   ============================================================ */
import { PAGES, api, refreshIcons } from './core.js';
import { navigate } from './router.js';

// Expose navigate globally so modules without direct import access can use it
window._navigate = navigate;

// Wire up copy buttons globally via event delegation
document.addEventListener('click', function (e) {
  const btn = e.target.closest('.copy-btn');
  if (!btn) return;
  e.stopPropagation();
  const text = btn.dataset.copy;
  navigator.clipboard.writeText(text).then(() => {
    btn.classList.add('copied');
    const { icon } = _getIconFn();
    btn.innerHTML = icon('check') + 'Copied';
    setTimeout(() => {
      btn.classList.remove('copied');
      btn.innerHTML = icon('copy') + 'Copy';
      refreshIcons();
    }, 1500);
    refreshIcons();
  });
});

// Lazy icon helper — avoids circular import
function _getIconFn() {
  return { icon: (name) => `<i data-lucide="${name}" aria-hidden="true"></i>` };
}

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

function openSidebar() {
  document.getElementById('sidebar').classList.add('open');
  document.getElementById('sidebar-overlay').classList.add('active');
}

function closeSidebar() {
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('sidebar-overlay').classList.remove('active');
}

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
