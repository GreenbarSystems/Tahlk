// Top nav bar — Sessions | Patients | Templates | Settings

import { LOGO_SVG } from './logoSvg.js';

export function renderHeader(activeTab) {
  const tabs = [
    { id: 'sessions',  label: 'Sessions'  },
    { id: 'patients',  label: 'Patients'  },
    { id: 'templates', label: 'Templates' },
    { id: 'settings',  label: 'Settings'  },
  ];
  const tabsHtml = tabs.map(t => `
    <button class="nav-tab ${t.id === activeTab ? 'nav-tab--active' : ''}"
            data-tab="${t.id}"
            ${t.id === activeTab ? 'aria-current="page"' : ''}>${t.label}</button>
  `).join('');

  return `
    <header class="app-header">
      <div class="header-brand">
        ${LOGO_SVG}
        <span class="header-name">Tahlk</span>
        <span class="header-badge">Beta</span>
      </div>
      <nav class="header-nav">${tabsHtml}</nav>
    </header>
  `;
}

export function wireHeaderNav(onNavigate) {
  document.querySelectorAll('.nav-tab').forEach(btn => {
    btn.addEventListener('click', () => onNavigate(btn.dataset.tab));
  });
}
