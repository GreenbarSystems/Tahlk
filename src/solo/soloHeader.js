// Top nav bar — Sessions | Templates | Settings

export function renderHeader(activeTab) {
  const tabs = [
    { id: 'sessions',  label: 'Sessions' },
    { id: 'templates', label: 'Templates' },
    { id: 'settings',  label: 'Settings'  },
  ];
  const tabsHtml = tabs.map(t => `
    <button class="nav-tab ${t.id === activeTab ? 'nav-tab--active' : ''}"
            data-tab="${t.id}">${t.label}</button>
  `).join('');

  return `
    <header class="app-header">
      <div class="header-brand">
        <span class="header-logo">✦</span>
        <span class="header-name">Greenbar Note</span>
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
