// Top nav bar — Sessions | Templates | Settings

// extraTabs: optional array of {id, label} inserted before Settings.
// Used by the Group build to inject the Practice tab without forking this file.
export function renderHeader(activeTab, extraTabs = []) {
  const tabs = [
    { id: 'sessions',  label: 'Sessions'  },
    { id: 'patients',  label: 'Patients'  },
    { id: 'templates', label: 'Templates' },
    ...extraTabs,
    { id: 'settings',  label: 'Settings'  },
  ];
  const tabsHtml = tabs.map(t => `
    <button class="nav-tab ${t.id === activeTab ? 'nav-tab--active' : ''}"
            data-tab="${t.id}">${t.label}</button>
  `).join('');

  return `
    <header class="app-header">
      <div class="header-brand">
        <img class="header-logo-img" src="/tahlk-logo.png" alt="Tahlk — AI-native ambient scribe" />
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
