// Group (Pro/Firm) entry point.
// Installs Group-tier capabilities, syncs the cloud provider roster, then
// boots the full app shell with the Practice tab and roster switcher.

import { installCapabilities } from './core/capabilities.js';
import { kvWarmup }            from './core/storageBackend.js';
import { initAuth }            from './core/auth.js';
import { startSyncLoop }       from './core/syncEngine.js';
import { on }                  from './core/eventBus.js';

import { ensureRosterSeeded, groupCapabilities } from './group/groupCapabilities.js';
import { syncRosterFromCloud }                   from './group/rosterSync.js';
import { renderRosterSwitcher, wireRosterSwitcher } from './group/rosterSwitcher.js';
import { renderPracticePanel, wirePracticePanel }   from './group/practicePanel.js';

import { isOnboarded, renderOnboarding, wireOnboarding } from './solo/onboarding.js';
import { renderHeader, wireHeaderNav }                    from './solo/soloHeader.js';
import { renderHomeScreen, wireHomeScreen }               from './solo/homeScreen.js';
import { renderEncounterPanel, wireEncounterPanel }       from './solo/encounterPanel.js';
import { renderSettings, wireSettings }                   from './solo/settingsModal.js';
import { renderTemplatesView }                            from './solo/templatesView.js';
import { renderPatientsView, wirePatientsView }           from './solo/patientsView.js';

const GROUP_EXTRA_TABS = [{ id: 'practice', label: 'Practice' }];

let _currentTab      = 'sessions';
let _openEncounter   = null;

// ── Bootstrap ─────────────────────────────────────────────────────────────────

async function bootstrap() {
  await kvWarmup();
  await initAuth();               // restore cloud auth state + enc key
  installCapabilities(groupCapabilities());

  if (!isOnboarded()) {
    document.getElementById('app').innerHTML = renderOnboarding();
    await wireOnboarding(async () => {
      ensureRosterSeeded();
      await syncRosterFromCloud();
      _currentTab = 'sessions';
      renderApp();
    });
    return;
  }

  ensureRosterSeeded();
  await syncRosterFromCloud();    // updates local roster from cloud org providers
  renderApp();
  startSyncLoop();

  // Re-render the full app when the active provider changes so the roster
  // switcher highlights the new selection and encounter filters refresh.
  on('group:provider_changed', () => renderApp());
}

// ── Shell ─────────────────────────────────────────────────────────────────────

async function renderApp() {
  const root = document.getElementById('app');

  root.innerHTML = `
    ${renderRosterSwitcher()}
    ${renderHeader(_currentTab, GROUP_EXTRA_TABS)}
    <main class="app-main" id="main-content"></main>
    <div class="toast" id="toast"><span id="toast-msg"></span></div>
  `;

  wireRosterSwitcher(tab => {
    _currentTab = tab;
    _openEncounter = null;
    renderApp();
  });

  wireHeaderNav(tab => {
    _currentTab = tab;
    _openEncounter = null;
    renderApp();
  });

  await renderMainContent();
}

async function renderMainContent() {
  const main = document.getElementById('main-content');
  if (!main) return;

  if (_openEncounter) {
    main.innerHTML = renderEncounterPanel(_openEncounter);
    wireEncounterPanel(
      _openEncounter,
      () => { _openEncounter = null; renderApp(); },
      updated => { _openEncounter = updated; },
    );
    return;
  }

  if (_currentTab === 'sessions') {
    main.innerHTML = await renderHomeScreen();
    await wireHomeScreen(encounter => {
      _openEncounter = encounter;
      renderMainContent();
    });
  } else if (_currentTab === 'patients') {
    main.innerHTML = await renderPatientsView();
    wirePatientsView(encounter => {
      _openEncounter = encounter;
      renderMainContent();
    });
  } else if (_currentTab === 'templates') {
    main.innerHTML = renderTemplatesView();
  } else if (_currentTab === 'practice') {
    main.innerHTML = await renderPracticePanel();
    await wirePracticePanel();
  } else if (_currentTab === 'settings') {
    main.innerHTML = await renderSettings();
    wireSettings();
  }
}

bootstrap();
