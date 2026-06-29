// Solo entry point — bootstraps storage, checks onboarding, renders the shell.

import { kvWarmup, kvGet, kvEnsure, encounterCacheKeys } from './core/storageBackend.js';
import { installCapabilities } from './core/capabilities.js';
import { isOnboarded, renderOnboarding, wireOnboarding } from './solo/onboarding.js';
import { renderHeader, wireHeaderNav } from './solo/soloHeader.js';
import { renderHomeScreen, wireHomeScreen } from './solo/homeScreen.js';
import { renderEncounterPanel, wireEncounterPanel } from './solo/encounterPanel.js';
import { renderSettings, wireSettings } from './solo/settingsModal.js';
import { renderTemplatesView } from './solo/templatesView.js';

let _currentTab = 'sessions';
let _openEncounter = null;
let _panelDispose = null;   // teardown for the mounted encounter panel, if any

// Dispose the encounter panel (drop bus subscriptions, flush pending edits)
// before any navigation or re-render that would unmount it.
async function disposePanel() {
  if (_panelDispose) {
    const d = _panelDispose;
    _panelDispose = null;
    await d();
  }
}

// Solo-tier capability impls. Read the provider profile live from storage on
// every call so the audit log reflects the current identity — including right
// after onboarding, before any re-warmup. (Group tier installs richer impls.)
function installSoloCapabilities() {
  installCapabilities({
    currentProvider: () => kvGet('note_provider_v1::profile') || null,
    currentUser: () => {
      const p = kvGet('note_provider_v1::profile');
      return p && p.name ? { name: p.name, id: 'solo' } : null;
    },
  });
}

async function bootstrap() {
  await kvWarmup();
  installSoloCapabilities();

  if (!isOnboarded()) {
    document.getElementById('app').innerHTML = renderOnboarding();
    await wireOnboarding(() => {
      _currentTab = 'sessions';
      renderApp();
    });
    return;
  }

  renderApp();
}

async function renderApp() {
  const root = document.getElementById('app');

  root.innerHTML = `
    ${renderHeader(_currentTab)}
    <main class="app-main" id="main-content"></main>
    <div class="toast" id="toast"><span id="toast-msg"></span></div>
  `;

  wireHeaderNav(async tab => {
    await disposePanel();
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
    // Lazily pull this encounter's note/transcript/history/audit into cache
    // before the panel renders synchronously from it.
    await kvEnsure(encounterCacheKeys(_openEncounter.id));
    main.innerHTML = renderEncounterPanel(_openEncounter);
    _panelDispose = wireEncounterPanel(
      _openEncounter,
      () => { _panelDispose = null; _openEncounter = null; renderApp(); },
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
  } else if (_currentTab === 'templates') {
    main.innerHTML = renderTemplatesView();
  } else if (_currentTab === 'settings') {
    main.innerHTML = await renderSettings();
    wireSettings();
  }
}

bootstrap();
