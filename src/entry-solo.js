// Solo entry point — bootstraps storage, checks onboarding, renders the shell.

import { kvWarmup, kvGet, kvEnsure } from './core/storageBackend.js';
import { encounterCacheKeys, keys } from './data/keys.js';
import { installCapabilities } from './core/capabilities.js';
import { loadHistory } from './domain/historyChain.js';
import { verifyHistoryChain } from './utils/contentHash.js';
import { reportIntegrityFailure } from './solo/integrityAlert.js';
import { appendAudit } from './core/auditLog.js';
import { shouldLogRecordView } from './domain/recordAccess.js';
import * as telemetry from './core/telemetry.js';
import { isOnboarded, renderOnboarding, wireOnboarding } from './solo/onboarding.js';
import { renderHeader, wireHeaderNav } from './solo/soloHeader.js';
import { renderHomeScreen, wireHomeScreen } from './solo/homeScreen.js';
import { renderEncounterPanel, wireEncounterPanel } from './solo/encounter/index.js';
import { renderSettings, wireSettings } from './solo/settingsModal.js';
import { renderTemplatesView } from './solo/templatesView.js';
import { renderPatientsView, wirePatientsView } from './solo/patientsView.js';

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
    currentProvider: () => kvGet(keys.provider()) || null,
    currentUser: () => {
      const p = kvGet(keys.provider());
      return p && p.name ? { name: p.name, id: 'solo' } : null;
    },
  });
}

async function bootstrap() {
  await kvWarmup();
  installSoloCapabilities();
  await telemetry.init();   // opt-in gated; subscribes to the bus, records nothing unless enabled

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

    // Record the view itself (HIPAA risk assessment §4, remediation item 1:
    // "add a record_viewed/encounter_opened audit event on opening an
    // encounter panel, at minimum for encounters with signed notes or
    // transcripts"). Skipped only for a fresh 'recording' encounter — that
    // status means the provider is actively creating it (nothing yet exists
    // to view; the open IS the creation), not accessing an existing record.
    // Every other status (recording_done, transcribing, draft, signed,
    // exported) has at least a transcript or note already in it, so this is
    // a superset of the doc's stated minimum bar, not a narrower one.
    //
    // Runs on every open, not just the first — HIPAA access logging tracks
    // each access event, not distinct-record-ever-viewed.
    if (shouldLogRecordView(_openEncounter)) {
      await appendAudit(keys.noteAudit(_openEncounter.id), 'record_viewed', {
        encounterId: _openEncounter.id,
        status: _openEncounter.status,
      });
    }

    // Verify the tamper-evident chain when opening a signed note. Detects
    // post-sign alteration of the audit history (the chain was always built
    // but never checked — this enforces it).
    if (_openEncounter.status === 'signed') {
      const integrity = await verifyHistoryChain(await loadHistory(_openEncounter.id));
      if (!integrity.ok) {
        reportIntegrityFailure(integrity);
      }
    }

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
  } else if (_currentTab === 'patients') {
    main.innerHTML = await renderPatientsView();
    wirePatientsView(() => renderMainContent());
  } else if (_currentTab === 'templates') {
    main.innerHTML = renderTemplatesView();
  } else if (_currentTab === 'settings') {
    main.innerHTML = await renderSettings();
    wireSettings();
  }
}

bootstrap();
