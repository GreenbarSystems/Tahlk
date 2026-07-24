// Solo entry point — bootstraps storage, checks onboarding, renders the shell.

import { kvWarmup, kvGet, kvEnsure } from './core/storageBackend.js';
import { encounterCacheKeys, keys } from './data/keys.js';
import { installCapabilities } from './core/capabilities.js';
import { loadHistory } from './domain/historyChain.js';
import { verifyHistoryChain } from './utils/contentHash.js';
import { reportIntegrityFailure } from './solo/integrityAlert.js';
import { logRecordViewed } from './core/auditLog.js';
import { shouldLogRecordView } from './domain/recordAccess.js';
import { onWindowCloseRequested, destroyWindow, invoke, isTauri } from './platform/tauri.js';
import { clearClipboardOnExit } from './export/exportFormatter.js';
import { startIdleWatcher } from './core/idleLock.js';
import * as telemetry from './core/telemetry.js';
import { authRepo } from './data/authRepo.js';
import { showSignInScreen, runFirstOpenAuth, showMigrationInterstitial } from './solo/authScreen.js';
import { isOnboarded, renderOnboarding, wireOnboarding } from './solo/onboarding.js';
import { renderHeader, wireHeaderNav } from './solo/soloHeader.js';
import { renderHomeScreen, wireHomeScreen } from './solo/homeScreen.js';
import { renderEncounterPanel, wireEncounterPanel } from './solo/encounter/index.js';
import { renderSettings, wireSettings } from './solo/settingsModal.js';
import { renderTemplatesView } from './solo/templatesView.js';
import { renderPatientsView, wirePatientsView } from './solo/patientsView.js';
import { retentionRepo } from './data/retentionRepo.js';

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

// Clear any clipboard PHI still pending its timed auto-clear (see
// exportFormatter.js) before the window actually closes. preventDefault +
// a manual destroy() is the standard Tauri pattern for finishing async
// cleanup on quit — an un-prevented close would let the process exit before
// the clipboard write below lands.
async function wireClipboardClearOnExit() {
  await onWindowCloseRequested(async event => {
    event.preventDefault?.();
    await clearClipboardOnExit();
    await destroyWindow();
  });
}

// A crossed idle threshold hardening step: not merely covering the screen but
// a real cryptographic logoff (M4). First ask Rust to zero the session DEK and
// drop the DB connection pool, so decrypted PHI is genuinely unreachable while
// locked; then require the same password sign-in used at startup, which
// re-derives the DEK and reopens the pool before the app shell is restored.
// The guard makes a repeat idle fire while already locked a no-op so it can't
// wipe a half-typed password out from under the provider.
let _locking = false;
async function handleIdleLock() {
  if (_locking) return;
  _locking = true;
  try {
    await authRepo.lockSession();
  } catch (err) {
    // Even if the backend call fails, still force re-authentication — demanding
    // a password is the safe direction; silently staying unlocked is not.
    console.error('Idle lock: failed to drop session in backend', err);
  }
  await new Promise(resolve => showSignInScreen(resolve));
  _locking = false;
  renderApp();
}

async function bootstrap() {
  await kvWarmup();
  installSoloCapabilities();
  await wireClipboardClearOnExit();
  // Idle lock is ON by default now (M4). Start the watcher unconditionally;
  // it re-reads isLockEnabled() on every tick, so a provider disabling it in
  // Settings takes effect without a restart.
  startIdleWatcher(() => { handleIdleLock(); });
  await telemetry.init();   // opt-in gated; subscribes to the bus, records nothing unless enabled

  const authConfigured = await authRepo.isConfigured();
  const app = document.getElementById('app');
  if (!authConfigured) {
    // If the user already has data (i.e. they onboarded before auth existed),
    // show a one-time explainer before dropping them into the password-setup flow.
    if (isOnboarded()) {
      await new Promise(resolve => showMigrationInterstitial(app, resolve));
    }
    await runFirstOpenAuth(app, () => {});
  } else {
    await new Promise(resolve => showSignInScreen(resolve));
  }

  if (!isOnboarded()) {
    document.getElementById('app').innerHTML = renderOnboarding();
    await wireOnboarding(() => {
      _currentTab = 'sessions';
      renderApp();
    });
    return;
  }

  renderApp();
  // Non-blocking launch check: if records are past the retention window, surface
  // a dismissible banner pointing the provider to Settings. Runs after renderApp()
  // so the DOM is ready and never delays the auth or onboarding flow.
  checkRetentionOnLaunch();
}

async function checkRetentionOnLaunch() {
  try {
    // No argument: the cutoff date is derived server-side so a caller cannot
    // supply a future date and make live records look expired (finding H2).
    // The `today` computed here was a leftover from before that change and
    // was being passed to a command that ignores it.
    const candidates = await retentionRepo.listCandidates();
    if (!candidates || candidates.length === 0) return;
    const notice = document.getElementById('retention-notice');
    if (!notice) return;
    const n = candidates.length;
    notice.innerHTML = `
      <span class="retention-notice__msg">
        ${n} encounter record${n === 1 ? '' : 's'} ${n === 1 ? 'has' : 'have'} passed your
        retention window.
        <a href="#" id="retention-notice-link">Review in Settings →</a>
      </span>
      <button class="retention-notice__dismiss" id="retention-notice-dismiss" aria-label="Dismiss">×</button>
    `;
    notice.hidden = false;
    document.getElementById('retention-notice-link')?.addEventListener('click', e => {
      e.preventDefault();
      _currentTab = 'settings';
      renderApp();
    });
    document.getElementById('retention-notice-dismiss')?.addEventListener('click', () => {
      notice.hidden = true;
    });
  } catch {
    // Non-critical — never block launch on a retention check failure.
  }
}

async function renderApp() {
  const root = document.getElementById('app');

  root.innerHTML = `
    ${renderHeader(_currentTab)}
    <div id="retention-notice" hidden class="retention-notice"></div>
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
      await logRecordViewed(_openEncounter.id, _openEncounter.status);
    }

    // Verify the tamper-evident chain when opening a signed note. Detects
    // post-sign alteration of the audit history (the chain was always built
    // but never checked — this enforces it).
    if (_openEncounter.status === 'signed') {
      const integrity = await verifyHistoryChain(await loadHistory(_openEncounter.id));
      if (!integrity.ok) {
        reportIntegrityFailure(integrity);
      } else if (isTauri) {
        // Authoritative keyed-MAC check (audit_mac.rs). verifyHistoryChain above
        // only proves the stored rows are internally self-consistent; this
        // recomputes each row's chain_mac with the keychain-derived MAC key, so
        // a wholesale-substituted or forged chain — which the hash chain cannot
        // detect — is caught here. Best-effort: a resolution error must not
        // block opening the record (the structural check already passed).
        try {
          const mac = await invoke('verify_history_macs', { encounterId: _openEncounter.id });
          if (mac && !mac.ok) reportIntegrityFailure(mac);
        } catch (e) {
          console.error('verify_history_macs failed', e);
        }
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
