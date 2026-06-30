// Roster switcher — the persistent provider-selector bar rendered above the
// main nav in Group mode. Shows the active provider's avatar + name and a
// dropdown of all roster providers. Emits 'group:provider_changed' on switch.

import { emit } from '../core/eventBus.js';
import {
  loadRoster, activeProviderId, setActiveProvider,
} from './groupCapabilities.js';

// ── Render ────────────────────────────────────────────────────────────────────

export function renderRosterSwitcher() {
  const roster   = loadRoster();
  const activeId = activeProviderId();
  const active   = roster.find(p => p.id === activeId) || roster[0] || null;

  if (!active) return '<div class="roster-bar roster-bar--empty">No providers in roster</div>';

  const providerItems = roster.map(p => `
    <button class="roster-provider-item ${p.id === activeId ? 'roster-provider-item--active' : ''}"
            data-provider-id="${p.id}">
      <span class="roster-avatar roster-avatar--sm">${_initials(p.name)}</span>
      <span class="roster-provider-name">${esc(p.name)}</span>
      ${p.id === activeId ? '<span class="roster-check">✓</span>' : ''}
    </button>
  `).join('');

  return `
    <div class="roster-bar" id="roster-bar">
      <button class="roster-active-btn" id="roster-toggle" aria-haspopup="listbox">
        <span class="roster-avatar">${_initials(active.name)}</span>
        <span class="roster-active-name">
          <span class="roster-active-label">Provider</span>
          <strong>${esc(active.name)}</strong>${active.credentials ? `<span class="roster-creds">, ${esc(active.credentials)}</span>` : ''}
        </span>
        <span class="roster-chevron" id="roster-chevron">▾</span>
      </button>

      <div class="roster-dropdown" id="roster-dropdown" hidden>
        <div class="roster-dropdown-label">Switch provider</div>
        ${providerItems}
      </div>

      <div class="roster-bar-actions">
        <button class="btn btn-ghost btn-sm" id="roster-manage-btn">Team →</button>
      </div>
    </div>
  `;
}

// ── Wire ──────────────────────────────────────────────────────────────────────

export function wireRosterSwitcher(onNavigate) {
  const toggle   = document.getElementById('roster-toggle');
  const dropdown = document.getElementById('roster-dropdown');
  const chevron  = document.getElementById('roster-chevron');

  // Toggle dropdown open/close
  toggle?.addEventListener('click', e => {
    e.stopPropagation();
    const isOpen = !dropdown.hidden;
    dropdown.hidden = isOpen;
    if (chevron) chevron.textContent = isOpen ? '▾' : '▴';
  });

  // Close on outside click
  document.addEventListener('click', () => {
    if (dropdown && !dropdown.hidden) {
      dropdown.hidden = true;
      if (chevron) chevron.textContent = '▾';
    }
  }, { capture: false });

  // Provider switch
  dropdown?.querySelectorAll('.roster-provider-item').forEach(btn => {
    btn.addEventListener('click', e => {
      e.stopPropagation();
      const id = btn.dataset.providerId;
      if (id && id !== activeProviderId()) {
        setActiveProvider(id);
        emit('group:provider_changed', { providerId: id });
      }
      dropdown.hidden = true;
    });
  });

  // "Team →" shortcut navigates to the practice tab
  document.getElementById('roster-manage-btn')?.addEventListener('click', () => {
    onNavigate?.('practice');
  });
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function _initials(name) {
  if (!name) return '?';
  const parts = String(name).trim().split(/\s+/);
  if (parts.length === 1) return parts[0][0].toUpperCase();
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}

function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
