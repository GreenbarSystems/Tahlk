// Templates view — browse built-in templates, create custom.

import { listTemplates } from '../templates/templateLibrary.js';
import { escapeHtml } from '../utils/format.js';
import { specialtyLabel } from '../domain/specialties.js';

export function renderTemplatesView() {
  const templates = listTemplates();

  return `
    <div class="templates-page">
      <div class="templates-header">
        <h2 class="settings-title">Note Templates</h2>
      </div>
      <div class="templates-grid">
        ${templates.map(t => renderTemplateCard(t)).join('')}
      </div>
    </div>
  `;
}

function renderTemplateCard(t) {
  return `
    <div class="template-card ${t.custom ? 'template-card--custom' : ''}">
      <div class="tc-name">${escapeHtml(t.name)}</div>
      <div class="tc-specialty">${escapeHtml(specialtyLabel(t.specialty))}</div>
      <div class="tc-sections">${escapeHtml((t.sections || []).slice(0, 4).join(' · '))}${(t.sections || []).length > 4 ? ' …' : ''}</div>
      ${t.custom ? '<span class="tc-badge">Custom</span>' : '<span class="tc-badge tc-badge--builtin">Built-in</span>'}
    </div>
  `;
}

