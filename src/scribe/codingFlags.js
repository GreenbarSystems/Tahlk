// Specialty coding flags — lightweight Claude call that runs after note generation.
// Reads the API key from the same KV store as the note generator.
// Returns structured billing suggestions; stores them per encounter so they survive
// closing and reopening the panel.

import { kvGet, kvSet } from '../core/storageBackend.js';

const FLAGS_KEY = id => `note_flags_v1::${id}`;
const MODEL    = 'claude-haiku-4-5-20251001';

// ── Public API ────────────────────────────────────────────────────────────────

export async function extractCodingFlags(note, transcript, specialty, encounterId) {
  const apiKey = kvGet('note_settings_v1::anthropic_api_key');
  if (!apiKey) return null;

  const family = _family(specialty);
  try {
    const resp = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type':    'application/json',
        'x-api-key':       apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model:      MODEL,
        max_tokens: 1024,
        system:     _systemPrompt(family),
        messages: [{
          role:    'user',
          content: `Clinical note:\n${note}\n\nTranscript excerpt:\n${transcript.substring(0, 2000)}`,
        }],
      }),
    });

    if (!resp.ok) return null;
    const data = await resp.json();
    const text = data.content?.[0]?.text || '';
    const match = text.match(/\{[\s\S]*\}/);
    if (!match) return null;
    const flags = JSON.parse(match[0]);
    flags._family = family;
    if (encounterId) kvSet(FLAGS_KEY(encounterId), flags);
    return flags;
  } catch (e) {
    console.error('Coding flags failed:', e);
    return null;
  }
}

export function loadCodingFlags(encounterId) {
  return kvGet(FLAGS_KEY(encounterId)) || null;
}

// ── Render ────────────────────────────────────────────────────────────────────

export function renderFlagsCard(flags) {
  if (!flags) return '';
  const family = flags._family || 'general';
  const parts = [];

  // CPT codes
  if (flags.cpt_codes?.length) {
    parts.push(`
      <div class="flags-group">
        <div class="flags-group-title">CPT Codes</div>
        ${flags.cpt_codes.map(c => `
          <div class="flag-item flag-item--code">
            <div class="flag-code-main">
              <span class="flag-code">${esc(c.code)}</span>
              <span class="flag-desc">${esc(c.description)}</span>
              <span class="flag-confidence flag-confidence--${c.confidence || 'medium'}">${c.confidence || 'medium'}</span>
            </div>
            <div class="flag-rationale">${esc(c.rationale)}</div>
            <button class="btn-flag-copy" data-copy="${esc(c.code)}" title="Copy code">Copy</button>
          </div>`).join('')}
      </div>`);
  }

  // ICD-10 / DSM-5 codes (BH)
  if (family === 'behavioral-health' && flags.icd10_codes?.length) {
    parts.push(`
      <div class="flags-group">
        <div class="flags-group-title">Diagnosis Codes (ICD-10)</div>
        ${flags.icd10_codes.map(c => `
          <div class="flag-item flag-item--code">
            <div class="flag-code-main">
              <span class="flag-code">${esc(c.code)}</span>
              <span class="flag-desc">${esc(c.description)}</span>
            </div>
            <div class="flag-rationale">${esc(c.rationale)}</div>
            <button class="btn-flag-copy" data-copy="${esc(c.code)}" title="Copy code">Copy</button>
          </div>`).join('')}
      </div>`);
  }

  // Modifier 25 alert (podiatry)
  if (family === 'podiatry' && flags.modifier_25) {
    const m = flags.modifier_25;
    if (m.applicable) {
      parts.push(`
        <div class="flags-group">
          <div class="flags-group-title">Modifier Alert</div>
          <div class="flag-item flag-item--modifier">
            <div class="flag-code-main">
              <span class="flag-code">–25</span>
              <span class="flag-desc">Modifier 25 — Separate E&amp;M on procedure day</span>
            </div>
            <div class="flag-rationale">${esc(m.rationale)}</div>
            <button class="btn-flag-copy" data-copy="-25" title="Copy modifier">Copy</button>
          </div>
        </div>`);
    }
  }

  // E&M level (podiatry)
  if (family === 'podiatry' && flags.em_level?.suggested) {
    const em = flags.em_level;
    parts.push(`
      <div class="flags-group">
        <div class="flags-group-title">E&amp;M Level</div>
        <div class="flag-item flag-item--code">
          <div class="flag-code-main">
            <span class="flag-code">${esc(em.suggested)}</span>
            <span class="flag-desc">Suggested E&amp;M level</span>
          </div>
          <div class="flag-rationale">${esc(em.rationale)}</div>
          <button class="btn-flag-copy" data-copy="${esc(em.suggested)}" title="Copy code">Copy</button>
        </div>
      </div>`);
  }

  // Documentation gaps
  if (flags.documentation_gaps?.length) {
    parts.push(`
      <div class="flags-group">
        <div class="flags-group-title">Documentation Gaps</div>
        ${flags.documentation_gaps.map(g => `
          <div class="flag-item flag-item--gap flag-item--${g.severity || 'warning'}">
            <span class="flag-gap-icon">${g.severity === 'error' ? '✕' : '⚠'}</span>
            <span class="flag-gap-text">${esc(g.issue)}</span>
          </div>`).join('')}
      </div>`);
  }

  if (!parts.length) return '';
  return parts.join('');
}

export function wireFlagsCard() {
  document.querySelectorAll('.btn-flag-copy').forEach(btn => {
    btn.addEventListener('click', () => {
      const code = btn.dataset.copy || '';
      navigator.clipboard.writeText(code).catch(() => {});
      const orig = btn.textContent;
      btn.textContent = 'Copied!';
      setTimeout(() => { btn.textContent = orig; }, 1500);
    });
  });
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function _family(specialty) {
  if (!specialty) return 'general';
  const s = specialty.toLowerCase();
  if (s.includes('podiat')) return 'podiatry';
  if (s.includes('psych') || s.includes('behav') || s.includes('therapy') || s.includes('mental'))
    return 'behavioral-health';
  return 'general';
}

function _systemPrompt(family) {
  if (family === 'podiatry') {
    return `You are a podiatry billing specialist. Analyze the clinical note and transcript, then return ONLY a JSON object (no other text) with coding suggestions.

JSON format:
{
  "cpt_codes": [{"code":"string","description":"string","rationale":"string","confidence":"high|medium|low"}],
  "modifier_25": {"applicable":boolean,"rationale":"string"},
  "em_level": {"suggested":"string","rationale":"string"},
  "documentation_gaps": [{"issue":"string","severity":"warning|error"}]
}

Rules:
- Modifier 25: true when a separately identifiable E&M service is documented alongside a procedure on the same date
- E&M: 99211-99215 based on medical decision making (MDM) complexity
- Common podiatry CPT: 11721 (nail debridement ≥6), 11055-11057 (benign lesion), 11730 (nail avulsion), 97010 (hot/cold pack), 29540 (ankle strapping)
- Gap: flag if "medically necessary" language is absent for any procedure
- Gap: flag if MDM documentation is thin for the suggested E&M level
- Return empty arrays if nothing applies`;
  }

  if (family === 'behavioral-health') {
    return `You are a behavioral health billing specialist. Analyze the clinical note and transcript, then return ONLY a JSON object (no other text) with coding suggestions.

JSON format:
{
  "cpt_codes": [{"code":"string","description":"string","rationale":"string","confidence":"high|medium|low"}],
  "icd10_codes": [{"code":"string","description":"string","rationale":"string"}],
  "documentation_gaps": [{"issue":"string","severity":"warning|error"}]
}

Rules:
- CPT by service type: 90791 (psychiatric eval), 90837 (therapy 53+ min), 90834 (therapy 38-52 min), 90832 (therapy 16-37 min), 90833 (add-on psychotherapy with E&M), 99213-99215 (medication management)
- ICD-10: suggest F-codes for documented diagnoses (e.g. F32.1 MDD moderate, F41.1 GAD, F33.0 MDD recurrent mild)
- Gap: flag missing session duration (required to select therapy CPT)
- Gap: flag missing DSM-5 diagnosis on intake notes
- Gap: flag missing diagnosis code on progress notes (billing continuity)
- Return empty arrays if nothing applies`;
  }

  return `You are a medical billing specialist. Analyze the clinical note and return ONLY a JSON object:
{"cpt_codes":[{"code":"string","description":"string","rationale":"string","confidence":"high|medium|low"}],"documentation_gaps":[{"issue":"string","severity":"warning|error"}]}`;
}

function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;').replace(/"/g, '&quot;')
    .replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
