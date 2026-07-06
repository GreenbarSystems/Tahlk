// Template library — ships 5 built-in behavioral health templates.
// Custom templates are stored in SQLite as JSON under note_templates_v1::.

import { kvGet, kvSet, kvList } from '../core/storageBackend.js';
import { genId } from '../utils/format.js';
import { specialtyFamily } from '../domain/specialties.js';

import psychEval        from './data/psych-eval.json'          with { type: 'json' };
import medMgmt         from './data/med-mgmt.json'            with { type: 'json' };
import crisisAssess    from './data/crisis-assess.json'       with { type: 'json' };
import therapyProgress from './data/therapy-progress.json'   with { type: 'json' };
import soapGeneric     from './data/soap-generic.json'        with { type: 'json' };
import podiatryEval    from './data/podiatry-eval.json'              with { type: 'json' };
import podiatryFollowup from './data/podiatry-followup.json'         with { type: 'json' };
import podiatryProc    from './data/podiatry-procedure.json'         with { type: 'json' };
import podiatryDfe     from './data/podiatry-diabetic-foot-exam.json' with { type: 'json' };
import podiatryWound   from './data/podiatry-wound-care.json'        with { type: 'json' };
import podiatryRfc     from './data/podiatry-routine-foot-care.json'  with { type: 'json' };
import podiatryOrthotic from './data/podiatry-orthotic.json'         with { type: 'json' };

const BUILT_IN = [
  psychEval, medMgmt, crisisAssess, therapyProgress, soapGeneric,
  podiatryEval, podiatryFollowup, podiatryProc, podiatryDfe, podiatryWound,
  podiatryRfc, podiatryOrthotic,
];
const BUILT_IN_MAP = new Map(BUILT_IN.map(t => [t.id, t]));

// Returns a template by id — built-in first, then custom.
export function getTemplate(id) {
  if (BUILT_IN_MAP.has(id)) return BUILT_IN_MAP.get(id);
  const key = `note_templates_v1::${id}`;
  return kvGet(key) || null;
}

const GENERIC_TEMPLATE_ID = 'soap-generic';

// Ranking for specialty-aware ordering. Lower sorts first:
//   0 — exact specialty match (a podiatrist's podiatry templates)
//   1 — same specialty family (a psychologist's behavioral-health templates)
//   2 — the generic SOAP template (a safe default for any specialty)
//   3 — everything else (kept reachable, sorted to the bottom)
// When providerSpecialty is unset/unknown, ranks 0 and 1 never match, so the
// generic SOAP template naturally becomes the top item and default.
function templateRank(t, providerSpecialty) {
  if (providerSpecialty && t.specialty === providerSpecialty) return 0;
  const family = specialtyFamily(providerSpecialty);
  if (family && specialtyFamily(t.specialty) === family) return 1;
  if (t.specialty === 'general') return 2;
  return 3;
}

// List all templates (built-in + custom). With no providerSpecialty the order
// is built-in-then-custom (unchanged legacy behavior). With a specialty, the
// list is sorted so specialty-relevant templates come first; off-specialty
// templates stay reachable at the bottom. The sort is stable, preserving the
// authored order within each rank.
export function listTemplates(providerSpecialty) {
  const custom = kvList('note_templates_v1::').map(key => kvGet(key)).filter(Boolean);
  const all = [...BUILT_IN, ...custom];
  if (!providerSpecialty) return all;
  return all
    .map((t, idx) => ({ t, idx, rank: templateRank(t, providerSpecialty) }))
    .sort((a, b) => a.rank - b.rank || a.idx - b.idx)
    .map(x => x.t);
}

// The template a fresh encounter should default to for this provider. Returns
// the top specialty-appropriate template, falling back to the generic SOAP
// template (never an arbitrary first-in-array specialty template) when the
// provider has no matching or family templates or an unset specialty.
export function defaultTemplateId(providerSpecialty) {
  const list = listTemplates(providerSpecialty);
  if (providerSpecialty) {
    const top = list[0];
    if (top && templateRank(top, providerSpecialty) <= 1) return top.id;
  }
  return BUILT_IN_MAP.has(GENERIC_TEMPLATE_ID)
    ? GENERIC_TEMPLATE_ID
    : (list[0]?.id ?? GENERIC_TEMPLATE_ID);
}

// Save a custom template. Returns the saved template.
export function saveTemplate(template) {
  const id = template.id || genId('tmpl');
  const t = { ...template, id, custom: true };
  kvSet(`note_templates_v1::${id}`, t);
  return t;
}

// Delete a custom template (built-ins cannot be deleted).
export function deleteTemplate(id) {
  if (BUILT_IN_MAP.has(id)) throw new Error('Cannot delete built-in templates');
  kvSet(`note_templates_v1::${id}`, null);
}
