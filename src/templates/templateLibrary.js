// Template library — ships 5 built-in behavioral health templates.
// Custom templates are stored in SQLite as JSON under note_templates_v1::.

import { kvGet, kvSet, kvList } from '../core/storageBackend.js';
import { genId } from '../utils/format.js';

import psychEval        from './data/psych-eval.json'          assert { type: 'json' };
import medMgmt         from './data/med-mgmt.json'            assert { type: 'json' };
import crisisAssess    from './data/crisis-assess.json'       assert { type: 'json' };
import therapyProgress from './data/therapy-progress.json'   assert { type: 'json' };
import soapGeneric     from './data/soap-generic.json'        assert { type: 'json' };
import podiatryEval    from './data/podiatry-eval.json'              assert { type: 'json' };
import podiatryFollowup from './data/podiatry-followup.json'         assert { type: 'json' };
import podiatryProc    from './data/podiatry-procedure.json'         assert { type: 'json' };
import podiatryDfe     from './data/podiatry-diabetic-foot-exam.json' assert { type: 'json' };
import podiatryWound   from './data/podiatry-wound-care.json'        assert { type: 'json' };
import podiatryRfc     from './data/podiatry-routine-foot-care.json'  assert { type: 'json' };
import podiatryOrthotic from './data/podiatry-orthotic.json'         assert { type: 'json' };

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

// List all templates (built-in + custom), sorted: built-in first.
export function listTemplates() {
  const custom = kvList('note_templates_v1::').map(key => kvGet(key)).filter(Boolean);
  return [...BUILT_IN, ...custom];
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
