// Export/generation-structure consistency check — advisory only.
//
// Every template in templates/data/*.json declares a `sections` array (e.g.
// psych-eval.json requires "Risk Assessment"). That array is currently used
// ONLY as a display preview in templatesView.js — it is never checked
// against what the LLM actually produced. The systemPrompt tells the model
// to include those sections, but LLM output is not guaranteed to comply:
// a truncated response, a model that skips a section it had nothing to say
// about, or a provider's manual edit before signing can all silently drop a
// section — including a compliance-critical one like "Risk Assessment" on a
// psychiatric eval or "Safety Plan" on a crisis assessment — with nothing in
// the app noticing before export.
//
// This module never blocks generation, signing, or export — it only reports
// what it found so the UI can show an advisory. A false positive (flagging
// a section the clinician deliberately phrased differently) must never stop
// a provider from signing or exporting their own note.

// Normalize a section label into a resilient match pattern. LLM output for
// a section named "Mental Status Examination" observed in practice varies:
// "Mental Status Examination", "**Mental Status Examination**",
// "Mental Status Examination:", "## Mental Status Examination", or the
// common initialism "MSE" the psych-eval systemPrompt itself introduces
// ("Mental Status Examination (MSE)"). We match on the normalized label
// text appearing anywhere in the note, case-insensitively — deliberately
// loose, since this is advisory and false negatives (missing a section that
// IS present) are far worse than false positives for this feature's purpose.
function normalize(s) {
  return s
    .toLowerCase()
    .replace(/\(.*?\)/g, ' ') // strip parenthetical asides like "(MSE)"
    .replace(/[^a-z0-9\s]/g, ' ') // strip markdown/punctuation (**, :, ##, /)
    .replace(/\s+/g, ' ')
    .trim();
}

// Checks whether `noteText` appears to contain each of `template.sections`.
// Returns { missing: string[], present: string[] }. An empty/missing
// `sections` array on the template (e.g. a hand-authored custom template
// that never set one) yields { missing: [], present: [] } — nothing to
// check, not a violation.
export function checkSectionCoverage(noteText, template) {
  const sections = Array.isArray(template?.sections) ? template.sections : [];
  const haystack = normalize(noteText || '');

  const missing = [];
  const present = [];
  for (const section of sections) {
    const needle = normalize(section);
    if (needle && haystack.includes(needle)) {
      present.push(section);
    } else {
      missing.push(section);
    }
  }
  return { missing, present };
}

// Plain-language summary for a toast/banner — never developer jargon (same
// principle as integrityAlert.js's INTEGRITY_FAILURE_MESSAGE: a clinician
// should see "may be missing", not "coverage check failed").
export function describeMissingSections(missing) {
  if (missing.length === 0) return '';
  if (missing.length === 1) return `This note may be missing the "${missing[0]}" section.`;
  return `This note may be missing ${missing.length} sections: ${missing.join(', ')}.`;
}
