// Single source of truth for the provider's US jurisdiction (state).
//
// Nearly every state patient-protection obligation Tahlk touches — medical-
// record retention floors, recording-consent (wiretap) rules, breach-
// notification timelines, behavioral-health confidentiality — is STATE-specific.
// The app previously captured no state at all and silently assumed Arizona in
// the retention module. This module lets onboarding/Settings capture the
// provider's state and gives the rest of the app one place to reason about it.
//
// IMPORTANT: the legal classifications below are engineering aids for prompting
// and guidance, NOT legal advice. They are deliberately CONSERVATIVE (they err
// toward asking for stronger patient protection) and must be verified against
// current statute by licensed counsel in each state of operation. See
// docs/compliance/state-retention-reference.md.

// 50 states + DC. `value` is the USPS 2-letter code (what we store on the
// provider profile); `label` is the display name. Territories are not yet
// covered — a provider practicing in one should consult counsel directly.
export const US_STATES = [
  { value: 'AL', label: 'Alabama' },        { value: 'AK', label: 'Alaska' },
  { value: 'AZ', label: 'Arizona' },        { value: 'AR', label: 'Arkansas' },
  { value: 'CA', label: 'California' },      { value: 'CO', label: 'Colorado' },
  { value: 'CT', label: 'Connecticut' },    { value: 'DE', label: 'Delaware' },
  { value: 'DC', label: 'District of Columbia' },
  { value: 'FL', label: 'Florida' },        { value: 'GA', label: 'Georgia' },
  { value: 'HI', label: 'Hawaii' },         { value: 'ID', label: 'Idaho' },
  { value: 'IL', label: 'Illinois' },       { value: 'IN', label: 'Indiana' },
  { value: 'IA', label: 'Iowa' },           { value: 'KS', label: 'Kansas' },
  { value: 'KY', label: 'Kentucky' },       { value: 'LA', label: 'Louisiana' },
  { value: 'ME', label: 'Maine' },          { value: 'MD', label: 'Maryland' },
  { value: 'MA', label: 'Massachusetts' },  { value: 'MI', label: 'Michigan' },
  { value: 'MN', label: 'Minnesota' },      { value: 'MS', label: 'Mississippi' },
  { value: 'MO', label: 'Missouri' },       { value: 'MT', label: 'Montana' },
  { value: 'NE', label: 'Nebraska' },       { value: 'NV', label: 'Nevada' },
  { value: 'NH', label: 'New Hampshire' },  { value: 'NJ', label: 'New Jersey' },
  { value: 'NM', label: 'New Mexico' },     { value: 'NY', label: 'New York' },
  { value: 'NC', label: 'North Carolina' }, { value: 'ND', label: 'North Dakota' },
  { value: 'OH', label: 'Ohio' },           { value: 'OK', label: 'Oklahoma' },
  { value: 'OR', label: 'Oregon' },         { value: 'PA', label: 'Pennsylvania' },
  { value: 'RI', label: 'Rhode Island' },   { value: 'SC', label: 'South Carolina' },
  { value: 'SD', label: 'South Dakota' },   { value: 'TN', label: 'Tennessee' },
  { value: 'TX', label: 'Texas' },          { value: 'UT', label: 'Utah' },
  { value: 'VT', label: 'Vermont' },        { value: 'VA', label: 'Virginia' },
  { value: 'WA', label: 'Washington' },     { value: 'WV', label: 'West Virginia' },
  { value: 'WI', label: 'Wisconsin' },      { value: 'WY', label: 'Wyoming' },
];

const _STATE_NAMES = Object.fromEntries(US_STATES.map(s => [s.value, s.label]));

/// True when `code` is a recognized 2-letter jurisdiction value.
export function isValidState(code) {
  return typeof code === 'string' && Object.prototype.hasOwnProperty.call(_STATE_NAMES, code);
}

/// Display name for a state code, or the code itself (or '' for empty) as a
/// fallback so a stale/unknown value never renders as "undefined".
export function stateName(code) {
  if (!code) return '';
  return _STATE_NAMES[code] || code;
}

// ── Recording-consent (wiretap) regime ──────────────────────────────────────
//
// States requiring ALL parties to consent before a confidential communication
// may be recorded. Recording a patient encounter without consent in one of
// these states can be a CRIMINAL wiretap violation (finding S1). This set is
// deliberately conservative: it includes states whose statutes or case law are
// commonly read as all-party for in-person confidential conversations, plus
// several where the rule is genuinely contested — because in a contested state
// the safe default for a therapy recording is to obtain affirmative consent
// anyway. A state NOT in this set is treated as one-party (consent of the
// recording party — the provider — suffices), which is the federal baseline.
//
// Verify against current statute; do not treat this as a legal determination.
export const ALL_PARTY_CONSENT_STATES = new Set([
  'CA', 'CT', 'DE', 'FL', 'IL', 'MD', 'MA', 'MI', 'MT', 'NV', 'NH', 'OR', 'PA', 'WA',
]);

/// True when the provider's state is (conservatively) an all-party-consent
/// jurisdiction, so the consent-to-record flow must require affirmative
/// patient consent rather than treating provider consent as sufficient.
/// Unknown/empty state → returns `true` (fail safe: prompt for the stronger
/// consent when we don't know where the provider practices).
export function requiresAllPartyConsent(code) {
  if (!isValidState(code)) return true;
  return ALL_PARTY_CONSENT_STATES.has(code);
}
