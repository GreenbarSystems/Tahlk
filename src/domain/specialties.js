// Single source of truth for provider specialties.
//
// - PICKER_SPECIALTIES: ordered list rendered in the settings + onboarding
//   specialty <select>s. Adding a new specialty for provider profiles happens
//   here and only here.
// - SPECIALTY_LABELS: display map used by any view that renders a specialty
//   value to a human label. Includes 'general' because built-in templates
//   (e.g. soap-generic) carry that value even though it isn't a provider
//   choice — so the map is a superset of the picker.
// - specialtyLabel(v): fallback-safe lookup for template cards and settings.

export const PICKER_SPECIALTIES = [
  { value: 'psychiatry',        label: 'Psychiatry' },
  { value: 'behavioral-health', label: 'Behavioral Health / Therapy' },
  { value: 'psychology',        label: 'Psychology' },
  { value: 'podiatry',          label: 'Podiatry' },
  { value: 'other',             label: 'Other' },
];

export const SPECIALTY_LABELS = {
  ...Object.fromEntries(PICKER_SPECIALTIES.map(s => [s.value, s.label])),
  // Template-only value carried by soap-generic; not selectable in provider pickers.
  general: 'General',
};

export function specialtyLabel(v) {
  return SPECIALTY_LABELS[v] || v;
}

// Specialty families group related provider/template specialties so the
// template picker can rank "close enough" templates above unrelated ones.
// A psychologist with no psychology-specific template should still see the
// behavioral-health family first — not a podiatry template. Specialties with
// no family entry (e.g. 'other', 'general', unset) match nothing here and
// fall back to the generic SOAP default. Keep this the single place that
// encodes cross-specialty affinity.
const SPECIALTY_FAMILIES = {
  psychiatry: 'behavioral-health',
  'behavioral-health': 'behavioral-health',
  psychology: 'behavioral-health',
  podiatry: 'podiatry',
};

// Family bucket for a specialty value, or null when it belongs to none.
export function specialtyFamily(v) {
  return SPECIALTY_FAMILIES[v] || null;
}
