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
