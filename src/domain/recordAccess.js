// Record-access logging predicate (domain logic, no imports — deliberately
// dependency-free so this is unit-testable without pulling in entry-solo.js's
// full import graph, which transitively reaches jspdf/pdfExport.js and
// cannot load outside a browser-like environment).
//
// See HIPAA risk assessment §4, remediation item 1: "add a record_viewed/
// encounter_opened audit event on opening an encounter panel, at minimum for
// encounters with signed notes or transcripts."
//
// 'recording' is the only status excluded: it means the provider is actively
// creating the encounter (nothing yet exists to view — the open IS the
// creation), not accessing an existing record. Every other status
// (recording_done, transcribing, draft, signed, exported) already has at
// least a transcript or note in it, so this is a superset of the doc's
// stated minimum bar, not a narrower one.
export function shouldLogRecordView(encounter) {
  return !!encounter && encounter.status !== 'recording';
}
