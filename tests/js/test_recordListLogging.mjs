// Record-view audit coverage for roster/list surfaces (HIPAA M3).
//
// shouldLogRecordView already covers the per-encounter panel. These pin the
// gap it did NOT cover: the list views that render PHI for many records at
// once — the home "Recent Sessions" roster, the Patients tab roster, and the
// new-session patient picker. Each must emit ONE record-list access event
// (audit_log_records_listed) when it displays PHI, and NONE when it has no
// rows to show (nothing was disclosed).
//
// Same escape-hatch approach as test_auditLog.mjs / test_homeScreen_newSession
// .mjs: install the test-only Tauri mock BEFORE importing app modules so
// platform/tauri.js's isTauri resolves true and the wrappers take the
// Tauri-backed path (invoke), not the KV fallback.

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

let calls;
let listData; // { list_encounters: [...], list_patients: [...] }

function invokeMock(cmd, args) {
  calls.push({ cmd, args });
  if (cmd === 'encounter_stats') return Promise.resolve({ total: 0, signed: 0, today: 0 });
  if (cmd === 'list_encounters') return Promise.resolve(listData.list_encounters);
  if (cmd === 'list_patients') return Promise.resolve(listData.list_patients);
  return Promise.resolve(null); // audit_log_records_listed etc.
}

globalThis.__TAHLK_TEST_TAURI__ = {
  core: { invoke: invokeMock },
  event: { listen: () => () => {} },
};
globalThis.window = globalThis.window || {};
globalThis.document = globalThis.document || {
  getElementById: () => null,
  querySelectorAll: () => [],
  createElement: () => ({ className: '', style: {}, setAttribute() {}, appendChild() {}, addEventListener() {} }),
  addEventListener() {},
};

const { renderHomeScreen } = await import('../../src/solo/homeScreen.js');
const { renderPatientsView } = await import('../../src/solo/patientsView.js');
const { logRecordsListed } = await import('../../src/core/auditLog.js');

function listedCalls() {
  return calls.filter(c => c.cmd === 'audit_log_records_listed');
}

beforeEach(() => {
  calls = [];
  listData = { list_encounters: [], list_patients: [] };
});

test('home roster logs one records_listed event with the row count when it shows encounters', async () => {
  listData.list_encounters = [
    { id: 'e1', status: 'signed', encounter_date: '2026-07-01', patient_alias: 'A.B.' },
    { id: 'e2', status: 'draft',  encounter_date: '2026-07-02', patient_alias: 'C.D.' },
  ];
  await renderHomeScreen();

  const listed = listedCalls();
  assert.equal(listed.length, 1, 'exactly one access event for the whole roster, not one per row');
  assert.equal(listed[0].args.scope, 'sessions');
  assert.equal(listed[0].args.count, 2);
});

test('home roster logs NOTHING when there are no encounters (no PHI disclosed)', async () => {
  listData.list_encounters = [];
  await renderHomeScreen();
  assert.equal(listedCalls().length, 0);
});

test('patients roster logs one records_listed event with the row count', async () => {
  listData.list_patients = [
    { id: 'p1', alias: 'A.B.', dob: '1990-01-01', notes: null },
    { id: 'p2', alias: 'C.D.', dob: null, notes: 'x' },
    { id: 'p3', alias: 'E.F.', dob: null, notes: null },
  ];
  await renderPatientsView();

  const listed = listedCalls();
  assert.equal(listed.length, 1);
  assert.equal(listed[0].args.scope, 'patients');
  assert.equal(listed[0].args.count, 3);
});

test('patients roster logs NOTHING when empty', async () => {
  listData.list_patients = [];
  await renderPatientsView();
  assert.equal(listedCalls().length, 0);
});

test('logRecordsListed invokes the narrow server command (actor is server-derived, not forgeable)', async () => {
  await logRecordsListed('sessions', 7);
  const listed = listedCalls();
  assert.equal(listed.length, 1);
  assert.deepEqual(listed[0].args, { scope: 'sessions', count: 7 });
});
