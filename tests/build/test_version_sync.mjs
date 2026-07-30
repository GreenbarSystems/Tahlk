// The app's version is declared in three places, independently, with nothing
// tying them together:
//
//   package.json            -> "version"
//   src-tauri/Cargo.toml    -> [package] version
//   src-tauri/tauri.conf.json -> "version"   (explicit, so it does NOT inherit
//                                             from package.json)
//
// docs/RELEASE.md tells a human to "bump version in tauri.conf.json and
// src-tauri/Cargo.toml together" — and does not even mention package.json. A
// prose instruction is not a control.
//
// This matters more than ordinary tidiness because tauri.conf.json's value is
// what gets stamped into the installer and shown in Windows' Programs and
// Features. If it drifts from the tag and the crate, a beta tester reports a
// bug against a version string that does not identify the build they are
// running — and the diagnostics they send name the wrong one too. For an app
// distributed as a download with no auto-update, "which build is this?" is the
// first question of every support conversation.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const root = new URL('../../', import.meta.url);
const read = p => readFileSync(new URL(p, root), 'utf8');

function packageJsonVersion() {
  return JSON.parse(read('package.json')).version;
}

function tauriConfVersion() {
  return JSON.parse(read('src-tauri/tauri.conf.json')).version;
}

// Deliberately not a TOML parser: this reads the [package] version only, and
// pulling in a dependency to do it would be more machinery than the check.
// Anchored to the first `version = "..."` after `[package]` so a dependency's
// version can never be mistaken for the crate's.
function cargoTomlVersion() {
  const toml = read('src-tauri/Cargo.toml');
  const pkg = toml.split(/^\[/m).find(section => section.startsWith('package]'));
  assert.ok(pkg, 'Cargo.toml must have a [package] section');
  const m = pkg.match(/^\s*version\s*=\s*"([^"]+)"/m);
  assert.ok(m, 'Cargo.toml [package] must declare a version');
  return m[1];
}

test('package.json, Cargo.toml and tauri.conf.json declare the same version', () => {
  const pkg = packageJsonVersion();
  const cargo = cargoTomlVersion();
  const tauri = tauriConfVersion();

  assert.equal(
    cargo, pkg,
    `src-tauri/Cargo.toml (${cargo}) disagrees with package.json (${pkg}) — bump all three together`,
  );
  assert.equal(
    tauri, pkg,
    `src-tauri/tauri.conf.json (${tauri}) disagrees with package.json (${pkg}) — this is the one stamped into the installer`,
  );
});

test('the version is a plain semver triple the installer can carry', () => {
  // Tauri/NSIS reject a version it cannot parse as a numeric triple, and that
  // failure surfaces late — during bundling in the release job, after the
  // build has already spent its time. Catch it here instead.
  const v = packageJsonVersion();
  assert.match(
    v, /^\d+\.\d+\.\d+$/,
    `version "${v}" must be a bare MAJOR.MINOR.PATCH triple — pre-release suffixes belong on the git tag, not in the bundled version`,
  );
});
