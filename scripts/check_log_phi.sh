#!/usr/bin/env bash
#
# PHI-in-logs regression guardrail (CI Layer 1).
#
# tauri_plugin_log writes the app log to the OS standard log directory, which
# lives OUTSIDE app_data_dir() and therefore outside this app's encryption and
# 0600-permission boundary. A contributor who writes e.g.
# `log::error!("{transcript}")` would silently land PHI as plaintext on disk.
#
# This is a BLUNT static check: it scans every `log::` macro line AND every
# bare `eprintln!`/`println!` line under src-tauri/src/, and fails if the line
# mentions any obviously-PHI-named token.
#
# eprintln!/println! are included, not just log::, because of an audit
# finding (Medium, "eprintln! diagnostic calls ... invisible to the
# PHI-safety CI check"): a bare eprintln! sits entirely outside a log::-only
# scan, so a future contributor could add one that leaks PHI and this check
# would never see it.
#
# There is NO exemption mechanism, deliberately — every matching line must
# pass on its own content. notes.rs::log_upstream_body stays a bare eprintln!
# (never log::) so a dev-only upstream-error echo can't land in the
# persistent, unencrypted app log even in a debug build; it is scanned like
# everything else and passes because its tag is "[upstream]" and its
# interpolated values aren't PHI-named. If a future edit makes any line match,
# reword the call or fix the leak — don't add an exemption here.
#
# Widening this regex to cover eprintln! immediately turned up five existing
# false positives ("content protection", "note_history migration", a "[notes]"
# tag), all reworded rather than exempted, per the false-positives-are-cheap
# policy below. Expect that to happen again if FORBIDDEN grows.
#
# Limitations (accepted on purpose):
#   * substring, case-insensitive — `note` matches `footnote`, `content` matches
#     `content_type`, etc. False positives are preferred over a missed leak;
#     rename the local or restructure the log call to appease it.
#   * it cannot follow a variable's value, so `let x = transcript; log!("{x}")`
#     slips through. The runtime redaction wrapper (log_safety.rs) is the
#     defense-in-depth second layer for what this can't see.
#   * only single-line calls are inspected.
#
# Exit 0 = clean, exit 1 = a forbidden token appeared on a log line.

set -euo pipefail

# Resolve repo root from this script's location so it runs the same locally and
# in CI regardless of the working directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="${SCRIPT_DIR}/../src-tauri/src"

# Field/variable names that strongly imply PHI. Substring, case-insensitive.
FORBIDDEN="transcript|note|content|patient|provider_name|chief_complaint|ssn|dob|date_of_birth|mrn|phone|email|address|zip|postal|insurance|member_id|policy|dea|npi|first_name|last_name|birth"

# Collect log::/eprintln!/println! macro lines (with file:line) across all
# .rs files. grep exits non-zero when nothing matches, which is the success
# case here, so guard with `|| true`.
log_lines="$(grep -rniE 'log::(error|warn|info|debug|trace)!|\b(e?println)!' "${SRC_DIR}" --include='*.rs' || true)"

# Match FORBIDDEN against the CODE ONLY, never the "path:lineno:" prefix grep
# prepends. Filtering the raw grep output would test the filename too, so every
# log line in notes.rs / note_audit.rs / note_history.rs would "violate" on the
# word "note" in its own filename — permanently red, and no rewording of the
# code could ever clear it. (That is exactly what happened once eprintln! sites
# in those files were migrated to log::.) The reported line keeps its prefix so
# the failure output stays clickable.
violations=""
while IFS= read -r line; do
  [ -z "${line}" ] && continue
  code="${line#*:}"   # drop path
  code="${code#*:}"   # drop line number
  if printf '%s' "${code}" | grep -qiE "${FORBIDDEN}"; then
    violations="${violations}${line}"$'\n'
  fi
done <<< "${log_lines}"
violations="$(printf '%s' "${violations}")"

if [ -n "${violations}" ]; then
  echo "ERROR: a log::/eprintln!/println! call references a PHI-named token (${FORBIDDEN})." >&2
  echo "The app log is unencrypted and outside app_data_dir() — never log PHI." >&2
  echo "Offending lines:" >&2
  printf '%s\n' "${violations}" >&2
  exit 1
fi

echo "log-PHI guardrail: clean (no forbidden tokens in log:: calls)."
