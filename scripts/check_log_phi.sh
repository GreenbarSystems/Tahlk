#!/usr/bin/env bash
#
# PHI-in-logs regression guardrail (CI Layer 1).
#
# tauri_plugin_log writes the app log to the OS standard log directory, which
# lives OUTSIDE app_data_dir() and therefore outside this app's encryption and
# 0600-permission boundary. A contributor who writes e.g.
# `log::error!("{transcript}")` would silently land PHI as plaintext on disk.
#
# This is a BLUNT static check: it scans every `log::` macro line under
# src-tauri/src/ and fails if the line mentions any obviously-PHI-named token.
# Limitations (accepted on purpose):
#   * substring, case-insensitive — `note` matches `footnote`, `content` matches
#     `content_type`, etc. False positives are preferred over a missed leak;
#     rename the local or restructure the log call to appease it.
#   * it cannot follow a variable's value, so `let x = transcript; log!("{x}")`
#     slips through. The runtime redaction wrapper (log_safety.rs) is the
#     defense-in-depth second layer for what this can't see.
#   * only single-line `log::` calls are inspected.
#
# Exit 0 = clean, exit 1 = a forbidden token appeared on a log line.

set -euo pipefail

# Resolve repo root from this script's location so it runs the same locally and
# in CI regardless of the working directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="${SCRIPT_DIR}/../src-tauri/src"

# Field/variable names that strongly imply PHI. Substring, case-insensitive.
FORBIDDEN="transcript|note|content|patient|provider_name|chief_complaint"

# Collect log:: macro lines (with file:line) across all .rs files, then filter
# for the forbidden tokens. grep exits non-zero when nothing matches, which is
# the success case here, so guard both greps with `|| true`.
log_lines="$(grep -rniE 'log::(error|warn|info|debug|trace)!' "${SRC_DIR}" --include='*.rs' || true)"
violations="$(printf '%s\n' "${log_lines}" | grep -iE "${FORBIDDEN}" || true)"

if [ -n "${violations}" ]; then
  echo "ERROR: log:: call(s) reference a PHI-named token (${FORBIDDEN})." >&2
  echo "The app log is unencrypted and outside app_data_dir() — never log PHI." >&2
  echo "Offending lines:" >&2
  printf '%s\n' "${violations}" >&2
  exit 1
fi

echo "log-PHI guardrail: clean (no forbidden tokens in log:: calls)."
