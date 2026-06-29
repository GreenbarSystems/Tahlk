# ADR 0002 — Revert the UI component kit; defer to a scheduled UI overhaul

- **Status:** Accepted — 2026-06-29
- **Deciders:** product owner + engineering
- **Supersedes:** the `src/ui/` kit introduced in commit `0c58691`

## Context

A dependency-free UI component kit (`src/ui/`: Button, Field, Spinner,
Skeleton, ProgressBar, Banner, StatusChip, StatCard, EmptyState + an
auto-escaping `html` tag) plus `styles/ui.css` was built and adopted on the
**home screen only**. The other screens — `encounterPanel`, `settingsModal`,
`onboarding`, `soloHeader`, `templatesView` — still used inline markup and
`solo.css`. The app was left with **two coexisting UI systems** (`.btn` and
`.ui-btn`), the worst state: two ways to do everything.

The earlier tech-lead review ([ADR 0001](0001-freeze-group-tier-and-sync.md)
context) set the priority as **finish the Solo core; freeze surface area**.

## Decision

Revert the half-finished migration rather than complete it now.

Why not finish:
- Finishing means migrating all remaining screens — including
  `encounterPanel`, the core clinical workflow with imperative button-state
  wiring (`#record-label` toggling, enable/disable by id) — and extending the
  `Button` component to support it.
- That is a large diff with **regression risk we cannot verify**: there is no
  integration test for the panel's DOM wiring, and it only truly runs under
  Tauri. Risking the most important screen for consistency/cosmetics runs
  against the focus-and-simplicity priority.
- A component system is off the critical path to a trustworthy, compliant,
  shippable Solo product.

## Consequences

- Removed `src/ui/`, `styles/ui.css`, `tests/js/test_ui.mjs`; reverted the home
  screen to inline markup and dropped the `ui.css` link. One UI system again.
- The kit was good work and is **preserved in git history** (commit `0c58691`)
  — this is a deferral, not a rejection.

## When to revisit

Schedule a real UI overhaul as a single focused effort — ideally **alongside
the Group-tier web UI**, where a shared component system compounds across two
surfaces and the investment pays for itself. At that point, restore the kit
from history (or rebuild) and migrate **all** screens in one pass, with the
`encounterPanel` wiring covered by tests first. Do not re-adopt it piecemeal.
