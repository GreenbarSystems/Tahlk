# ADR 0007 — On-screen content protection (screen-capture exclusion)

- **Status:** Accepted — 2026-07-25
- **Deciders:** product owner + engineering
- **Related:** open-item OPS-2; `docs/security/hipaa-risk-assessment.md` §3

## Context

Tahlk displays PHI on screen — notes, transcripts, patient names. Nothing today
excludes the app window from **screen capture**, so any screen-recording,
screen-sharing, or remote-support tool running on the device (Zoom, Teams,
Loom, TeamViewer, OS screen recording, etc.) can capture PHI off the screen.
This is a desktop-specific exposure with no in-app control, flagged as OPS-2.

Tauri 2 exposes a per-window **content-protection** flag
(`WebviewWindow::set_content_protected(true)`, or `contentProtected` in
`tauri.conf.json`). It maps to:

- **macOS:** `NSWindowSharingType = .none` — the window is blank in captures.
- **Windows:** `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` — same effect.
- **Linux:** **not supported** — no reliable equivalent, the flag is a no-op
  (the same platform gap ADR 0004's biometric option hit).

## The tradeoff

Content protection is a genuine confidentiality control, but it is **not free**:
turning it on makes the window appear **black/blank** to every screen-capture
consumer, including *legitimate* ones — telehealth where a clinician shares a
note with a patient or supervisor, remote IT support, and training/recording.
For a behavioral-health tool those legitimate uses are real, so a
default-on-everywhere flag would silently break workflows and generate "why is
my screen-share black?" support load. It also does nothing on Linux, so it must
never be presented as a guaranteed control.

## Decision

1. **Ship it as an opt-in Settings toggle** — "Hide window from screen capture"
   — **default OFF**, so no existing workflow changes silently. A practice that
   wants the protection enables it; the copy explains it prevents PHI appearing
   in screen recordings/shares **and** that it will make the window blank during
   legitimate screen-sharing, and that it has no effect on Linux. The stored
   setting is applied to the main window at startup and on toggle. *(Tracked as
   the implementation follow-up under OPS-2; the mechanism is a thin wrapper over
   `set_content_protected`.)*

2. **Until the toggle ships — and for Linux, and for the default-off state —
   document the exposure as an operational caution** in the HIPAA risk
   assessment and provider-facing setup guidance: providers must not screen-
   share or screen-record a device showing PHI to an unauthorized audience, and
   should treat remote-support sessions as a PHI-exposure event.

Rejected: **default-on** (breaks telehealth/support silently, and is a
false sense of security on Linux where it no-ops); and **config-only
`contentProtected: true`** (all-or-nothing, same default-on problem, no way for
a provider to disable it for a legitimate share).

## Consequences

- The exposure is named and has an owner; the control is available to practices
  that want it without imposing a surprising default on those that don't.
- Because the control is opt-in and platform-limited, the **operational caution
  remains the primary safeguard** and must stay in the provider docs even after
  the toggle ships — the toggle strengthens it, it does not replace it.
- Revisit if a future requirement makes default-on acceptable (e.g., a
  deployment profile with no telehealth), or if Linux gains a real equivalent.
