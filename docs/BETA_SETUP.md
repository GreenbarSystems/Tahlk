# Tahlk Beta Setup — Quick Guide

Welcome to the Tahlk beta. This is everything you need to get the app
installed and running your first session.

## Status of this build

This is a **signed v0.1.0 installer** (Authenticode-signed, verified in CI),
but the release is currently held as a **draft** on GitHub pending a final
manual QA pass on a clean Windows machine — standard practice before wider
distribution. Two things follow from that:

1. **The Tahlk repo is public, but draft releases are not.** Only accounts
   with write access to the repo can see a draft release page or download its
   asset — being able to view the public repo itself is not enough. Each
   tester needs to be added as a collaborator (or the release needs to be
   published) before the link below will work for them.
2. **Don't share this link outside the beta group.** Expect the exact URL to
   change if the release is republished; ping your contact if it 404s.

## 1. Download

Installer: **`Tahlk_0.1.0_x64-setup.exe`** (~135 MB), from the draft release at:
`https://github.com/GreenbarSystems/Tahlk/releases/tag/untagged-fd808239fe98339de1f3`

(Yes, that URL looks odd — it's a known GitHub Actions quirk where the draft
release page doesn't inherit the clean `v0.1.0` tag name in its own URL. The
release itself is still correctly tagged `v0.1.0` internally. If this link
404s, the release has likely been republished under a new URL — ask whoever
sent you this guide for the current link.)

## 2. System requirements

- **Windows 10 or 11, 64-bit.** This beta build is Windows-only.
- A working microphone.
- No other software to install — Whisper (speech-to-text) is bundled inside
  the installer and runs entirely on your machine. Nothing to download later.

## 3. Install

1. Run `Tahlk_0.1.0_x64-setup.exe`.
2. Windows SmartScreen may still show a caution prompt the first time a new
   publisher's app runs — this is normal for a brand-new signing certificate.
   Click **More info → Run anyway** if you see it.
3. Launch **Tahlk** from the Start menu once install finishes.

## 4. Before you open the app, have these two things ready

1. **An Anthropic API key.** Tahlk uses Claude to draft notes from your
   transcripts — you bring your own Anthropic account and key. The app has a
   built-in "How do I get one?" walkthrough during setup if you don't have one
   yet.
2. **A BAA (Business Associate Agreement) with Anthropic covering that key.**
   Because visit transcripts are protected health information (PHI), Tahlk
   will not generate notes until you confirm a BAA is in place. This is a
   checkbox you personally attest to — Tahlk can't verify the paperwork
   itself, so make sure it's actually true for your account before checking it.
   The setup screen links to Anthropic's BAA request process if you haven't
   started this yet.

## 5. First-run setup (about 3 minutes)

On first launch, Tahlk walks you through three steps:

1. **Your provider profile** — name (this is what's recorded as the note
   signer), credentials, specialty.
2. **Your Anthropic API key** — pasted in, stored in Windows' secure
   credential store (never sent to any Tahlk server).
3. **BAA acknowledgment** — the checkbox from step 4 above.

Then click **Start using Tahlk**.

## 6. Your first session

**+ New Session → Start Recording → Stop Recording → Transcribe → Generate
Note → review/edit → Sign & Attest Note.** Audio and transcripts never leave
your device except the transcript text itself, which is sent to Anthropic
only at the moment you click Generate Note.

## Reporting issues

Send feedback, bugs, or anything that feels off directly to your contact —
this is a small beta group, so direct reports work better than a public
tracker for now.
