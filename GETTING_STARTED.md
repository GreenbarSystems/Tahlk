# Getting Started with Tahlk

Tahlk is an ambient scribe that listens to a patient visit, transcribes it on
your own computer, and turns the transcript into a clinical note you review and
sign — all while keeping your data on your device.

This guide is written for clinicians. It walks through what you need, how to
open the app, what the first-run setup asks for, and how to go from a recording
to a signed note. You do not need any programming or IT background to follow it.

> **Please read first — early access still needs a hand from your technical
> contact.** Tahlk does not yet ship as a click-to-install app with a signed
> installer. Right now, getting Tahlk running on your machine the first time
> requires a developer or IT person to build and launch it using the steps in
> [SETUP.md](SETUP.md). A one-click installer is planned but not available yet,
> so we won't pretend the install is push-button today. Once someone has Tahlk
> open on your computer, **everything below describes the app experience itself**
> — and that part is designed for you, not for a developer.

> **Beta note:** Tahlk is currently in a test-data-only beta — please do not
> enter real patient information yet. The steps below describe the full app
> experience, but the BAA requirement in step 3 is not yet enforced by the
> app itself during this phase; it becomes required (with a matching setup
> step) before real PHI use is supported.

## What you'll need before you start

1. **Tahlk running on your computer.** Have your technical contact get the app
   open for you the first time using [SETUP.md](SETUP.md). After that, you open
   it like any other app.
2. **An Anthropic account and API key.** Tahlk uses Anthropic's AI (Claude) to
   draft your notes from what was said. You bring your own Anthropic account and
   key so transcripts go directly to Anthropic under your own agreement with
   them — Tahlk never stores your key on any server. The app's first-run setup
   has a built-in "How do I get one?" walkthrough, so you can create the key
   right when it asks.
3. **A signed Business Associate Agreement (BAA) with Anthropic**, before you
   ever send real patient information. Because visit transcripts are protected
   health information (PHI), HIPAA requires a BAA between your organization
   and Anthropic. During the current test-data-only beta the app does not yet
   block on this, but you should still have it in place before treating Tahlk
   as ready for real patients. If you already have one, you can record it
   voluntarily in **Settings → BAA acknowledgment** for your own audit trail.

You don't have to gather all of this before opening the app — the first-run
setup explains each item as you reach it and links out to where you get it.

## Opening the app for the first time

Once Tahlk is installed and launched, it greets you with a short welcome:
**"Welcome. Let's get you set up."** This one-time setup takes about three
minutes. Your data stays on this device.

### What the setup asks for

The welcome screen has two quick steps:

1. **Your provider profile** — your full name (required), your credentials
   (e.g. MD, PMHNP-BC, LCSW), and your specialty. Your name is what gets
   recorded as the signer on each note.
2. **Note generation API key** — paste your Anthropic API key (it starts with
   `sk-ant-`). If you don't have one yet, expand **"How do I get one?"** for a
   step-by-step. Your key is saved in your operating system's secure
   credential store (the same place your computer keeps other app passwords)
   and is never sent to any Tahlk server.

When both are filled in, click **Start using Tahlk**. Setup does not currently
ask about the Anthropic BAA (see the beta note above) — if your organization
already has one, you can record it from **Settings → BAA acknowledgment** at
any time for your own audit trail.

## Your first recording → note → sign

From the home screen, click **+ New Session** to begin a visit. Inside a
session you'll move through these steps:

1. **Record.** Click **Start Recording** to capture the visit, then **Stop
   Recording** when you're done. Audio is saved locally on your device and is
   never uploaded to a server.
2. **Transcribe.** Click **Transcribe** to turn the audio into text. Speech
   recognition (Whisper) runs entirely on your computer — the included model
   comes bundled with Tahlk, so there's nothing to download and no audio leaves
   the device. The transcript appears in an editable box.
3. **Generate the note.** Pick a note template from the dropdown, then click
   **Generate Note**. This is the step that sends the transcript to Anthropic
   (under your account and BAA) and drafts a clinical note. Review and edit the
   draft — it's fully editable until you sign.
4. **Sign.** When the note is correct, click **Sign & Attest Note**. Signing
   locks the note and records a tamper-evident (SHA-256) fingerprint of the
   exact signed content, so the record can't be silently altered afterward.
5. **Export (optional).** Copy the note to your clipboard or save it to a file
   in the format your downstream system expects.

That's the whole loop: record, transcribe, generate, review, sign. After your
first session it becomes a quick, repeatable routine.

## Where your data lives

- **Audio and transcripts stay on your device.** Transcription runs locally.
- **Only the transcript is sent to Anthropic**, and only when you click
  **Generate Note** — under your own account and BAA.
- **Your notes are stored locally** in an encrypted database on your computer.
- **Signed notes are tamper-evident** via a running SHA-256 hash chain.

## Getting help

- **Setting up the app for the first time** (installation, for your technical
  contact): [SETUP.md](SETUP.md).
- **API key questions:** the in-app setup screen has expandable help with a
  link to Anthropic's console.
- **BAA questions:** see **Settings → BAA acknowledgment** for a link to
  Anthropic's BAA request process.
