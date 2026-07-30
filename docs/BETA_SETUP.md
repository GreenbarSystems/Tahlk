# Welcome to the Tahlk Beta

Thank you for helping test Tahlk. This guide gets you up and running.

> **Please use test data only during the beta.** Do not enter real patient
> information yet. The agreements that cover real patient use are not in place
> during this phase.

## What you'll need

Nothing to prepare in advance. Tahlk is a single installer with everything
inside it — including the speech-recognition model, which is why the download is
around 160 MB. There is no API key to obtain and no account to create first.

You will need:

- **Windows 10 or 11**, 64-bit.
- **A microphone** your computer can already record from.
- **About 500 MB of free disk space.**

## Installing Tahlk

1. Run the installer you were given.
2. Tahlk installs **for your user account only**, so it will not ask for
   administrator rights.
3. When it finishes, open **Tahlk** from your Start menu.

> If Windows shows a blue "Windows protected your PC" pop-up, please stop and
> tell us before clicking through. The release you were given is
> digitally signed, so that warning should not appear — if it does, we want to
> know rather than have you work around it.

## Setting up

The first launch walks you through three things. All three are required.

**1. Create your password.** This password encrypts every note, transcript, and
recording on your device. Tahlk cannot recover it for you and there is no reset
link — the encryption is the point.

**2. Save your three recovery codes.** Tahlk shows them one at a time and lets
you save each to a file. **Save all three, somewhere separate from your
computer.** Any one of them can get you back in if you forget your password. If
you lose the password *and* all three codes, your notes cannot be recovered by
anyone, including us.

**3. Your profile and agreements.** Enter your name, credentials (e.g. MD,
LCSW), and your **practice state** — the state determines your record-retention
window, recording-consent rules, and breach-notification requirements, so please
set it accurately. Then read and accept the BAA and EULA covering how Tahlk
processes protected health information.

There is no API-key step. Tahlk connects to the note-generation service on your
behalf; nothing to paste, nothing to configure.

## Recording a session

1. **+ New Session** to start.
2. **Start Recording**, then **Stop Recording** when the visit is over.
3. **Transcribe** turns the recording into text. This runs entirely on your own
   computer and works offline — a long session takes a few minutes.
4. **Generate Note** drafts the clinical note.
5. **Review and edit.** The draft is fully editable, and reviewing it is your
   clinical responsibility — the note is a draft until you sign it.
6. **Sign & Attest Note** locks in the final version.
7. Optionally export or copy the note into your EHR.

## Where your data goes

- **Audio and transcripts never leave your computer.** Recording and
  transcription are entirely local.
- **Notes, transcripts, recordings, and the audit trail are encrypted at rest**
  on your device, under your password.
- **When you click Generate Note**, the transcript text is sent to Greenbar
  Systems' processing service, which passes it to Anthropic under agreements
  that cover protected health information. Nothing else is sent — not the
  patient name, not the date of birth, not your roster, not previous notes.
- **Exported files are not encrypted.** Once you save a note as .txt or .pdf,
  protecting that file is up to you — save exports only somewhere secure.

## Things worth knowing

**Tahlk locks itself.** After a period of inactivity (2 minutes by default) it
locks and asks for your password again, and it will always lock after a maximum
session length regardless of activity. Both are adjustable in
**Settings → Screen lock**. It will not lock in the middle of a recording.

**Updates are manual.** There is no auto-update during the beta. If we ship a
fix, we will send you a new installer to run over the top.

## If something goes wrong

Please tell us — especially anything that looks like data loss, a note that
appears wrong, or a warning message you did not expect.

It helps enormously if you include the diagnostics log. It is **off by default**
and contains no patient information — only technical events. To send it:

**Settings → Diagnostics → turn on Diagnostics → reproduce the problem →
Export Log**, then attach the file.

## Known limits during this beta

- **Windows only.** No macOS build yet.
- **Test data only.** See the note at the top.
- **English only** for transcription.
