# Tahlk
AI-native ambient scribe for behavioral health, psychiatry, and podiatry practices

## Documentation

- **Clinicians:** [GETTING_STARTED.md](GETTING_STARTED.md) — a plain-language
  walkthrough of setting up and using the app.
- **Developers / IT:** [SETUP.md](SETUP.md) — building, running, and the
  technical setup path.
- **Releasing:** [docs/RELEASE.md](docs/RELEASE.md) — building and signing a
  distributable installer.
- **Architecture decisions:** [docs/adr/](docs/adr/) — recorded decisions and
  their rationale (e.g. why the Group-tier sync service is frozen).
- **Server security:** [docs/security/pre-deploy-checklist.md](docs/security/pre-deploy-checklist.md)
  — the checklist gating any deploy of `server/` (see below).
- **Group-tier sync service:** [server/README.md](server/README.md) — a
  separate, currently **frozen** backend; not part of the Solo desktop app.
