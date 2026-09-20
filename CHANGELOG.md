# Changelog

This changelog combines facts recoverable from the original source archives and running binary. Where exact source was not recovered, the entry is explicitly marked.

## v2.3.0 — recovered binary release

**Source status:** authentic installer recovered; matching source tree not recovered.

Observed in the recovered/running binary:
- Local localhost dashboard remains operational.
- Duplicate scan and quarantine workflows remain present.
- Storage analyzer UI is present with folder exploration, largest-file analysis, storage categories, overlap analysis, warnings, pause/resume/cancel controls, and duplicate-root handoff.
- English/Arabic and privacy-mode UI hooks are present.

Exact original v2.3.0 source-level changelog was not recovered, so no unsupported implementation claims are made here.

## v2.1.1 — Reload and lifecycle fix

Recovered release notes document:
- Removal of the English startup reload loop.
- In-place English/Arabic switching.
- Global Exit DuplicateGuard toolbar control.
- Windows notification-area icon with open/recovery/exit actions.
- `DuplicateGuard.exe --exit` support.
- Exit shortcut in Start Menu.
- Safer upgrade behavior: graceful shutdown before replacement, with fallback termination for unresponsive older builds.
- Core SHA-256 duplicate-safety engine unchanged from hardened v2.1.0.

## v2.1.0

Two distinct recovered source snapshots exist and are preserved exactly. They differ in installer, web UI, tests, scan logic, types, README, and release notes. Neither artifact has been discarded.

## v2.0.0

Recovered source introduces the multi-file application layout, installer, quarantine engine, scan engine, storage helpers, platform-specific Windows code, and expanded web UI.

## v1.0.0

Earliest recovered source archive. Single-main implementation plus embedded web dashboard and Windows build script.
