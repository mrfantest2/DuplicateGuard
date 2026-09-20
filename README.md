# DuplicateGuard

DuplicateGuard is a local Windows duplicate-file and storage-management utility designed around conservative file safety. It verifies duplicate content with SHA-256 before quarantine and keeps recoverable metadata locally.

## Current archival status

- **Latest recovered binary:** `v2.3.0` Windows x64 installer.
- **Latest recovered source:** `v2.1.1`.
- **Repository source tree:** the exact recovered `v2.1.1` source, validated again during repository recovery.
- **Historical source archives:** v1.0.0, v2.0.0, two distinct v2.1.0 snapshots, and v2.1.1 are preserved under `archive/original-source-zips/` and in the GitHub release assets.

No authentic v2.2.0 or v2.3.0 source tree was found in the recovered ChatGPT library or on the Master PC. The repository therefore does **not** relabel v2.1.1 code as v2.3.0 source. See [`docs/SOURCE_RECOVERY_STATUS.md`](docs/SOURCE_RECOVERY_STATUS.md).

## What DuplicateGuard does

- Finds byte-for-byte duplicate files using staged size/hash checks and SHA-256 verification.
- Protects the retained copy so the final valid copy cannot be quarantined.
- Moves selected duplicate copies into a restorable local quarantine.
- Maintains recovery metadata, backups, audit data, and diagnostics under Local AppData.
- Protects Windows/application paths, reparse points, offline/recall files, cloud-sync locations, and hard links conservatively.
- Provides a localhost-only browser dashboard with a random session token.
- Includes English/Arabic UI support in the recovered v2.1.1 source.
- The recovered v2.3.0 binary additionally exposes the newer storage analyzer UI found in the running application.

## Privacy model

DuplicateGuard binds its dashboard to `127.0.0.1`. The recovered source contains no remote web assets and no upload workflow for scanned file contents.

## Build from recovered source

Requirements: Go 1.23+ and Windows x64 for the standard batch workflow.

```powershell
build_windows.bat
```

The build script runs tests and vet, builds `DuplicateGuard.exe`, embeds it into the installer payload, and builds `DuplicateGuard_Setup.exe`.

See [`docs/BUILD.md`](docs/BUILD.md) for reproducible commands and validation details.

## Installation

Use the GitHub **v2.3.0** release asset `DuplicateGuard_v2.3.0_Setup_Windows_x64.exe`. It installs per-user under `%LOCALAPPDATA%\Programs\DuplicateGuard` and does not require administrator access in the recovered installer behavior.

Always compare the installer checksum with [`release/checksums-SHA256.txt`](release/checksums-SHA256.txt).

## Repository map

- `*.go`, `web/`, `installer/` — latest recovered source (v2.1.1)
- `docs/` — build, installation, architecture/recovery, and historical documentation
- `archive/original-source-zips/` — exact source ZIP artifacts recovered from ChatGPT
- `release/` — checksums and release manifest
- `.github/workflows/ci.yml` — automated Go test/vet and Windows cross-build validation

## Safety note

Quarantine is intentionally separate from permanent purge. Review duplicate groups before destructive actions, especially when using synced folders, removable media, network locations, or application data.

## License

No open-source license was present in the recovered project artifacts. Publication of the source in this repository should not be interpreted as granting additional reuse rights beyond those provided by the repository owner.
