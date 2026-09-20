# DuplicateGuard v2.3.0 — recovered Windows release

This release restores the latest authentic DuplicateGuard Windows installer found in the project archive.

## Included assets

- Windows x64 installer for v2.3.0.
- Every recovered original source archive from v1.0.0 through v2.1.1, including both distinct v2.1.0 snapshots.
- SHA-256 checksum manifest.

## Source provenance note

The latest authentic source tree recovered is v2.1.1. No matching v2.2.0/v2.3.0 source tree was found during the migration. The repository intentionally does not relabel or reconstruct v2.1.1 as v2.3.0 source.

## Validation

The v2.3.0 installer SHA-256 is recorded in `checksums-SHA256.txt`. The recovered v2.1.1 source independently passes `go test ./...`, `go vet ./...`, and Windows amd64 cross-compilation.

## Windows warning

The historical binaries are not known to be Authenticode-signed, so Windows may display an Unknown publisher / SmartScreen warning. Verify the SHA-256 checksum before installation.
