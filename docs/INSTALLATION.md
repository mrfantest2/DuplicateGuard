# Installation and operation

## Recommended recovered build

Install the recovered `DuplicateGuard_v2.3.0_Setup_Windows_x64.exe` from the GitHub v2.3.0 release and verify SHA-256 first.

## Installed location

The recovered installer behavior installs the application for the current Windows account under:

```text
%LOCALAPPDATA%\Programs\DuplicateGuard\DuplicateGuard.exe
```

Recovery/application data is stored separately under:

```text
%LOCALAPPDATA%\DuplicateGuard
```

Do not remove the recovery data directory while quarantined files may still need restoration.

## Dashboard

The application listens only on loopback. It prefers port `18473` and can fall back to a dynamically allocated local port if that port is unavailable. The UI uses a random per-process session token for protected API calls.

## Uninstall

Use Windows Settings > Apps > Installed apps > DuplicateGuard > Uninstall. The recovered design intentionally preserves Local AppData recovery data so a later reinstall can recover quarantined files.
