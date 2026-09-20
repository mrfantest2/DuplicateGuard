# Security

DuplicateGuard performs destructive-capable filesystem operations, so issues involving quarantine, restore, purge, path protection, hash validation, symlink/reparse handling, or localhost API authorization should be treated as security-sensitive.

Do not publish real user file paths, quarantine metadata, diagnostics, or recovery data in public issues. Reproduce problems with synthetic paths/data whenever possible.
