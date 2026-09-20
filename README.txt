DuplicateGuard 2.1.1 — Windows x64
==================================

Purpose
-------
DuplicateGuard locates byte-for-byte identical files and safely moves extra
copies into a restorable local quarantine. It does not classify files as
identical from names alone.

Closing the application
-----------------------
DuplicateGuard now remains visible in the Windows notification area. The icon
may be under the ^ hidden-icons button beside the clock.

- Left-click the icon to reopen the dashboard.
- Right-click it and choose Exit DuplicateGuard / إغلاق DuplicateGuard.
- A red Exit DuplicateGuard button is also available in the dashboard toolbar.
- The Start Menu contains an Exit DuplicateGuard shortcut.
- Task Manager remains the final emergency option for an unresponsive process.

Recommended installation
------------------------
1. Run DuplicateGuard_Setup.exe. Setup automatically closes an older running version before upgrading it.
2. No administrator access is required.
3. The app installs for the current Windows account and opens its local
   dashboard in the default browser.
4. Windows may display an Unknown publisher warning because this build is not
   digitally code-signed.

Portable use
------------
Run DuplicateGuard.exe directly. Keep it in a permanent folder before enabling
Start with Windows.

Safe first run
--------------
1. Keep automatic quarantine and automatic purge disabled.
2. Scan only personal folders such as Downloads, Desktop, Documents, Pictures,
   and Videos.
3. Review the KEEP decision in each duplicate group.
4. Move selected extra copies to Quarantine.
5. Keep quarantine retention at 30 days or longer.

Production safety controls
--------------------------
- SHA-256 content verification
- Size grouping before hashing
- Quick-hash cache revalidation
- Final SHA-256 recheck immediately before quarantine
- Retained-copy protection: the final valid copy cannot be selected
- Restorable quarantine with a persistent transaction record
- Interrupted-operation reconciliation on the next launch
- Restore conflict protection; existing files are never overwritten
- Quarantine hash verification before restore or permanent purge
- Protected Windows and application-folder exclusions
- OneDrive, Dropbox, Google Drive, reparse-point, offline, and recall protection
- Hard-link detection to avoid counting one physical file twice
- Optional removable-drive and network-drive controls
- Conservative approved-folder rules for unattended quarantine
- Config, scan, cache, and quarantine metadata backups
- Local audit log and privacy-safe diagnostic ZIP
- Localhost-only dashboard with a random session token
- No remote web assets and no file uploads

Automatic protection
--------------------
Scheduled scans may be enabled from Protection. Automatic quarantine remains
restricted to files that meet all conservative eligibility rules, including an
approved folder, sufficient age, verified retained copy, ordinary local file,
and configured maximum size.

Permanent deletion
------------------
Permanent purge is separate from quarantine. Manual purge requires an explicit
PURGE confirmation. Automatic purge is independently disabled by default and
only applies after the configured retention period.

Data and recovery location
--------------------------
%LOCALAPPDATA%\DuplicateGuard

This folder stores settings, audit logs, recovery metadata, backups, diagnostic
files, and quarantined data. Do not delete it while files remain quarantined.

Uninstall
---------
Use Windows Settings > Apps > Installed apps > DuplicateGuard > Uninstall.
Uninstalling preserves the Local AppData recovery folder so quarantined files
can still be recovered after reinstalling.

Privacy
-------
DuplicateGuard runs locally. Its dashboard binds to 127.0.0.1 and does not send
scanned file data to an online service.

Support diagnostics
-------------------
Open Diagnostics in the app and select Download diagnostics. The archive omits
file contents and is intended to contain operational settings, health data, and
sanitized audit information needed for troubleshooting.
