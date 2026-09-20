# Source recovery status

This repository was reconstructed from original project artifacts on 2026-09-21.

## Recovered artifacts

| Version | Artifact | Status |
|---|---|---|
| 1.0.0 | source ZIP | recovered |
| 2.0.0 | source ZIP | recovered |
| 2.1.0 | source ZIP snapshot A | recovered |
| 2.1.0 | source ZIP snapshot B | recovered; distinct from snapshot A |
| 2.1.1 | source ZIP | recovered and used as repository source tree |
| 2.3.0 | Windows x64 setup EXE | recovered and verified |

## Missing matching source

No authentic v2.2.0 or v2.3.0 source archive/tree was found in the ChatGPT file library inventory or Master PC searches performed during migration.

Because of that, this repository deliberately keeps the source version identity at v2.1.1 and treats v2.3.0 as a recovered binary release. Reverse-engineered output is not presented as original source.

## Why two v2.1.0 archives are kept

The two recovered v2.1.0 ZIPs have different SHA-256 hashes and different contents. Differences include `installer/setup.go`, `web/index.html`, tests, scan/types code, README, and release notes. Both are retained for provenance.
