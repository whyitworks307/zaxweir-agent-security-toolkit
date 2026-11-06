# ZAXWEIR Agent Security Toolkit v0.5.0rc8 — Public Pre-release

**Research/testing toolkit, not a production security guarantee.** This is the first public **pre-release**, approved for distribution by project owner Christopher Wright on November 6, 2026. It is free, licensed under Apache-2.0, and is not presented as a finished production security product.

## What it does
ZAXWEIR Toolkit lets developers exercise proposed AI-agent actions against a deny-by-default policy gate. It includes action-bound human approval tokens, an HMAC-chained audit log, simulated adversarial scenarios, and a Windows NTFS handle-relative file reader and adversarial probe. The gate makes decisions; it does **not** execute agent tools. The examples use synthetic data, and the harness itself is intended for offline testing.

## Exact official source archive
- File: `zaxweir-agent-security-toolkit-0.5.0rc8-source.zip`
- Size: **302,461 bytes**
- SHA-256: `780a789895a33647284443ea0f5aa5fd0b0c8f49e9bdca1ad3877acc59815887`
- Source contents: **58 files plus SOURCE_MANIFEST.json** (59 ZIP members).
- Git tag: `v0.5.0rc8` (frozen source only). The release asset contains the exact owner-approved ZIP, rather than a GitHub-generated archive.
- `SHA256SUMS.txt` accompanies the ZIP; verify the checksum **before** extraction.
- Licence: Apache License 2.0; NOTICE identifies Christopher Wright, 2026.

## Engineering evidence and honest coverage
- Linux: **227 passed, 24 skipped, 0 failed, 0 errors** per 251-test run in Vex's two-round campaign.
- Windows: **247 passed, 4 skipped, 0 failed, 0 errors** per 251-test run in Vex's two-round campaign; a subsequent independent Windows reproduction agreed.
- Windows filesystem adversarial probe: **40 passed, 5 skipped, 0 failed**. Some symlink setup was unavailable without special Windows privileges. Root/ancestor substitution attempts had **zero successful substitutions**, so that part of race coverage was **not exercised**. No genuine OS CloseHandle failure was induced. These are coverage gaps, not passes.
- Vex accepted its in-scope technical QC **but excluded its own previously authored Windows reader** from independent native acceptance. Muse independently inspected the native reader and reported no blocking static issue; Muse could not execute its own Python dynamic tests.
- ScanCode scanned **59/59 source-archive members** across its main and hidden-file runs. No third-party package or other copyright holder was identified.
- Public-source review used **34 GitHub code searches** and **16 direct source comparisons**. No substantial matching public implementation was identified in that bounded scope. This does **not** prove no similar or externally sourced code exists in unpublished/unindexed projects.

The owner has accepted these disclosed pre-release limitations. No independent legal authorship certification or full security certification is claimed. Read `KNOWN_LIMITATIONS.md`, `THREAT_MODEL.md`, and `SECURITY_ARCHITECTURE.md`.

## Important note about this frozen ZIP
The exact rc8 ZIP was originally created for a **private release-candidate review**. Its original `README.md`, `INSTALL.md`, `SECURITY.md`, `KNOWN_LIMITATIONS.md`, and `LICENSING_STATUS.md` still contain historical “private / public release hold” language. That language describes the packaging state when these exact bytes were frozen; the **November 6, 2026 owner approval and this public pre-release record** supersede the distribution-status wording. The described technical limitations remain in effect.

The archive has deliberately **not** been silently edited or repackaged, because doing so would change its approved SHA-256. Documentation changes and improvements will be published in new commits and future versioned releases.

## Use and vulnerability reports
- Use Python 3.11+; the specifically tested versions were Linux CPython 3.12.14 and Windows CPython 3.13.15. No administrator rights or third-party runtime packages are required for the source examples.
- This package is **not** an OS sandbox, endpoint protection product, or a guarantee of confidential/production-data safety. Do not run tests with real credentials or private records.
- Report security concerns privately to **founder@zaxweir.com**, not as public exploit issues. The project owner checks that receiving address daily; no response SLA is promised.

## Future development
The GitHub repository will continue receiving fixes and improvements. Each future release will have its own version, reviewed archive, checksum, and release notes; this frozen v0.5.0rc8 asset will stay unchanged.
