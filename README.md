# ZAXWEIR Agent Security Toolkit

**0.5.0rc8 — private release-preparation candidate. Public distribution is blocked pending independent QC, inherited-source provenance and final-hash owner publication authorization. Owner Apache-2.0 approval and the private reporting channel are recorded.** The proposed tag is `v0.5.0rc8`; no public repository or release is created by this package.

The Toolkit lets you test the rules between an AI agent and its proposed actions. It checks a request against a policy, verifies human approval when required, and records the decision in a tamper-evident audit log. Its examples use fictional data and run offline.

| Part | Purpose |
|---|---|
| Policy and gate | Deny unsupported capabilities, paths and requests. Return ALLOW only after an audit append succeeds. |
| Human approvals | Bind an HMAC token to the exact action, approver, expiry and single-use nonce. Persistent ledgers serialize consumption. |
| Audit | Verify a keyed record chain and separate anchor; refuse corrupt, oversized or failed state. |
| Windows reader | Read only enrolled paths under a pinned root, checking file identity, link count and content hash. Local NTFS only within the tested scope. |
| Windows probe | Create a disposable synthetic tree and test traversal, aliases, links, swaps and handle cleanup as a standard user. It invokes the system command interpreter only for junction setup. |

The gate returns decisions; it does not execute proposed agent tools. The filesystem probe does perform its listed local setup and read operations. This package supplies no live agent integration, desktop controller, network service or production database.

This is a research/testing harness, not an OS sandbox, endpoint protection product or security certification. A process with direct OS access can bypass a library-level gate. Authentic old audit state plus its matching anchor can be restored without detection. Read [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) before integrating it.

Start with [INSTALL.md](INSTALL.md). No package download or pip install is needed to use the source: CPython and its standard library are sufficient. The native reader/probe require Windows. Current builder testing covers Linux CPython 3.12.14 and Windows CPython 3.13.15; other versions/environments remain unverified.

```text
python -m agent_security_toolkit version
python -m agent_security_toolkit validate configs/examples/baseline_scenarios.json
python -m agent_security_toolkit run configs/examples/baseline_scenarios.json --out reports
```

Set `PYTHONPATH` to this folder's `src` first; exact PowerShell and Linux commands are in INSTALL.md. Test commands and honest skip reporting are in [TESTING.md](TESTING.md). Never put real credentials or private documents in examples or review reports.

Release identity is the version plus the archive SHA-256, not a filename alone. Verify downloads against an externally trusted digest before extraction. `SOURCE_MANIFEST.json` covers every packaged file except itself. `tools/verify_release.py` provides bounded, read-only ZIP and manifest checks and never extracts or executes archive content. A checksum does not prove authorship or the absence of vulnerabilities.

Apache-2.0 metadata and NOTICE use the owner-approved direction, Christopher Wright, and 2026. The verified private reporting address is founder@zaxweir.com, checked daily by the owner. Inherited source rights remain unresolved; see LICENSING_STATUS.md, SOURCE_PROVENANCE.md, THIRD_PARTY_LICENSES.md and SECURITY.md. Keep this candidate private until the remaining release gates are met.

AI assistance: prior source development and this hardening used AI assistance. Meta Muse Spark 1.3 reviewed selected non-native source, tests and documentation; GPT investigated its claims and ran tests. Native implementation files were not supplied to Muse. These are builder/reviewer results; Vex's exact-artifact independent decision is pending. See CHANGELOG.md for the change from recovered R1.
