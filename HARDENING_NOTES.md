# Hardening notes — 0.5.0rc5 private candidate

R1 is preserved as a separate frozen 0.5.0rc4 archive. rc5 retains its approval, audit, bounded path matching, scenario validation, exception redaction and native handle-cleanup repairs. The native reader implementation is byte-for-byte unchanged from R1.

The rc5 change fixes junction setup command selection and quoting, adds a read-only release verifier and regression tests, and prepares source-based public documentation. These changes need fresh independent QC. Tests and documentation distinguish fail-closed limitations from repaired defects; no live agent integration, installer or public release was added.

A crash can leave audit or nonce locks; only an authorized operator may review and recover state. Never discard nonce history or restore an anchor to force a pass. Capacity/rotation procedures remain the integrator's responsibility. Authentic coordinated state rollback and historical process-wide handle attribution remain unresolved.

rc8 incorporates the approved Apache-2.0 direction, copyright notice and verified private reporting address. Inherited provenance and independent exact-artifact acceptance remain open. See README.md, SECURITY.md, LICENSING_STATUS.md and KNOWN_LIMITATIONS.md.
