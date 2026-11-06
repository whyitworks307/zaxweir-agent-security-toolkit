# Contributing

Christopher Wright has approved the Apache-2.0 licensing direction. Contributions
are not being accepted while public release remains on hold for inherited-source
provenance, independent exact-candidate review and owner publication approval.
See LICENSING_STATUS.md. No outside contributors or assignments are inferred.
If a public contribution process is opened:

- Standard library only; no runtime dependencies.
- Every security control needs a negative test; every fixed finding needs a regression test.
- Fail closed: unexpected states must deny.
- Synthetic fixtures only: no real credentials, personal data, machine identifiers or production paths.
- Never weaken an existing test to make it pass; document skips with the exact reason.
- Run `python -m unittest discover -s tests -t .` on Windows and one other OS before proposing changes.
