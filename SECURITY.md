# Security reporting — private rc8 candidate

This 0.5.0rc8 candidate is not approved for public deployment or distribution.
No version is currently declared supported for public production use. Do not
use the Toolkit as the sole safeguard for real data.

## Private reporting channel

Report suspected Toolkit vulnerabilities privately to **founder@zaxweir.com**.
Christopher Wright confirmed control of the email and will check the receiving
inbox every day. A synthetic message sent from a different email account was
verified as delivered on November 5, 2026. The confirmation evidence is retained
in the private release records; sender details and account configuration are not
published here. Daily checking is not a promised acknowledgement or repair time.
No backup monitor, encryption key or response-time SLA has been invented.

Include the exact Toolkit version and archive SHA-256, Windows/Python version,
impact, and the smallest synthetic reproduction. Do not send real credentials,
personal documents or production data. Do not publish unresolved exploit details
in a public issue tracker. Coordinate disclosure timing and attribution with the
maintainer. A report does not authorize testing anyone else's system.

## Security boundaries and release hold

The gate decides without executing agent tools. Operator-controlled state paths,
protected HMAC keys and correct enrollment hashes remain required. Audit integrity
does not detect coordinated rollback of an authentic old log plus anchor. Action
IDs are scoped to a Gate instance; downstream execution needs durable idempotency.
Native races are bounded observations. Direct-root substitutions can be blocked
by the pin; zero successful substitutions and unavailable symlinks are coverage
skips, not evidence of exercised resistance. The separate ancestor-substitution
probe records whether its namespace replacement actually occurred.

Owner licensing direction and the private channel are recorded. Inherited native
source provenance, independent exact-artifact QC, and explicit owner authorization
of the final publication hash remain open. LICENSE/NOTICE are not independent
originality certificates. See LICENSING_STATUS.md, SOURCE_PROVENANCE.md,
KNOWN_LIMITATIONS.md and THREAT_MODEL.md.

Keep reports within this standalone package; exclude unrelated private systems,
private development archives and real user records.
