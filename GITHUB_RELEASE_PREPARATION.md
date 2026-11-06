# Publication runbook — gated, not executed

Proposed dedicated repository name: zaxweir-agent-security-toolkit. Proposed tag: v0.5.0rc8. The package has no public repository or release URL yet. Keep it separate from all other projects and from the website repository.

Do not create a public repository, push source, create a tag remotely or publish assets until inherited source/provenance and all applicable exact-artifact independent decisions are cleared and the owner explicitly authorizes the final hash. The Apache direction, owner details and private channel are recorded in rc8; these do not clear the remaining blockers. Do not publish historical private QC reports or model inputs as repository contents.

Prepare a source-only repository from this candidate, retaining SOURCE_MANIFEST.json, LICENSE, documentation and tests. If approval requires any content change, assign a fresh archive hash and request review of that exact changed distribution. Do not reuse the recovered R1 hash or call an altered archive R1. Record the approved source commit, annotated version tag and archive hash.

After authorization, enable GitHub release immutability for the new repository before publishing. Prepare the release as a draft, attach the reviewed source archive plus SHA256SUMS and the approved notes, verify every asset, then publish. Immutability applies to future releases; do not rely on a plain movable Git tag. Do not add a paid service or payment method.

Official GitHub procedure: https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/establish-provenance-and-integrity/prevent-release-changes . The current release draft notes and exact candidate digest are supplied in the private completion packet.

Use a browser without authentication to verify repository access, release metadata, all linked documents and the asset download. Hash the freshly downloaded bytes and compare with the independently accepted digest. Record the public URLs and the immutable-release state. No anonymous-download success can be claimed while publication is blocked.

Only then update the existing Security Tools release section with version, actual GitHub Release/source URLs, checksum instructions, installation, limitations and disclosure links. Preserve its existing CSS/structure. Keep the current pending message until this point. Run the website's static and Playwright tests, verify the required mobile/desktop layouts and links, and request separate Vex website QC.
