# Source and dependency disclosure

No third-party runtime packages are declared in pyproject.toml. Existing import-hygiene tests check Toolkit source imports against the Python standard library; the release tools and tests also use standard-library modules. No Python interpreter, Windows DLL, driver, package binary or vendored dependency is included in this source ZIP.

CPython and the Windows libraries used at runtime are separately supplied by the user's system. Optional packaging declares setuptools>=69; it is not bundled or needed for source execution. SBOM.cdx.json and DEPENDENCIES.json describe declared components and evidence limits, not an installed dependency inventory or a current vulnerability-database clearance.

The native reader was described by its builder as a procedure-based rewrite from written requirements and public API signatures. The same builder lineage had prior implementation exposure. The permitted source/provenance records do not independently prove ownership or originality. No protected-source comparison was performed in this campaign. No blanket 'no third-party code' or legal clearance is asserted from standard-library imports alone.

Public references used for technical verification include Microsoft Learn's CreateProcessW and GetSystemDirectoryW documentation. Calling an OS API is not redistribution of its DLL; this statement does not resolve inherited-source provenance. Owner/legal and independent provenance review remain required before public distribution.
