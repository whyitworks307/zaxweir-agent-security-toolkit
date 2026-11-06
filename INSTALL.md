# Run from the verified source archive

Status: private 0.5.0rc8 candidate; publication gates are open. There is no approved installer, wheel or public download yet. Source use needs CPython 3.11+ and no third-party runtime packages. Builder validation currently covers CPython 3.12.14 on Linux and 3.13.15 on Windows; the declared minimum alone is not a test result.

## Check the archive first

Obtain the expected SHA-256 from the approved release record through a trusted channel. Compare it before extracting. Do not take the digest from inside an unverified ZIP.

PowerShell:

```powershell
Get-FileHash -Algorithm SHA256 .\zaxweir-agent-security-toolkit-0.5.0rc8-source.zip
```

Linux:

```sh
sha256sum zaxweir-agent-security-toolkit-0.5.0rc8-source.zip
```

The sidecar SHA256SUMS supplies the candidate digest. After it matches, extract into a new disposable folder and open a terminal at the extracted project root. Do not overwrite an existing installation. No administrator rights, execution-policy changes, drivers, services or security-setting changes are required.

## PowerShell

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) 'src')
python -m agent_security_toolkit version
python -m agent_security_toolkit validate configs/examples/baseline_scenarios.json
python -m agent_security_toolkit run configs/examples/baseline_scenarios.json --out reports
```

Windows-only synthetic filesystem checks:

```powershell
python -m agent_security_toolkit fsprobe --out reports --iterations 300
```

## Linux

```sh
export PYTHONPATH="$PWD/src"
python -m agent_security_toolkit version
python -m agent_security_toolkit validate configs/examples/baseline_scenarios.json
python -m agent_security_toolkit run configs/examples/baseline_scenarios.json --out reports
```

The native probe returns unsupported-platform exit code 3 on Linux. Symlink setup can be skipped on standard Windows accounts; record those skips and leave system security settings unchanged.

The CLI uses 0 for a completed pass, 1 for a failed expectation/integrity check, 2 for invalid input, and 3 for an unsupported platform. A command that reports skips has not verified those cases.

Output files are placed under the specified report directory. Audit/key/ledger/report paths are trusted configuration, not a containment boundary: keep real keys and state outside agent-writable folders. Never delete nonce history or reset an anchor to work around a failed check. Remove this source folder and its disposable reports to remove the source-based setup; no global package is installed by these commands.

Optional development packaging through pyproject.toml requires setuptools>=69 already available in a controlled build environment. It is not needed here and may cause pip to access the network unless separately constrained. No wheel/sdist is part of this candidate; do not follow old wheel examples from prior releases.
