<p align="center">
  <img src="docs/images/banner.png" alt="scan-results-bridge by CompleteTech LLC" width="100%">
</p>

<p align="center">
  <a href="https://github.com/CompleTetech-Security/scan-results-bridge/actions"><img src="https://img.shields.io/github/actions/workflow/status/CompleTetech-Security/scan-results-bridge/tests.yml?label=tests" alt="Tests"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-1E3A8A" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/dependencies-none-067647" alt="No runtime dependencies">
  <a href="LICENSING.md"><img src="https://img.shields.io/badge/license-AGPL--3.0%20%7C%20commercial-64748B" alt="AGPL-3.0 or commercial license"></a>
</p>

# scan-results-bridge

Offline conversion of CompleteTech security checker JSON reports into SARIF 2.1.0
or NDJSON, with a privacy-preserving default projection.

## Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Offline workflow](#offline-workflow)
- [Usage](#usage)
- [Input contracts](#input-contracts)
- [Output formats](#output-formats)
- [Privacy and evidence](#privacy-and-evidence)
- [Limits](#limits)
- [Interpreting results](#interpreting-results)
- [Development](#development)
- [Contributing and security](#contributing-and-security)
- [License and brand assets](#license-and-brand-assets)

## Overview

`scan_results_bridge.py` reads existing local JSON reports and writes SARIF 2.1.0
or NDJSON. It is optional: individual checkers do not depend on it.

- **Offline.** It never scans targets, executes code, loads packages, reads
  credentials, or uploads data. No HEC/syslog transport or credential
  configuration is implemented.
- **Metadata only.** It converts supplied local evidence. Every observation keeps
  `exploitability: not_tested`; nothing it emits confirms exploitation, and a
  reported fixed version is never a verified deployed patch or a safety claim.
- **Private by default.** Asset labels, URLs, paths, evidence prose and
  similar values are replaced by SHA-256 identifiers unless you opt in to
  publishing relative source paths. See [Privacy and evidence](#privacy-and-evidence).
- **Fails closed.** Unsupported tools or versions and malformed or contradictory
  input exit 2 rather than producing a partial conversion.

## Requirements

- Python 3.10 or later (CI runs 3.10 and 3.14 on Linux, Windows and macOS).
- Nothing to install: one standalone file, standard library only.
- [`jsonschema`](#sarif-schema-validation) is needed only for the optional
  development check of emitted SARIF.

## Quick start

The bundled example is synthetic.

```sh
# Convert a report to SARIF (the output file must not already exist)
python scan_results_bridge.py --input examples/report.json --format sarif --output report.sarif

# NDJSON to stdout, publishing reported relative source paths
python scan_results_bridge.py --input examples/report.json --format ndjson --include-relative-paths

# A legacy node2shell-check report (placeholder file name), failing CI on findings or unknowns
python scan_results_bridge.py --input node-report.json --input-schema node2shell-v1 --fail-on either

# Run the tests and show all options
python -m unittest -v
python scan_results_bridge.py --help
```

Keep unrelated reports out of commits.

## Offline workflow

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/overview-dark.png">
  <img src="docs/images/overview-light.png" alt="Scan Results Bridge offline workflow" width="100%">
</picture>

The tool uses supplied local evidence only. It does not contact targets or execute
the software being assessed.

## Usage

```text
python scan_results_bridge.py --input REPORT [--input REPORT ...]
    [--input-schema PROFILE] [--format {sarif,ndjson}] [--include-relative-paths]
    [--fail-on {none,findings,unknown,either}] [--output FILE [--force]]
```

### Options

| Option | Meaning |
| --- | --- |
| `--input FILE` | Required. An existing report JSON file; repeat for up to 20 inputs. |
| `--input-schema PROFILE` | Input [contract](#input-contracts); default `contract-v1.0`. One profile applies to every input in the invocation. |
| `--format {sarif,ndjson}` | Output format; default `sarif`. |
| `--include-relative-paths` | Opt in to publishing valid reported source paths. Inventory-derived locations are never published. See [Privacy and evidence](#privacy-and-evidence). |
| `--fail-on {none,findings,unknown,either}` | Policy exit code 1 after successful output; default `none`. See [Exit codes](#exit-codes). |
| `--output FILE` | Write to a new file instead of stdout. |
| `--force` | Replace an existing `--output` file atomically. Never replaces an input or the checker itself. |

### Output and interruption

- Output defaults to stdout. An existing `--output` file is refused unless
  `--force` is given.
- The checker and every input are protected from being overwritten, including
  through symlink or hardlink aliases, even with `--force`.
- The whole report is rendered before anything is published, and file output is
  published atomically.
- Malformed, unsupported or over-limit input is rejected before any output.
- Interruption exits 130 and the output is not retried. Interrupted stdout, or an
  interrupt at the file commit boundary, may leave an incomplete or indeterminate
  publication; verify or discard it.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Conversion succeeded, every input reported `complete: true`, and the selected `--fail-on` policy is satisfied. |
| `1` | Conversion succeeded and was written, but `--fail-on` matched. |
| `2` | Operational failure: malformed, unsupported or over-limit input, protected or unwritable output, or an input that reports `complete: false`. An incomplete input is still converted and written before the exit, and is marked incomplete in the output. |
| `130` | Interrupted. |

`--fail-on` policies:

| Policy | Exit 1 when the output contains |
| --- | --- |
| `none` (default) | Never. |
| `findings` | `potentially_affected`, `precondition_present` or `likely_exposed`. |
| `unknown` | `unknown`, `unsupported_runtime` or `source_discrepancy`. |
| `either` | Either of the above. |

A policy exit never suppresses results. Exit code 2 takes precedence over 1.
Operational failures are distinct from assessment results.

## Input contracts

Select the profile explicitly with `--input-schema`; one profile applies to all
inputs in an invocation. Unsupported tools or versions and malformed or
contradictory canonical evidence fail closed with exit 2. The canonical validator
is bundled from
[Sharp's common contract](https://github.com/CompleTetech-Security/sharp-rsvg-rce-check/blob/14955717ab29676828dc215e993d987c40e3f575/vendor/common.py)
under the same code license; no installed shared package is required.

| Profile | Input |
| --- | --- |
| `contract-v1.0` (default) | Complete schema 1.0 object with tool/rules/results, including semantic evidence-reference validation |
| `node2shell-v1` | Legacy unversioned node2shell-check tool_version 1.0.0 JSON; named adapter only, not a universal schema |
| `copyescape-v1.1` | copyescape-check schema_version `1.1` |
| `vm2-v1.1` | vm2-nesting-check report_schema_version `1.1` |
| `simplegit-v1.1` | simplegit-rce-check report_schema_version `1.1` |
| `atlassian-v1` | atlassian-cve-2026-21589-check integer schema_version 1 |
| `flowise-v1` | flowise-cve-2026-69254-check integer schema_version 1; version_status maps to normalized status |

Common to all profiles:

- Published tool versions must use the public numeric `major.minor.patch` format,
  including canonical reports and empty runs. Free-form version labels are
  rejected before output because they can contain private metadata.
- Every result must carry `exploitability: not_tested`. Threat metadata is kept
  separate from it, and no input status becomes confirmed exploitation.
- Confidence is retained when its vocabulary matches; otherwise it is `unknown`.
- The original evidence receives a deterministic digest for local reconciliation.
- Canonical version assessments are retained explicitly.
- Legacy adapters validate the consumed envelope, status, exploitability and
  version fields. They do not claim validation of every unused legacy report field.

## Output formats

Output is deterministic: results, rules and report envelopes are ordered stably,
no timestamp is generated, and all output is JSON escaped. Non-finite numbers,
including overflowing JSON exponents, fail before publication.

### SARIF

- One run per tool and version, each with its own combined completion state.
  This includes tools whose input reports have no result rows. An incomplete run
  is marked with an unsuccessful invocation.
- Triage level: `warning` for `potentially_affected`, `precondition_present` and
  `likely_exposed`; `note` for `unknown`, unsupported, fixed or mitigated
  observations. This is a triage level, not a CVSS score or an exploitability claim.
- Original status, confidence and completion state remain in result properties.
- Source locations are emitted only when [qualifying evidence](#privacy-and-evidence)
  exists and paths are opted in. Valid Unicode paths are percent-encoded in URIs.
- Each result carries a `checkerIdentity/v1` partial fingerprint.

### NDJSON

One JSON object per observation, followed by an explicit `summary` record, which
is also written for empty or incomplete conversions. The summary includes
`complete`, `result_count`, `observation_count` and the report envelopes
(`reports`).

### Report envelopes

Each validated input also contributes a report envelope independently of its result
rows. SARIF stores these under each matching run's `properties.input_reports`; the
NDJSON summary stores them in `reports`.

An envelope retains:

- the public tool, version and input profile;
- explicit completion state;
- `report_sha256`, a digest of the full canonicalized input;
- `evidence_sha256`, a digest of the report-level metadata; and
- a privacy-projected `evidence` object.

Canonical rule snapshots and limitations therefore survive empty runs. Input
filenames are never published. Repeated identical inputs remain repeated, and
differing inputs remain attributable by digest. These are content identities, not
authenticity or deployed-patch attestations. Report metadata uses the same
structural privacy projection as observation evidence.

### Fingerprints and deduplication

Fingerprints combine tool, rule, private asset identity, component instance and
reported source location. They use the stable component name, not its
version/build assessment, and exclude status, run time and input ordering. When
reported, same-line source candidate ordinals and hashed input-artifact identities
disambiguate fingerprints without inventing source columns.

- Identity is preserved across status changes at the same location.
- Moving a line or changing an asset identifier changes the fingerprint. This is
  not semantic code matching.
- Exact projected duplicates collapse into one row with an `occurrences` count.
- Conflicting statuses or evidence remain separate observations. Full component
  metadata, sources and canonical rule snapshot metadata are part of the projected
  evidence, so different snapshots and conflicts do not deduplicate.
- Corroborating source records at the same path and line retain one unambiguous
  location.
- The raw combined-result limit applies before deduplication.

## Privacy and evidence

Default exports use a structural privacy projection. Asset labels, URLs, paths,
arbitrary object keys, evidence prose, versions, secrets and original remediation
text are replaced by SHA-256 identifiers. Known evidence kinds and states,
confidence, booleans, numbers and uncertainty survive, as do public tool and rule
identifiers, which SARIF requires. Exported remediation directs the reader to the
original private report and vendor guidance.

This deliberately omits raw prose rather than claiming a regex can remove every
possible credential. Retain the original report securely to interpret the
projected evidence, including hashed prose and field names. Hashes are linkable
and dictionary-guessable; they are not anonymous identifiers. Canonical report
limitations are included in the privately projected evidence digest.

### Source paths

Relative source paths are omitted unless `--include-relative-paths` is set. That
switch explicitly permits publishing those reported paths, so review filenames for
secrets before enabling it.

- Only bounded relative paths with integer source lines from source evidence
  qualify.
- Inventory paths, network URLs and missing locations never produce fabricated
  code locations.
- Absolute paths, drive or URL schemes, backslashes, empty or traversal components
  and control characters are rejected as locations.
- Numeric observations, including reported line numbers in projected evidence,
  remain visible even without the opt-in; publishing the path still requires it.

## Limits

| Limit | Value |
| --- | --- |
| Input files per invocation | 20 |
| Size per input / combined inputs | 4 MiB / 16 MiB |
| JSON nesting depth | 40 |
| JSON nodes per input | 250,000 |
| Characters per string | 16,384 |
| Combined results | 10,000 |
| Output size | 32 MiB |

Exceeding a limit fails with exit 2; nothing is silently truncated. Local inputs
and output directories should be stable and controlled by the operator. This is
not a service hardened against a concurrent hostile filesystem.

## Interpreting results

- Statuses describe reported metadata, not tested behavior. `exploitability`
  stays `not_tested` and no result confirms exploitation or safety.
- `fixed_version_reported` records what a checker reported. It is not a verified
  deployed patch.
- `unknown`, `unsupported_runtime` and `source_discrepancy` preserve uncertainty;
  they are not clean results. Treat them as needing review, for example with
  `--fail-on unknown`.
- Hashes and fingerprints are content identities, not proof of authenticity.
- Schema validation checks SARIF format only. It does not prove GitHub ingestion
  or live code-scanning display, and no upload or production acceptance was
  performed.

## Development

Run the tests (local only, synthetic reports only, no third-party dependencies):

```sh
python -m unittest -v
python scan_results_bridge.py --help
```

### SARIF schema validation

The unmodified official OASIS schema is bundled under `schemas/` with its original
license terms ([OASIS-LICENSE.md](schemas/OASIS-LICENSE.md)). An optional
development check uses `jsonschema`. CI runs it locally against the bundled schema
for source, inventory-only, Unicode, findings, unknown, and empty or incomplete
runs. Tests fetch no remote schema references.

```sh
python -m pip install jsonschema==4.25.1
python tools/validate_sarif.py
```

Sources: [OASIS SARIF schema](https://github.com/oasis-tcs/sarif-spec/blob/main/sarif-2.1/schema/sarif-schema-2.1.0.json),
[GitHub SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support).

## Contributing and security

Read [AGENTS.md](AGENTS.md), [CONTRIBUTING.md](CONTRIBUTING.md) and
[SECURITY.md](SECURITY.md) first. Keep the tool standalone, standard-library only
and offline, and preserve uncertainty, bounds, the privacy projection, stable
fingerprints, input protection and atomic output. Before merge, run
`python -m unittest -v`, `python scan_results_bridge.py --help` and
`git diff --check`; GitHub Copilot review and exact-head hosted CI are required.

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), using
synthetic reproductions only.

## License and brand assets

Code is available under [AGPL-3.0](LICENSE) or a separate commercial license from
CompleteTech LLC; see [LICENSING.md](LICENSING.md). The bundled OASIS SARIF schema
keeps its upstream license under [`schemas/`](schemas/OASIS-LICENSE.md).

No logo or trademark license is granted by the code license. The CompleteTech LLC
names, logos and repository artwork under `docs/images/` remain brand assets;
see [BRAND_ASSETS.md](BRAND_ASSETS.md).
