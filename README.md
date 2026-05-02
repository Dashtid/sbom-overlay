# sbom-overlay

[![CI](https://github.com/Dashtid/sbom-overlay/actions/workflows/ci.yml/badge.svg)](https://github.com/Dashtid/sbom-overlay/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Dashtid/sbom-overlay/branch/main/graph/badge.svg)](https://codecov.io/gh/Dashtid/sbom-overlay)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Dashtid/sbom-overlay/badge)](https://scorecard.dev/viewer/?uri=github.com/Dashtid/sbom-overlay)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Checked with mypy](https://www.mypy-lang.org/static/mypy_badge.svg)](https://mypy-lang.org/)

Reconcile a hand-curated SPDX SBOM (the authoritative artifact, e.g. for FDA
submission) against an automatically generated Syft SBOM. Surfaces components
the manual SBOM may have missed, and version or license disagreements between
the two views.

## Why

Manual SBOMs catch what scanners can't see (vendored binaries, statically
linked libraries, runtime-loaded plugins). Scanners catch what humans miss
(transitive deps, build-time tooling, generated artifacts). Neither is
complete on its own; the safe artifact is the union, triaged.

This tool produces that triage report.

## Position vs sbom-sentinel

| Tool          | Job                                              |
| ------------- | ------------------------------------------------ |
| sbom-sentinel | One SBOM in, vulnerability + KEV report out      |
| sbom-overlay  | Two SBOMs in, reconciliation triage report out   |

They are complementary, not coupled.

## Install

```bash
pip install -e .
```

## Usage

```bash
sbom-overlay reconcile \
    --manual product.spdx \
    --syft   product.syft.spdx.json \
    --name   product-1.0.0
```

`--manual` accepts any SPDX 2.x serialization spdx-tools understands
(tag-value `.spdx`, JSON, YAML, RDF/XML); `--syft` likewise. The report
lands at `<output-dir>/<name>-overlay.md`. Exit code is `0` on success,
`2` on parse failure.

## Try it

The repo ships a real fixture pair under
`tests/fixtures/dogfood/dicom-fuzzer-1.11.0/` — a hand-written manual SBOM
plus a Syft scan of the project venv, shaped to seed every reconciliation
bucket on purpose.

```bash
sbom-overlay reconcile \
    --manual tests/fixtures/dogfood/dicom-fuzzer-1.11.0/manual.spdx \
    --syft   tests/fixtures/dogfood/dicom-fuzzer-1.11.0/syft.spdx.json \
    --name   dicom-fuzzer-1.11.0
```

Terminal:

```text
[+] wrote artifacts/dicom-fuzzer-1.11.0-overlay.md
[+] in both, agree: 10
[!] version disagreements: 1
[!] license disagreements: 5
[!] only in Syft: 122
[i] only in manual: 2
```

The report itself is a Markdown file with one section per bucket:

```markdown
# SBOM reconciliation report — dicom-fuzzer-1.11.0

## Summary

- Only in manual: 2
- Only in Syft: 122
- In both, agree on version: 10
- Version disagreements: 1
- License disagreements: 5

## Only in manual

| Name | Version | License | PURL |
| --- | --- | --- | --- |
| internal-dicom-codec | 1.0.0 | MIT | _n/a_ |
| vendored-zlib | 1.3.1 | Zlib | _n/a_ |

## Version disagreements

| Name | Manual | Syft |
| --- | --- | --- |
| pydantic | 2.0.0 | 2.12.5 |
```

…and so on for the other buckets. Empty buckets render as `(none)` so
the report's diff is stable run-to-run.

## v1 limitations (deliberate)

- **Component identity** is lowercase name match. PURL-based matching is
  deferred because PURLs embed the version and cannot match the
  same-name-different-version disagreement bucket.
- **Version equivalence** is strict string equality. `1.0` ≠ `1.0.0` in
  v1; PEP 440 / semver is a rabbit hole.
- **License equivalence** is strict string equality. `Apache-2.0 OR MIT`
  ≠ `MIT OR Apache-2.0`; SPDX expression equivalence flagged for the
  reviewer.
- **No CycloneDX support.** Have Syft emit SPDX
  (`syft scan ... -o spdx-json=...`) — both sides same format, no
  translation layer.

## Development

```bash
pip install -e ".[dev]" || pip install -e .
pip install pytest pytest-cov ruff mypy bandit

ruff check .
mypy sbom_overlay
pytest --cov=sbom_overlay --cov-branch
bandit -c pyproject.toml -r sbom_overlay
```

## License

MIT
