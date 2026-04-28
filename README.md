# sbom-overlay

Reconcile a hand-curated SPDX SBOM (the authoritative artifact, e.g. for FDA
submission) against an automatically generated Syft SBOM. Surfaces components
the manual SBOM may have missed, and version or license disagreements between
the two views.

Status: alpha. The CLI is a stub; reconciliation logic lands in the first
working iteration.

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
    --manual product.spdx.json \
    --syft   product.cdx.json \
    --name   product-1.0.0
```

(Not implemented yet — see `docs/ARCHITECTURE.md` for the design.)

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
