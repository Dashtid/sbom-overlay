# dicom-fuzzer 1.11.0 dogfood fixture

Real-shape SPDX-on-SPDX reconciliation pair used by `tests/test_dogfood.py`
and (eventually) by the reconciler integration test.

## Files

- `manual.spdx` — hand-written SPDX 2.3 tag-value SBOM, simulating the
  curator's view of dicom-fuzzer's runtime dependencies plus two vendored
  components no scanner can see.
- `syft.spdx.json` — Syft scan of the project's installed venv, locked to
  the version present at scan time. Refresh with `scripts/refresh_dogfood.sh`.

## Engineered reconciliation buckets

The fixture is shaped to exercise every reconciler bucket on purpose:

| Bucket | How it's seeded |
| --- | --- |
| Only in manual | `internal-dicom-codec` and `vendored-zlib` — fabricated entries Syft cannot see |
| Only in Syft | All transitive dev/runtime deps the curator never lists (dozens) |
| In both, agree | The 10 direct runtime deps from pyproject.toml at venv-installed versions |
| In both, version disagree | `pydantic` — manual lists `2.0.0` (pyproject floor), Syft sees the installed version |

License disagreement is intentionally not seeded; Syft is generally accurate
on PyPI license metadata, and a fabricated mismatch confuses more than it
illustrates.

## Reproducibility

`syft.spdx.json` is environment-dependent: a different installed venv
produces different transitive dep versions. The fixture is locked to
dicom-fuzzer 1.11.0's venv state at the time `refresh_dogfood.sh` was run.
When dicom-fuzzer ships a new minor version, add a sibling directory
(`dicom-fuzzer-1.12.0/`) rather than overwriting this one.

## Refresh command

```bash
syft scan dir:c:/code-two/dicom-fuzzer/.venv \
  -o spdx-json=tests/fixtures/dogfood/dicom-fuzzer-1.11.0/syft.spdx.json \
  --source-name dicom-fuzzer \
  --source-version 1.11.0 \
  --override-default-catalogers python-installed-package-cataloger
```

The `python-installed-package-cataloger` override drops Go-binary detection
(iterfzf bundles `fzf`) and `\Scripts\...` entry-point noise. Both are real
artifacts in the venv but neither is a Python dependency the manual SBOM
would track.
