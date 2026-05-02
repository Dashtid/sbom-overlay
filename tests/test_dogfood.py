"""End-to-end checks on the dicom-fuzzer dogfood fixture pair.

The fixture is shaped to seed every reconciliation bucket; these tests assert
each engineered case lands in the right one.
"""

from pathlib import Path

from sbom_overlay.parsers.spdx import load
from sbom_overlay.reconcile.diff import reconcile

DOGFOOD = Path(__file__).parent / "fixtures" / "dogfood" / "dicom-fuzzer-1.11.0"


def test_manual_sbom_parses_and_lists_direct_deps() -> None:
    components = load(DOGFOOD / "manual.spdx", source="manual")
    names = {c.name for c in components}

    assert {"pydicom", "pynetdicom", "numpy", "pydantic", "rich", "cryptography"} <= names
    assert {"internal-dicom-codec", "vendored-zlib"} <= names
    # The DESCRIBES target (the dicom-fuzzer product itself) is skipped.
    assert "dicom-fuzzer" not in names


def test_syft_sbom_parses_and_finds_more_than_manual() -> None:
    syft_components = load(DOGFOOD / "syft.spdx.json", source="syft")
    manual_components = load(DOGFOOD / "manual.spdx", source="manual")

    assert len(syft_components) > len(manual_components)


def test_dogfood_reconciliation_lands_seeded_buckets() -> None:
    manual = load(DOGFOOD / "manual.spdx", source="manual")
    syft = load(DOGFOOD / "syft.spdx.json", source="syft")
    result = reconcile(manual, syft)

    only_manual_names = {c.name for c in result.only_in_manual}
    assert {"internal-dicom-codec", "vendored-zlib"} <= only_manual_names

    # Plenty of transitive deps Syft saw and the curator never listed.
    assert len(result.only_in_syft) > 50

    in_both_names = {m.name for m, _ in result.in_both}
    assert {"pydicom", "rich", "cryptography"} <= in_both_names


def test_dogfood_seeds_pydantic_version_disagreement() -> None:
    manual = load(DOGFOOD / "manual.spdx", source="manual")
    syft = load(DOGFOOD / "syft.spdx.json", source="syft")
    result = reconcile(manual, syft)

    mismatch_names = {m.name for m, _ in result.version_mismatches}
    assert "pydantic" in mismatch_names
