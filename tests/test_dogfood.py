"""Smoke-level checks on the dicom-fuzzer dogfood fixture pair.

Bucket-level reconciliation assertions belong in the reconciler PR; here we
verify the fixtures parse and have the rough shape we shaped them to have.
"""

from pathlib import Path

from sbom_overlay.parsers.spdx import load

DOGFOOD = Path(__file__).parent / "fixtures" / "dogfood" / "dicom-fuzzer-1.11.0"


def test_manual_sbom_parses_and_lists_direct_deps() -> None:
    components = load(DOGFOOD / "manual.spdx")
    names = {c.name for c in components}

    # Direct runtime deps from dicom-fuzzer's pyproject.toml.
    assert {"pydicom", "pynetdicom", "numpy", "pydantic", "rich", "cryptography"} <= names

    # Vendored components shaped to land in the Only-in-manual bucket.
    assert {"internal-dicom-codec", "vendored-zlib"} <= names

    # The DESCRIBES target (the dicom-fuzzer product itself) is skipped.
    assert "dicom-fuzzer" not in names


def test_syft_sbom_parses_and_finds_more_than_manual() -> None:
    syft_components = load(DOGFOOD / "syft.spdx.json")
    manual_components = load(DOGFOOD / "manual.spdx")

    assert len(syft_components) > len(manual_components), (
        "Syft should find substantially more components than the manual SBOM "
        "lists (transitive deps, dev-deps, etc.) — that gap is the value "
        "proposition for reconciliation."
    )


def test_pydantic_version_disagreement_is_seeded() -> None:
    # Engineered to demonstrate the In-both-with-version-disagreement bucket:
    # manual lists the pyproject floor, Syft reports the installed version.
    manual = {c.name: c for c in load(DOGFOOD / "manual.spdx")}
    syft = {c.name: c for c in load(DOGFOOD / "syft.spdx.json")}

    assert manual["pydantic"].version == "2.0.0"
    assert syft["pydantic"].version != "2.0.0"
