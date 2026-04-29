import json
from pathlib import Path

import pytest

from sbom_overlay.parsers.spdx import SpdxParseError, load

FIXTURES = Path(__file__).parent / "fixtures" / "spdx"


def test_load_returns_components_in_deterministic_order() -> None:
    components = load(FIXTURES / "affinity_minimal.spdx.json")

    # documentDescribes target (Affinity) and no-versionInfo package skipped.
    assert [c.name for c in components] == [
        "internal.tool",
        "malformed-purl-pkg",
        "Newtonsoft.Json",
        "openssl",
        "weird-ref-pkg",
    ]


def test_load_tags_components_as_manual_with_versions() -> None:
    components = load(FIXTURES / "affinity_minimal.spdx.json")
    by_name = {c.name: c for c in components}

    assert all(c.source == "manual" for c in components)
    assert by_name["openssl"].version == "3.0.12"
    assert by_name["Newtonsoft.Json"].version == "13.0.3"


def test_load_extracts_purl_when_well_formed() -> None:
    by_name = {c.name: c for c in load(FIXTURES / "affinity_minimal.spdx.json")}

    assert by_name["openssl"].purl == "pkg:nuget/openssl@3.0.12"
    assert by_name["malformed-purl-pkg"].purl is None
    assert by_name["weird-ref-pkg"].purl is None
    assert by_name["Newtonsoft.Json"].purl is None


def test_load_falls_back_from_concluded_to_declared_license() -> None:
    by_name = {c.name: c for c in load(FIXTURES / "affinity_minimal.spdx.json")}

    assert by_name["openssl"].license == "Apache-2.0"
    assert by_name["Newtonsoft.Json"].license == "MIT"
    assert by_name["internal.tool"].license is None
    assert by_name["malformed-purl-pkg"].license is None


def test_load_invalid_json_raises_parse_error(tmp_path: Path) -> None:
    p = tmp_path / "bad.spdx.json"
    p.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(SpdxParseError, match="invalid JSON"):
        load(p)


def test_load_top_level_array_raises_parse_error(tmp_path: Path) -> None:
    p = tmp_path / "array.spdx.json"
    p.write_text('["array at top"]', encoding="utf-8")
    with pytest.raises(SpdxParseError, match="JSON object"):
        load(p)


def test_load_missing_spdx_version_raises_parse_error(tmp_path: Path) -> None:
    p = tmp_path / "noversion.spdx.json"
    p.write_text(json.dumps({"packages": []}), encoding="utf-8")
    with pytest.raises(SpdxParseError, match="SPDX-2"):
        load(p)


def test_load_spdx_3_document_raises_parse_error(tmp_path: Path) -> None:
    p = tmp_path / "spdx3.spdx.json"
    p.write_text(json.dumps({"spdxVersion": "SPDX-3.0", "packages": []}), encoding="utf-8")
    with pytest.raises(SpdxParseError, match="SPDX-2"):
        load(p)


def test_load_package_without_name_raises_parse_error(tmp_path: Path) -> None:
    p = tmp_path / "noname.spdx.json"
    p.write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "packages": [{"SPDXID": "SPDXRef-Package-X", "versionInfo": "1.0.0"}],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(SpdxParseError, match="no name"):
        load(p)


def test_load_skips_document_describes_target(tmp_path: Path) -> None:
    p = tmp_path / "described.spdx.json"
    p.write_text(
        json.dumps(
            {
                "spdxVersion": "SPDX-2.3",
                "documentDescribes": ["SPDXRef-Package-Root"],
                "packages": [
                    {
                        "SPDXID": "SPDXRef-Package-Root",
                        "name": "Root",
                        "versionInfo": "1.0.0",
                    },
                    {
                        "SPDXID": "SPDXRef-Package-Dep",
                        "name": "Dep",
                        "versionInfo": "2.0.0",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    assert [c.name for c in load(p)] == ["Dep"]


def test_load_handles_document_with_no_packages(tmp_path: Path) -> None:
    p = tmp_path / "empty.spdx.json"
    p.write_text(json.dumps({"spdxVersion": "SPDX-2.3"}), encoding="utf-8")
    assert load(p) == []
