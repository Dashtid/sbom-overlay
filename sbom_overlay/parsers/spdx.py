"""Parser for SPDX 2.x SBOMs (JSON, tag-value, YAML, RDF/XML)."""

import logging
from pathlib import Path

from license_expression import LicenseExpression
from spdx_tools.spdx.model.document import Document as SpdxDocument
from spdx_tools.spdx.model.package import Package as SpdxPackage
from spdx_tools.spdx.model.relationship import RelationshipType
from spdx_tools.spdx.parser.parse_anything import parse_file

from sbom_overlay.parsers.model import Component

_log = logging.getLogger(__name__)


class SpdxParseError(ValueError):
    """Raised when an SPDX document cannot be parsed as SPDX 2.x."""


def load(path: Path) -> list[Component]:
    """Parse an SPDX 2.x SBOM into normalized Component records.

    Accepts any SPDX 2.x serialization that spdx-tools understands: JSON
    (.spdx.json), tag-value (.spdx, .txt), YAML (.spdx.yaml), and RDF/XML.
    Components are tagged with source="manual" and returned in deterministic
    order (lowercase name, then version).

    Skips packages targeted by the document's DESCRIBES relationship; those
    represent the product itself and would otherwise produce a guaranteed
    "Only in manual" entry on every report.

    Raises SpdxParseError on parse failure or non-2.x spdxVersion. SPDX 3.0
    is rejected explicitly because spdx-tools accepts the version string but
    cannot interpret the underlying graph-based format.
    """
    try:
        doc = parse_file(str(path))
    except Exception as exc:
        raise SpdxParseError(f"{path}: {exc}") from exc

    version = doc.creation_info.spdx_version
    if not version.startswith("SPDX-2."):
        raise SpdxParseError(f"{path}: expected SPDX-2.x, got {version!r}")

    described = _document_describes(doc)
    components: list[Component] = []
    for pkg in doc.packages:
        if pkg.spdx_id in described:
            continue
        if not pkg.version:
            _log.debug("skipping package %r: no version", pkg.name)
            continue
        components.append(
            Component(
                name=pkg.name,
                version=pkg.version,
                source="manual",
                purl=_extract_purl(pkg),
                license=_extract_license(pkg),
            )
        )
    components.sort(key=lambda c: (c.name.lower(), c.version))
    return components


def _document_describes(doc: SpdxDocument) -> set[str]:
    return {
        rel.related_spdx_element_id
        for rel in doc.relationships
        if rel.spdx_element_id == doc.creation_info.spdx_id
        and rel.relationship_type == RelationshipType.DESCRIBES
        and isinstance(rel.related_spdx_element_id, str)
    }


def _extract_purl(pkg: SpdxPackage) -> str | None:
    for ref in pkg.external_references:
        if ref.reference_type == "purl":
            return ref.locator
    return None


def _extract_license(pkg: SpdxPackage) -> str | None:
    for value in (pkg.license_concluded, pkg.license_declared):
        if isinstance(value, LicenseExpression):
            return str(value)
    return None
