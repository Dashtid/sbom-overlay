"""Parser for SPDX 2.3 JSON SBOMs."""

import json
import logging
from pathlib import Path
from typing import Any

from sbom_overlay.parsers.model import Component

_log = logging.getLogger(__name__)

_NULL_LICENSE_TOKENS = frozenset({"NOASSERTION", "NONE"})


class SpdxParseError(ValueError):
    """Raised when an SPDX document cannot be parsed as SPDX 2.x."""


def load(path: Path) -> list[Component]:
    """Parse an SPDX 2.3 JSON SBOM into normalized Component records.

    Components are tagged with source="manual" and returned in deterministic
    order (lowercase name, then version). Packages referenced by the
    document's documentDescribes field are skipped: they represent the
    product itself, not a dependency, and would otherwise produce a
    guaranteed "Only in manual" entry on every report.

    Raises SpdxParseError on invalid JSON, a non-object root, a missing or
    non-2.x spdxVersion, or a package without a name.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SpdxParseError(f"{path}: invalid JSON: {exc}") from exc

    if not isinstance(raw, dict):
        raise SpdxParseError(f"{path}: top-level value must be a JSON object")

    doc: dict[str, Any] = raw

    version = doc.get("spdxVersion")
    if not isinstance(version, str) or not version.startswith("SPDX-2."):
        raise SpdxParseError(f"{path}: expected SPDX-2.x, got {version!r}")

    described: set[str] = set(doc.get("documentDescribes") or [])
    packages: list[dict[str, Any]] = list(doc.get("packages") or [])

    components: list[Component] = []
    for pkg in packages:
        spdx_id = pkg.get("SPDXID")
        if isinstance(spdx_id, str) and spdx_id in described:
            continue

        name = pkg.get("name")
        if not isinstance(name, str) or not name:
            raise SpdxParseError(f"{path}: package {spdx_id!r} has no name")

        version_info = pkg.get("versionInfo")
        if not isinstance(version_info, str) or not version_info:
            _log.debug("skipping package %r: no versionInfo", name)
            continue

        components.append(
            Component(
                name=name,
                version=version_info,
                source="manual",
                purl=_extract_purl(pkg),
                license=_extract_license(pkg),
            )
        )

    components.sort(key=lambda c: (c.name.lower(), c.version))
    return components


def _extract_purl(pkg: dict[str, Any]) -> str | None:
    for ref in pkg.get("externalRefs") or []:
        if ref.get("referenceType") == "purl":
            locator = ref.get("referenceLocator")
            if isinstance(locator, str) and locator:
                return locator
    return None


def _extract_license(pkg: dict[str, Any]) -> str | None:
    for field in ("licenseConcluded", "licenseDeclared"):
        value = pkg.get(field)
        if isinstance(value, str) and value and value not in _NULL_LICENSE_TOKENS:
            return value
    return None
