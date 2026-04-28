from pathlib import Path

from sbom_overlay.parsers.model import Component


def load(path: Path) -> list[Component]:
    """Parse a CycloneDX 1.5 JSON SBOM into normalized Component records.

    Not implemented yet. Records are tagged with source="syft" since this
    tool's contract assumes the CycloneDX input was produced by Syft.
    """
    raise NotImplementedError("CycloneDX parser not implemented yet")
