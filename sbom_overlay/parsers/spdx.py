from pathlib import Path

from sbom_overlay.parsers.model import Component


def load(path: Path) -> list[Component]:
    """Parse an SPDX 2.3 JSON SBOM into normalized Component records.

    Not implemented yet. The shape of the function is the contract:
    inputs are a path on disk, outputs are a list of Component records
    tagged with source="manual".
    """
    raise NotImplementedError("SPDX parser not implemented yet")
