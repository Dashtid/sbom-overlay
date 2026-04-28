from dataclasses import dataclass

from sbom_overlay.parsers.model import Component


@dataclass(frozen=True)
class Reconciliation:
    """Result of comparing a manual SBOM against a Syft SBOM.

    only_in_manual: components present only in the authoritative manual SBOM.
        Usually fine (vendored binaries, statically linked libs Syft can't see).
    only_in_syft: components present only in the Syft scan. Likely missing
        from the manual SBOM and worth a human review.
    in_both: components matched across both inputs, possibly with version or
        license disagreement. Stored as (manual, syft) pairs for diffing.
    """

    only_in_manual: list[Component]
    only_in_syft: list[Component]
    in_both: list[tuple[Component, Component]]


def reconcile(manual: list[Component], syft: list[Component]) -> Reconciliation:
    """Compare the two component lists.

    Not implemented yet. Identity strategy is an open design question: PURL
    when both sides have it, fallback to (normalized_name, version) otherwise.
    """
    raise NotImplementedError("reconcile() not implemented yet")
