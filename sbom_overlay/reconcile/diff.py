"""Reconcile a manual SBOM against a Syft-generated SBOM."""

from dataclasses import dataclass

from sbom_overlay.parsers.model import Component


@dataclass(frozen=True)
class Reconciliation:
    """Result of comparing a manual SBOM against a Syft SBOM.

    Attributes:
        only_in_manual: Components present only in the authoritative manual
            SBOM. Usually fine (vendored binaries, statically linked libs
            Syft cannot see).
        only_in_syft: Components present only in the Syft scan. Likely
            missing from the manual SBOM and worth a human review.
        in_both: Components matched across both inputs as
            ``(manual, syft)`` pairs. The pair may agree, differ on
            version, differ on license, or differ on both. Reporters
            inspect the pairs to surface disagreements.
    """

    only_in_manual: list[Component]
    only_in_syft: list[Component]
    in_both: list[tuple[Component, Component]]

    @property
    def version_mismatches(self) -> list[tuple[Component, Component]]:
        """In-both pairs whose versions disagree."""
        return [(m, s) for m, s in self.in_both if m.version != s.version]

    @property
    def license_mismatches(self) -> list[tuple[Component, Component]]:
        """In-both pairs whose license strings disagree.

        Both ``None`` counts as agreement; one ``None`` and one set string
        counts as disagreement.
        """
        return [(m, s) for m, s in self.in_both if m.license != s.license]


def reconcile(manual: list[Component], syft: list[Component]) -> Reconciliation:
    """Compare two component lists and bucket them.

    Identity is lowercase name match: two components match if and only if
    ``a.name.lower() == b.name.lower()``. PURL is preserved on the records
    but not used for matching in v1, because PURL embeds the version and
    cannot match same-name-different-version (which is exactly the
    disagreement bucket we want to surface).

    Where multiple components share a normalized name within a single
    side (rare, but possible when a manual SBOM lists two builds of the
    same library), each is matched against any same-name component on
    the other side; pairs are produced one-to-one in input order, and
    extras spill into the only-in-X buckets.

    Output ordering inside each bucket is deterministic
    ``(name.lower(), version)`` so the eventual triage report diffs
    cleanly run-to-run.
    """
    manual_by_name: dict[str, list[Component]] = {}
    for c in manual:
        manual_by_name.setdefault(c.name.lower(), []).append(c)

    only_in_syft: list[Component] = []
    in_both: list[tuple[Component, Component]] = []
    for s in syft:
        bucket = manual_by_name.get(s.name.lower())
        if bucket:
            in_both.append((bucket.pop(0), s))
        else:
            only_in_syft.append(s)

    only_in_manual: list[Component] = [c for bucket in manual_by_name.values() for c in bucket]

    only_in_manual.sort(key=_sort_key)
    only_in_syft.sort(key=_sort_key)
    in_both.sort(key=lambda pair: _sort_key(pair[0]))

    return Reconciliation(
        only_in_manual=only_in_manual,
        only_in_syft=only_in_syft,
        in_both=in_both,
    )


def _sort_key(c: Component) -> tuple[str, str]:
    return (c.name.lower(), c.version)
