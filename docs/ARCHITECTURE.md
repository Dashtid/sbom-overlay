# Architecture

## Problem

A hand-curated SBOM (SPDX 2.3) is the authoritative artifact for regulatory
submission. A scanner-generated SBOM (Syft, CycloneDX 1.5) is the easiest
artifact to keep up to date but cannot see vendored or statically-linked
components.

Neither is a complete picture. The safe deliverable is the union, with each
component triaged by a human.

## Design

```
   manual.spdx.json (authoritative)
            \
             >---  parse  ---  normalize  ---\
            /                                  >---  reconcile  ---  report.md
   syft.cdx.json (overlay)                   /
            \                               /
             >---  parse  ---  normalize  -/
```

### Stages

1. **Parse**. Read SPDX 2.3 and CycloneDX 1.5 into a common in-memory shape:
   `{name, version, purl?, license?, source: "manual" | "syft"}`.

2. **Normalize**. Lowercase names, strip vendor prefixes where unambiguous,
   coalesce versions ("1.0" vs "1.0.0"). Document each rule; precision matters
   more than recall.

3. **Reconcile**. Three buckets:
   - **Only in manual** — usually fine (vendored, hand-rolled).
   - **Only in Syft** — likely missing from the manual SBOM. Action item.
   - **In both** — cross-check version and license; flag mismatches.

4. **Report**. Markdown, suitable for a PR comment or audit attachment.

## Out of scope (for v1)

- Generating a merged SBOM. Reconciliation only.
- Vulnerability scanning. That is `sbom-sentinel`'s job.
- Format conversion (SPDX <-> CycloneDX). Use Syft or `spdx-tools` if needed.

## Open questions

- Component identity. PURL when available, else `(name, version)` pair.
  How aggressive is normalization allowed to get before false-positive matches
  hide real divergence?
- License comparison. SPDX expression equivalence is not string equality.
  v1 may flag any non-identical license string and let the reviewer judge.
- Output stability. The triage report is read by humans; ordering and section
  layout should not change run-to-run unless the inputs changed.
