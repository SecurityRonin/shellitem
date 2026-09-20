# 8. Adopt the reader/analyzer split — shellitem is a parser, not a codec

Date: 2026-09-20

Status: Accepted — supersedes points 1 and 2 of
[ADR-0001](0001-shellitem-as-a-shared-decoder-primitive.md)

## Context

ADR-0001 shipped one bare-named crate that emits no findings, reasoning that
the **codec-primitive precedent** applied — `xpress-huffman`, `lznt1` — rather
than the fleet's Pattern A reader/analyzer split.

The fleet's per-parser invariant (ronin-issen ADR-0009) says every **parser**
owes a reader *and* an analyzer, and is explicitly **scoped to parsers**: codec
primitives, utility cores and foundation cores owe no `-forensic`. So the whole
question is which side of that line `shellitem` sits on, and ADR-0001 put it on
the codec side.

**That classification does not hold.** `xpress-huffman` and `lznt1` transform
bytes: the same input yields the same output and there is nothing to have an
opinion about. `shellitem` interprets an **evidence artifact format** and hands
back forensically loaded fields — short *and* long names, three MAC timestamps,
an NTFS MFT entry and sequence. Those fields can disagree with each other, and
a disagreement is a finding.

The point is not theoretical. A first analyzer pass found three anomaly classes
in the fields this reader already returns:

- a bidirectional-control codepoint in a name (U+202E and friends), which is
  how `…cod.exe` is made to render as `…exe.doc` — MITRE T1036.002;
- a long name whose extension contradicts the 8.3 short name Windows derives
  from it;
- a creation time later than the modification time — MITRE T1070.006.

None of these are expressible about a compression codec. ADR-0001's own
consequence — "the forensic interpretation lives in the consumers" — meant in
practice that **nobody did it**: neither `lnk-core` nor `winreg-artifacts`
grades a shell item, so the analysis was assigned to two crates that never
performed it, and an examiner got silence.

## Decision

1. Adopt **Pattern A** (ADR-0008 of the fleet): `core/` publishes
   `shellitem-core` (the reader, unchanged behaviour) and `forensic/` publishes
   `shellitem-forensic` (the analyzer, emitting `forensicnomicon::report`
   findings via `impl Observation`).
2. **Keep `shellitem` as a root facade** that re-exports `shellitem-core`.
   crates.io has no rename: `shellitem` is published (0.2.3, ~4.5k downloads)
   and five fleet manifests depend on it, so the name must keep resolving. The
   facade is why this split costs no downstream edits — including the fuzz
   crate, which still depends on `path = ".."`.
3. **The reader still emits no findings.** ADR-0001 point 2 was right about the
   *reader*; it was wrong only in concluding that the repo therefore ships no
   analyzer. Reading and grading pull in opposite directions — a reader
   normalizes and skips, an auditor must see what was skipped — which is
   precisely why they are separate crates.

## Consequences

- The repo goes from one crate to three; `--workspace` (never `--lib`) is what
  makes the coverage gate see the analyzer's integration tests. The stale
  "single-crate repo" note in `ci.yml` was corrected in the same change.
- Two new names are published. Both were free, so no collision fallback was
  needed (see ronin-issen ADR-0009 for when `<repo>-core` is required instead).
- Anomaly tests run through `parse_idlist` on spec-exact bytes rather than
  hand-built structs — `ShellItem` is `#[non_exhaustive]` and cannot be
  literalled from outside `shellitem-core`, which forces the tests to exercise
  the real parse → audit pipeline. A clean file entry raising nothing is a
  first-class test case: a detector that fires on ordinary evidence reports
  nothing.
- ADR-0001 stays in the tree. Its point 3 — that consumers own timeline
  placement — still holds; only the "no analyzer here" conclusion is replaced.
