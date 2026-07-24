# 2. KNOWLEDGE-only dependency direction; decode from `&[u8]`

Date: 2026-07-24
Status: Accepted

## Context

The fleet layer model places PARSER-tier crates so they depend on the KNOWLEDGE
leaf only, accept `Path` or `&[u8]`, and **never** import a CONTAINER,
FILESYSTEM, PAGING, OS-STRUCTURE, or LOG-FORMAT crate
(`ronin-issen/CLAUDE.md`, dependency rules). Shell-item class-type bytes, the
`0x70` major-class mask, the My-Computer GUID, and the `0xbeef0004` / `0xbeef0026`
extension signatures are stable *facts about a format* — KNOWLEDGE, not
algorithm.

The fleet also mandates preferring our own crates: `forensicnomicon` already
publishes those shell-item constants (`forensicnomicon::shellbags`).

## Decision

1. Depend on **exactly one** crate: `forensicnomicon = "1"` (`Cargo.toml`
   `[dependencies]`), the KNOWLEDGE leaf.
2. Pull every format constant from `forensicnomicon::shellbags` rather than
   hardcoding literals: `is_file_entry`, `CLASS_ROOT_FOLDER`, `CLASS_VOLUME_2E`,
   `CLASS_VOLUME_2F`, `CLASS_NETWORK_LOCATION`, `CLASS_FILE_ENTRY_UNICODE`,
   `MAJOR_CLASS_URI`, `MAJOR_CLASS_CONTROL_PANEL`, `major_class`, and
   `MY_COMPUTER_GUID` (`src/parse.rs:5,74,82-96`).
3. Take input as a byte slice — `parse_idlist(data: &[u8]) -> Vec<ShellItem>`
   (`src/parse.rs:15`) — so the crate is medium-agnostic: it never opens a
   `.lnk` file, a hive, or a disk image, and imposes no dependency below it.

## Consequences

- A single source of truth for shell-item constants across the fleet; a spec
  correction in `forensicnomicon` propagates to every consumer.
- The crate can be linked by `lnk-core`, `winreg-artifacts`, jump-list parsers,
  and anything else that holds PIDL bytes, with no transitive container weight.
- The dependency arrow only ever points *down* to KNOWLEDGE, honouring the
  PARSER-tier rule and keeping the graph acyclic.
