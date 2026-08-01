# shellitem — Purpose & Scope

*This is a **library**-tier intent doc (Purpose & Scope), not a product PRD:
`shellitem` ships no binary an examiner runs — it is a decoder primitive that
other crates link. Per the fleet PRD & ADR standard, library crates carry a
lighter `docs/PRD.md`; the load-bearing design decisions live in
[`docs/decisions/`](decisions/).*

## What it is

`shellitem` decodes a Windows **`ITEMIDLIST`** (PIDL — pointer to an item
identifier list) blob into typed [`ShellItem`]s and, via `reconstruct_path`,
into a human-readable path such as `My Computer\C:\Users\bob\secret.docx`.

An `ITEMIDLIST` is the binary form of a shell-namespace path: a run of
variable-length **shell items** (`ItemID { u16 cb; data[cb-2] }`) terminated by
an empty item. The *same* structure appears in many artifacts — a `.lnk` file's
`LinkTargetIDList`, registry **ShellBags** (`BagMRU`) values, jump lists, and
the OpenSave/LastVisited PIDL MRUs — so the parser belongs in exactly one place.

This is a **reusable parser primitive**, in the spirit of the `lznt1` /
`xpress-huffman` codecs (`src/lib.rs`): it decodes the structure and surfaces
the fields, and emits **no findings and makes no forensic judgements**. Timeline
placement and anomaly grading live in the consuming analyzers, not here.

## Who links it

- **`lnk-core`** — the `.lnk` `LinkTargetIDList`, for full target-path
  reconstruction (resolving a shortcut's real target even when `LinkInfo` is
  absent).
- **`winreg-artifacts`** — registry **ShellBags** (`BagMRU` PIDL values →
  folder-access paths).
- Jump Lists and other shell MRUs that embed PIDL blobs.

Position in the fleet layer model: a **PARSER**-tier primitive that depends only
on the KNOWLEDGE leaf `forensicnomicon` (format constants), never on a
container/filesystem/paging crate (see ADR 0002).

## What it decodes

| Kind | Class byte(s) | Carries |
|---|---|---|
| `Root` | `0x1F` | shell-folder GUID (My Computer, Network, Control Panel, …) |
| `Volume` | `0x2E` / `0x2F` | drive string (`C:\`) |
| `FileEntry` | `0x30` major (`0x31` dir, `0x32` file, `0x35`/`0x36`, `0xB1` Unicode) | short + long name, size, modified/created/accessed times, NTFS MFT entry+sequence (`0xbeef0004`) |
| `Network` | `0xC3` | UNC / network location |
| `Uri` / `ControlPanel` | `0x60` / `0x70` major | URI / control-panel item |
| `Unknown` | any other | raw bytes retained — nothing silently dropped |

Format constants (class bytes, the `0xbeef0004` / `0xbeef0026` extension
signatures, the My-Computer GUID) are sourced from
`forensicnomicon::shellbags`; the byte-level reference is libyal's *Windows
Shell Item format* (libfwsi).

## Scope

- Frame an `ITEMIDLIST` into its shell-item sequence, lenient and panic-free on
  truncated or malformed input (`parse_idlist`).
- Decode the class families above to typed fields on a best-effort, per-class
  basis; retain the full raw bytes of every item so nothing is lost.
- Reconstruct a display path by joining each item's best display name
  (`reconstruct_path`).
- Convert FAT (MS-DOS) packed date/time fields to Unix epoch seconds with no
  date-library dependency.

## Non-goals

- **No findings, no forensic judgement, no anomaly grading.** This crate does
  not emit `forensicnomicon::report` Findings; interpretation is the consumer's
  job (ADR 0001).
- **No artifact containers.** It parses a shell-item blob handed to it as
  `&[u8]`; it does not open `.lnk` files, registry hives, or disk images (that
  is `lnk-core` / `winreg-artifacts` / the container layer).
- **No CLSID → friendly-name database.** Only the universally-stable
  My-Computer GUID is named; every other shell-folder GUID is surfaced verbatim
  for the consumer to resolve against its own map.
- **No write / reconstruction of PIDL blobs** — decode only.

## Validation approach

Correctness is exercised by inline unit tests built TDD-style
(RED/GREEN commit pairs across framing, root, volume, file-entry, class, and
path reconstruction — see `git log`) over spec-exact `ITEMIDLIST` fixtures
derived from libfwsi. The static robustness posture is `forbid(unsafe_code)`
plus `unwrap_used`/`expect_used = deny` with bounds-checked readers (ADR 0003).

The dynamic partner to that static posture is `fuzz/`: two `cargo-fuzz` targets
over arbitrary bytes — `idlist` (`parse_idlist` alone) and `pipeline`
(`parse_idlist` → `reconstruct_path` → `display_name`). Neither crashed in its
first run (8.2M and 9.1M executions respectively); `ci.yml` smoke-fuzzes both for
30s on every PR alongside the low-MSRV and coverage jobs (ADR 0003).
