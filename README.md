# shellitem

[![shellitem](https://img.shields.io/crates/v/shellitem.svg)](https://crates.io/crates/shellitem)
[![Docs.rs](https://img.shields.io/docsrs/shellitem)](https://docs.rs/shellitem)
[![Rust 1.81+](https://img.shields.io/badge/rust-1.81%2B-blue.svg)](https://www.rust-lang.org)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/shellitem/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/shellitem/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Decode a Windows `ITEMIDLIST` (PIDL) blob into typed shell items and a reconstructed path — the reusable primitive behind LNK `LinkTargetIDList`, registry ShellBags, and Jump Lists.**

A shell item is one component of the Windows shell namespace serialization (`ITEMIDLIST`): a volume, a folder, a file (with its short *and* long name, size, MAC timestamps, and NTFS MFT reference), a network share, or a known-folder GUID. The exact same blob format appears in many artifacts, so the parser belongs in one place — like `xpress-huffman` or `lznt1`, this is a **decoder primitive, not an analyzer** (it emits no findings; the forensic interpretation lives in the consuming crates).

## Parse a PIDL in 30 seconds

```toml
[dependencies]
shellitem = "0.1"
```

```rust
use shellitem::{parse_idlist, reconstruct_path};

let items = parse_idlist(pidl_bytes);          // Vec<ShellItem>, lenient + panic-free
let path  = reconstruct_path(&items);          // "C:\\Users\\beth\\Downloads\\evil.exe"

for item in &items {
    if let Some(name) = item.display_name() {
        println!("{:?}  {name}", item.kind);
        // FileEntry items also carry: long_name, file_size, modified/created/accessed,
        // and the NTFS mft_entry / mft_sequence from the 0xbeef0004 extension block.
    }
}
# fn _doc(pidl_bytes: &[u8]) { let _ = pidl_bytes; }
```

`reconstruct_path` is the headline: a raw IDList → a human path, used to resolve the *real* target of a `.lnk` (even when `LinkInfo` is absent) and to render which folders a user browsed from a ShellBag.

## What it decodes

| Kind | Class | Carries |
|---|---|---|
| `Root` | `0x1F` | shell-folder GUID (My Computer, Network, Control Panel, …) |
| `Volume` | `0x2E`/`0x2F` | drive string (`C:\`) |
| `FileEntry` | `0x30` major (`0x31` dir, `0x32` file, `0x35`/`0x36`, `0xB1`) | short + **long name**, size, modified/created/accessed times, **NTFS MFT entry+sequence** (`0xbeef0004`) |
| `Network` | `0xC3` | UNC / network location |
| `Uri` / `ControlPanel` | `0x60` / `0x70` | URI / control-panel item |
| `Unknown` | other | raw bytes retained — nothing silently dropped |

Format constants (class bytes, the `0xbeef0004`/`0xbeef0026` extension signatures, the My-Computer GUID) come from [`forensicnomicon::shellbags`](https://crates.io/crates/forensicnomicon); the spec is libyal's *Windows Shell Item format*.

## Who consumes this

- **`lnk-core`** — the `.lnk` `LinkTargetIDList` (full target-path reconstruction).
- **`winreg-artifacts`** — registry **ShellBags** (`BagMRU` PIDL values → folder-access paths).
- Jump Lists and other shell MRUs (OpenSave/LastVisited PIDL MRUs).

## Trust but verify

- **Fuzzed** — two `cargo-fuzz` targets drive arbitrary bytes: `idlist` (`parse_idlist` alone) and `pipeline` (`parse_idlist` → `reconstruct_path` → `display_name`). No crashes in 8.2M and 9.1M executions respectively; CI smoke-fuzzes both on every PR.
- **Panic-free by lint** — `unsafe_code = "forbid"` with `unwrap_used`/`expect_used` denied, so every `cb`/offset is range-checked before use, UTF-16 is decoded lossily, and DOS-date conversion is overflow-guarded.
- **Validated** against spec-exact `ITEMIDLIST` fixtures derived from libfwsi.

---

[Privacy Policy](https://securityronin.github.io/shellitem/privacy/) · [Terms of Service](https://securityronin.github.io/shellitem/terms/) · © 2026 Security Ronin Ltd
