#![no_main]
//! `ITEMIDLIST` parse over arbitrary bytes — must never panic.
//!
//! `parse_idlist` walks a chain of variable-length shell items, each framed by
//! an attacker-controlled 2-byte `cb` size field, and dispatches on the class
//! byte into the per-class decoders (root `0x1f`, volume `0x2e`/`0x2f`, file
//! entry `0x30`-major plus its `0xbeef0004` extension block, network `0xc3`).
//! Every one of those fields — the `cb` framing, the class byte, the extension
//! offsets, the FAT date/time words, the UTF-16 name runs — is fuzzer-supplied
//! here. The invariant is total: for *any* byte slice the call returns a
//! (possibly empty, possibly truncated) `Vec<ShellItem>`, never panics, never
//! reads out of bounds, and never loops forever on a zero-advance `cb`.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = shellitem::parse_idlist(data);
});
