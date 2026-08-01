#![no_main]
//! Full public pipeline over arbitrary bytes — parse → path reconstruction →
//! per-item field access — must never panic.
//!
//! `idlist.rs` covers the decoder in isolation; this target adds the two things
//! a consumer actually does with the result. `reconstruct_path` joins decoded
//! names with `\` after a known-folder rewrite, and `display_name` picks the
//! most specific label — both operating on strings that came out of lossy
//! UTF-16 decoding of fuzzer bytes, so this is where a char-boundary or
//! empty-name assumption would surface rather than in the parse itself.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let items = shellitem::parse_idlist(data);
    let _ = shellitem::reconstruct_path(&items);
    for item in &items {
        let _ = item.display_name();
    }
});
