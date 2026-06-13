//! `ITEMIDLIST` framing and per-class shell-item decoding.

use crate::{ShellItem, ShellItemKind};

/// Parse a Windows `ITEMIDLIST` (PIDL) blob into its sequence of shell items.
///
/// The list is a run of `ItemID { u16 cb; data[cb-2] }` records terminated by
/// a `cb == 0` item (libfwsi). Parsing is **lenient**: it stops at the
/// terminator, at a `cb` that would run past the end of the buffer, or at a
/// `cb < 2` (which cannot make progress), returning whatever items were
/// decoded so far. It never panics on malformed input.
#[must_use]
pub fn parse_idlist(data: &[u8]) -> Vec<ShellItem> {
    // stub — implemented in GREEN
    let _ = data;
    Vec::new()
}

/// Reconstruct a human-readable path from a parsed item list by joining each
/// item's best display name with `\`.
#[must_use]
pub fn reconstruct_path(items: &[ShellItem]) -> String {
    // stub — implemented in GREEN
    let _ = items;
    String::new()
}

#[allow(dead_code)]
fn decode_item(class: u8, raw: Vec<u8>) -> ShellItem {
    ShellItem {
        class,
        kind: ShellItemKind::Unknown,
        name: None,
        long_name: None,
        file_size: None,
        modified: None,
        created: None,
        accessed: None,
        mft_entry: None,
        mft_sequence: None,
        guid: None,
        raw,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod framing_tests {
    use super::*;

    /// Build one raw item with the given class byte and trailing data, framed
    /// with its `cb` size prefix (cb = 2 + 1 + data.len()).
    fn item(class: u8, data: &[u8]) -> Vec<u8> {
        let cb = (3 + data.len()) as u16;
        let mut v = cb.to_le_bytes().to_vec();
        v.push(class);
        v.extend_from_slice(data);
        v
    }

    fn list(items: &[Vec<u8>]) -> Vec<u8> {
        let mut v = Vec::new();
        for it in items {
            v.extend_from_slice(it);
        }
        v.extend_from_slice(&[0u8, 0u8]); // terminator cb == 0
        v
    }

    #[test]
    fn splits_two_items_and_stops_at_terminator() {
        let blob = list(&[item(0x1F, &[0xAA; 16]), item(0x32, &[0xBB; 8])]);
        let items = parse_idlist(&blob);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].class, 0x1F);
        assert_eq!(items[1].class, 0x32);
    }

    #[test]
    fn empty_input_yields_no_items() {
        assert!(parse_idlist(&[]).is_empty());
        assert!(parse_idlist(&[0u8, 0u8]).is_empty());
    }

    #[test]
    fn cb_overrunning_buffer_stops_cleanly() {
        // cb claims 100 bytes but only a few are present — must not panic,
        // must stop without emitting a bogus item.
        let blob = vec![100u8, 0u8, 0x32, 0xAA, 0xBB];
        let items = parse_idlist(&blob);
        assert!(items.is_empty());
    }

    #[test]
    fn cb_below_minimum_stops_cleanly() {
        // cb == 1 cannot make progress (no room for the class byte).
        let blob = vec![1u8, 0u8, 0x32];
        let items = parse_idlist(&blob);
        assert!(items.is_empty());
    }

    #[test]
    fn raw_bytes_are_preserved_per_item() {
        let raw0 = item(0x1F, &[0xAA; 16]);
        let blob = list(&[raw0.clone()]);
        let items = parse_idlist(&blob);
        assert_eq!(items[0].raw, raw0);
    }
}
