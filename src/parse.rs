//! `ITEMIDLIST` framing and per-class shell-item decoding.

use crate::reader;
use crate::{ShellItem, ShellItemKind};
use forensicnomicon::shellbags;

/// Parse a Windows `ITEMIDLIST` (PIDL) blob into its sequence of shell items.
///
/// The list is a run of `ItemID { u16 cb; data[cb-2] }` records terminated by
/// a `cb == 0` item (libfwsi). Parsing is **lenient**: it stops at the
/// terminator, at a `cb` that would run past the end of the buffer, or at a
/// `cb < 2` (which cannot make progress), returning whatever items were
/// decoded so far. It never panics on malformed input.
#[must_use]
pub fn parse_idlist(data: &[u8]) -> Vec<ShellItem> {
    let mut items = Vec::new();
    let mut pos = 0usize;
    while pos + 2 <= data.len() {
        let cb = crate::reader::le_u16(data, pos) as usize;
        if cb == 0 {
            break; // terminator
        }
        if cb < 3 {
            break; // cannot hold a class byte — cannot make progress
        }
        let end = match pos.checked_add(cb) {
            Some(e) if e <= data.len() => e,
            _ => break, // cb lies / overruns the buffer — stop cleanly
        };
        let raw = data[pos..end].to_vec();
        let class = raw[2];
        items.push(decode_item(class, raw));
        pos = end;
    }
    items
}

/// Reconstruct a human-readable path from a parsed item list by joining each
/// item's best display name with `\`.
#[must_use]
pub fn reconstruct_path(items: &[ShellItem]) -> String {
    // stub — implemented in GREEN
    let _ = items;
    String::new()
}

/// A freshly-constructed `ShellItem` with the given class/kind and the raw
/// bytes attached; every optional field starts empty for the per-class decoder
/// to fill in.
fn blank(class: u8, kind: ShellItemKind, raw: Vec<u8>) -> ShellItem {
    ShellItem {
        class,
        kind,
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

/// Map a well-known shell-folder GUID to its canonical display name. Only the
/// universally-stable My-Computer / "This PC" GUID is hard-named here (sourced
/// from [`forensicnomicon::shellbags::MY_COMPUTER_GUID`]); every other GUID is
/// surfaced verbatim so consumers can resolve it against their own CLSID map.
fn known_folder_name(guid: &str) -> Option<&'static str> {
    if guid.eq_ignore_ascii_case(shellbags::MY_COMPUTER_GUID) {
        Some("My Computer")
    } else {
        None
    }
}

fn decode_item(class: u8, raw: Vec<u8>) -> ShellItem {
    match class {
        shellbags::CLASS_ROOT_FOLDER => decode_root(class, raw),
        _ => blank(class, ShellItemKind::Unknown, raw),
    }
}

/// Decode a root / known-folder item (`0x1f`): a 1-byte sort index followed by
/// a 16-byte shell-folder GUID at offset 4 (libfwsi).
fn decode_root(class: u8, raw: Vec<u8>) -> ShellItem {
    let mut item = blank(class, ShellItemKind::Root, raw);
    if let Some(guid) = reader::guid(&item.raw, 4) {
        item.name = known_folder_name(&guid).map(ToString::to_string);
        item.guid = Some(guid);
    }
    item
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod root_tests {
    use super::*;
    use crate::ShellItemKind;

    /// The My-Computer GUID `20D04FE0-3AEA-1069-A2D8-08002B30309D` in on-disk
    /// mixed-endian byte order (first three groups little-endian).
    const MY_COMPUTER_BYTES: [u8; 16] = [
        0xE0, 0x4F, 0xD0, 0x20, // 20D04FE0 (LE)
        0xEA, 0x3A, // 3AEA (LE)
        0x69, 0x10, // 1069 (LE)
        0xA2, 0xD8, // A2D8 (BE)
        0x08, 0x00, 0x2B, 0x30, 0x30, 0x9D, // 08002B30309D (BE)
    ];

    fn root_item(sort: u8, guid: &[u8; 16]) -> Vec<u8> {
        let mut data = vec![sort];
        data.extend_from_slice(guid);
        // frame: cb = 2 + 1(class) + 1(sort) + 16(guid)
        let cb = (3 + data.len()) as u16;
        let mut v = cb.to_le_bytes().to_vec();
        v.push(0x1F);
        v.extend_from_slice(&data);
        v.extend_from_slice(&[0u8, 0u8]); // terminator
        v
    }

    #[test]
    fn root_item_decodes_guid_and_kind() {
        let blob = root_item(0x00, &MY_COMPUTER_BYTES);
        let items = parse_idlist(&blob);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].kind, ShellItemKind::Root);
        assert_eq!(
            items[0].guid.as_deref(),
            Some("20D04FE0-3AEA-1069-A2D8-08002B30309D")
        );
    }

    #[test]
    fn my_computer_guid_maps_to_display_name() {
        let blob = root_item(0x00, &MY_COMPUTER_BYTES);
        let items = parse_idlist(&blob);
        // "My Computer" is the canonical display name for the My-Computer GUID.
        assert_eq!(items[0].name.as_deref(), Some("My Computer"));
        assert_eq!(items[0].display_name(), Some("My Computer"));
    }

    #[test]
    fn unknown_root_guid_has_no_name_but_keeps_guid() {
        let other = [0x11u8; 16];
        let blob = root_item(0x00, &other);
        let items = parse_idlist(&blob);
        assert_eq!(items[0].kind, ShellItemKind::Root);
        assert!(items[0].name.is_none());
        assert!(items[0].guid.is_some());
        // display_name falls back to the GUID string.
        assert_eq!(items[0].display_name(), items[0].guid.as_deref());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod volume_tests {
    use super::*;
    use crate::ShellItemKind;

    /// Build a 0x2F drive-letter volume item: class 0x2F then a 20-byte ASCII
    /// volume name (NUL-terminated, zero-padded) per libfwsi.
    fn volume_2f(name: &str) -> Vec<u8> {
        let mut field = [0u8; 20];
        for (i, b) in name.bytes().enumerate().take(19) {
            field[i] = b;
        }
        let mut v = Vec::new();
        let cb = (3 + field.len()) as u16;
        v.extend_from_slice(&cb.to_le_bytes());
        v.push(0x2F);
        v.extend_from_slice(&field);
        v.extend_from_slice(&[0u8, 0u8]);
        v
    }

    #[test]
    fn drive_letter_volume_decodes_name() {
        let blob = volume_2f("C:\\");
        let items = parse_idlist(&blob);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].kind, ShellItemKind::Volume);
        assert_eq!(items[0].class, 0x2F);
        assert_eq!(items[0].name.as_deref(), Some("C:\\"));
        assert_eq!(items[0].display_name(), Some("C:\\"));
    }

    #[test]
    fn volume_2e_is_classified_as_volume() {
        // 0x2E variant: still major-class volume (0x20). We classify the kind
        // even though its inner layout (a GUID) is not name-decoded here.
        let mut v = Vec::new();
        v.extend_from_slice(&(3u16 + 16).to_le_bytes());
        v.push(0x2E);
        v.extend_from_slice(&[0u8; 16]);
        v.extend_from_slice(&[0u8, 0u8]);
        let items = parse_idlist(&v);
        assert_eq!(items[0].kind, ShellItemKind::Volume);
    }
}
