//! `shellitem` — a Windows Shell Item / `ITEMIDLIST` (PIDL) parser primitive.
//!
//! A Windows **`ITEMIDLIST`** (also "PIDL", pointer to an item identifier list)
//! is the binary form of a shell path: a sequence of variable-length **shell
//! items**, each one component of the path, terminated by an empty item. The
//! same structure appears inside a `.lnk` file's `LinkTargetIDList`, inside
//! registry **ShellBags** (`BagMRU`) values, jump lists, and elsewhere. This
//! crate turns those bytes into typed [`ShellItem`]s and, via
//! [`reconstruct_path`], into a human-readable path such as
//! `My Computer\C:\Users\bob\secret.docx`.
//!
//! This is a **reusable parser primitive**, in the same spirit as the
//! `lznt1` / `xpress-huffman` codecs: it decodes the structure and surfaces the
//! fields, but emits **no findings and makes no forensic judgements**. The
//! forensic interpretation (timeline placement, anomaly grading) lives in the
//! consumers — `lnk-core` (LinkTargetIDList) and `winreg-artifacts` (ShellBags).
//!
//! # Robustness
//!
//! Shell-item blobs are attacker-controllable. Parsing is **panic-free and
//! bounds-checked** throughout: the per-item `cb` size field is validated
//! against the remaining buffer and capped, every integer read goes through a
//! bounds-checked helper, FAT-date conversion is overflow-safe, and UTF-16
//! decoding is lossy (unpaired surrogates become U+FFFD). A truncated or
//! corrupt list stops cleanly at the point of damage rather than panicking.
//!
//! # Authoritative source
//!
//! libyal `libfwsi`, *Windows Shell Item format* (Joachim Metz) — the
//! reverse-engineered reference for the `ITEMIDLIST` framing and every
//! shell-item class layout (root `0x1f`, volume `0x2e`/`0x2f`, file entry
//! `0x30`-major and its `0xbeef0004` extension block, network `0xc3`):
//! <https://github.com/libyal/libfwsi/blob/main/documentation/Windows%20Shell%20Item%20format.asciidoc>.
//! Format constants (class-type bytes, the `0x70` major-class mask, the
//! My-Computer GUID, the `beef0004`/`beef0026` signatures) are sourced from
//! [`forensicnomicon::shellbags`].
//!
//! # Example
//!
//! ```
//! use shellitem::{parse_idlist, reconstruct_path};
//!
//! # let pidl_bytes: &[u8] = &[0, 0]; // an empty ITEMIDLIST (terminator only)
//! let items = parse_idlist(pidl_bytes);
//! let path = reconstruct_path(&items);
//! ```

mod dosdate;
mod parse;
mod reader;

pub use parse::{parse_idlist, reconstruct_path};

/// The decoded *kind* of a [`ShellItem`], naming the shell-item class family
/// the bytes belong to (libfwsi). Coarser than the raw `class` byte: several
/// raw bytes collapse into one kind (e.g. `0x31`/`0x32`/`0x35`/`0x36`/`0xb1`
/// are all [`ShellItemKind::FileEntry`]).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellItemKind {
    /// Root / known-folder item (`0x1f`) — carries a shell-folder GUID
    /// (My Computer, Network, Control Panel, …).
    Root,
    /// Volume / drive item (`0x2e`/`0x2f`) — carries a drive string (`C:\`).
    Volume,
    /// File or directory entry (major class `0x30`: `0x31` dir, `0x32` file,
    /// `0x35`/`0x36`, `0xb1` Unicode) — carries the short/long names, size,
    /// timestamps and (when present) the NTFS MFT reference.
    FileEntry,
    /// Network location / UNC share (`0xc3`).
    Network,
    /// URI / internet-shortcut item (major class `0x60`, e.g. `0x61`).
    Uri,
    /// Control-panel item (major class `0x70`, e.g. `0x71`).
    ControlPanel,
    /// A recognised class whose detailed layout this primitive does not (yet)
    /// decode, or an unrecognised class byte. The raw bytes are preserved on
    /// the [`ShellItem`] so nothing is silently dropped.
    Unknown,
}

/// One decoded shell item — a single component of an `ITEMIDLIST`.
///
/// Fields are populated on a best-effort, per-class basis; a field that does
/// not apply to the item's class, or that was absent/truncated in the bytes,
/// is `None`. The raw item bytes (including the `cb` size prefix) are always
/// retained in [`ShellItem::raw`] so a consumer can re-inspect or surface the
/// class byte for an [`ShellItemKind::Unknown`] item.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellItem {
    /// The raw class-type indicator byte (offset 2 of the item).
    pub class: u8,
    /// The decoded class family.
    pub kind: ShellItemKind,
    /// The item's short / display name (DOS short name for a file entry, drive
    /// string for a volume, GUID display label for a root item).
    pub name: Option<String>,
    /// The long (Unicode) name from the `0xbeef0004` extension block, when the
    /// item is a file entry and the block is present.
    pub long_name: Option<String>,
    /// The file size (`u32`) for a file-entry item.
    pub file_size: Option<u32>,
    /// Last-modified timestamp (Unix epoch seconds, UTC) — the file entry's
    /// FAT date/time.
    pub modified: Option<i64>,
    /// Creation timestamp (Unix epoch seconds, UTC) from the `0xbeef0004`
    /// extension block.
    pub created: Option<i64>,
    /// Last-access timestamp (Unix epoch seconds, UTC) from the `0xbeef0004`
    /// extension block.
    pub accessed: Option<i64>,
    /// NTFS MFT entry index (48-bit) from the `0xbeef0004` file reference,
    /// when the extension version is high enough to carry it.
    pub mft_entry: Option<u64>,
    /// NTFS MFT sequence number (16-bit) from the `0xbeef0004` file reference.
    pub mft_sequence: Option<u16>,
    /// Shell-folder GUID for a root item, in canonical upper-case form.
    pub guid: Option<String>,
    /// The full raw bytes of this item, including the 2-byte `cb` size prefix.
    pub raw: Vec<u8>,
}

impl ShellItem {
    /// The best available display name for this item, preferring the most
    /// specific: long name → short/display name → GUID. Returns `None` only
    /// when the item carries no usable label at all.
    #[must_use]
    pub fn display_name(&self) -> Option<&str> {
        self.long_name
            .as_deref()
            .or(self.name.as_deref())
            .or(self.guid.as_deref())
    }
}
