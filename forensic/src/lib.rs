//! Anomaly auditor for Windows Shell Items (`ITEMIDLIST` / PIDL components).
//!
//! The reader is [`shellitem_core`]; this crate adds the findings it
//! deliberately does not emit. Every variant is an **observation** — phrased
//! "consistent with", never a verdict — per the fleet reporting model
//! (ADR-0007).
//!
//! Shell items reach an examiner from `.lnk` `LinkTargetIDList` structures and
//! registry ShellBags, both of which record names a user never typed and
//! timestamps no filesystem still holds. That makes display-spoofing and
//! timestamp inconsistency detectable here after the file itself is gone.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use forensicnomicon::report::{Category, Finding, Observation, Severity, Source};
use shellitem_core::{ShellItem, ShellItemKind};

/// Earliest timestamp a FAT date can honestly express: 1980-01-01T00:00:00Z.
/// The FAT epoch is the format's own floor, so anything below it is a decode
/// artefact or a forged field rather than a real time.
const FAT_EPOCH: i64 = 315_532_800;
/// 2100-01-01T00:00:00Z. A fixed ceiling, deliberately not "now": a bound that
/// moves with the clock makes the same evidence audit differently on two days.
const FAR_FUTURE: i64 = 4_102_444_800;

/// A bidirectional-control codepoint. Any of these can reorder how a name
/// renders without changing the bytes that execute.
fn bidi_control(c: char) -> bool {
    matches!(c, '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// The lower-cased extension of a name, if it has one.
fn extension(name: &str) -> Option<String> {
    let (_, ext) = name.rsplit_once('.')?;
    if ext.is_empty() || ext.contains(' ') {
        return None;
    }
    Some(ext.to_ascii_lowercase())
}

/// An observation about one shell item.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellItemAnomaly {
    /// A name carries a bidirectional-control codepoint. These reorder how the
    /// name renders in Explorer without changing the bytes, which is how a
    /// `.exe` is made to read as a document. MITRE T1036.002.
    BidiControlInName {
        /// The name as stored, control codepoint included.
        name: String,
        /// The offending codepoint, so the reader need not re-derive it.
        codepoint: u32,
    },
    /// The long (Unicode) name and the short 8.3 name claim different
    /// extensions. Windows derives the short name from the long one, so the
    /// two normally agree.
    ExtensionMismatch {
        /// The long name from the `0xbeef0004` block.
        long_name: String,
        /// The short/DOS name from the item body.
        short_name: String,
        /// Extension parsed from `long_name`.
        long_ext: String,
        /// Extension parsed from `short_name`.
        short_ext: String,
    },
    /// The recorded creation time is later than the modification time.
    TimestampOrderInversion {
        /// Best available display name for the item.
        name: Option<String>,
        /// Creation time, Unix epoch seconds.
        created: i64,
        /// Modification time, Unix epoch seconds.
        modified: i64,
    },
    /// A timestamp falls outside what the FAT encoding can honestly express.
    ImplausibleTimestamp {
        /// Best available display name for the item.
        name: Option<String>,
        /// Which field: `created`, `modified` or `accessed`.
        field: &'static str,
        /// The decoded value, Unix epoch seconds.
        value: i64,
    },
    /// A class-type byte this reader does not decode. Reported with the byte
    /// itself so "unrecognised" is never asserted without its evidence.
    UnrecognizedClass {
        /// The raw class-type indicator at offset 2.
        class: u8,
        /// Length of the item's raw bytes, including the `cb` prefix.
        byte_len: usize,
    },
}

impl ShellItemAnomaly {
    /// The stable, published anomaly code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::BidiControlInName { .. } => "SHELLITEM-BIDI-CONTROL-IN-NAME",
            Self::ExtensionMismatch { .. } => "SHELLITEM-EXTENSION-MISMATCH",
            Self::TimestampOrderInversion { .. } => "SHELLITEM-TIMESTAMP-ORDER-INVERSION",
            Self::ImplausibleTimestamp { .. } => "SHELLITEM-IMPLAUSIBLE-TIMESTAMP",
            Self::UnrecognizedClass { .. } => "SHELLITEM-UNRECOGNIZED-CLASS",
        }
    }
}

impl Observation for ShellItemAnomaly {
    fn severity(&self) -> Option<Severity> {
        Some(match self {
            Self::BidiControlInName { .. } => Severity::High,
            Self::ExtensionMismatch { .. } | Self::TimestampOrderInversion { .. } => {
                Severity::Medium
            }
            Self::ImplausibleTimestamp { .. } => Severity::Low,
            Self::UnrecognizedClass { .. } => Severity::Info,
        })
    }

    fn code(&self) -> &'static str {
        ShellItemAnomaly::code(self)
    }

    fn category(&self) -> Category {
        match self {
            Self::BidiControlInName { .. } | Self::ExtensionMismatch { .. } => {
                Category::Concealment
            }
            Self::TimestampOrderInversion { .. } => Category::History,
            Self::ImplausibleTimestamp { .. } => Category::Integrity,
            Self::UnrecognizedClass { .. } => Category::Structure,
        }
    }

    fn mitre(&self) -> &'static [&'static str] {
        match self {
            Self::BidiControlInName { .. } => &["T1036.002"],
            Self::ExtensionMismatch { .. } => &["T1036"],
            Self::TimestampOrderInversion { .. } => &["T1070.006"],
            _ => &[],
        }
    }

    fn note(&self) -> String {
        match self {
            Self::BidiControlInName { name, codepoint } => format!(
                "the item name {name:?} contains bidirectional control U+{codepoint:04X}; \
                 consistent with a name crafted to render differently from the bytes that \
                 execute (MITRE T1036.002)"
            ),
            Self::ExtensionMismatch {
                long_name,
                short_name,
                long_ext,
                short_ext,
            } => format!(
                "the long name {long_name:?} claims extension {long_ext:?} while the short name \
                 {short_name:?} claims {short_ext:?}; Windows derives the short name from the \
                 long one, so consistent with a name altered after the item was written"
            ),
            Self::TimestampOrderInversion {
                name,
                created,
                modified,
            } => format!(
                "{} records creation at {created} after modification at {modified}; consistent \
                 with timestamp manipulation (MITRE T1070.006)",
                name.as_deref().unwrap_or("the item")
            ),
            Self::ImplausibleTimestamp { name, field, value } => format!(
                "{} carries {field} time {value}, outside the range a FAT date can express \
                 ({FAT_EPOCH}..{FAR_FUTURE}); consistent with a forged or misdecoded field",
                name.as_deref().unwrap_or("the item")
            ),
            Self::UnrecognizedClass { class, byte_len } => format!(
                "class-type byte {class:#04X} is not decoded by this reader ({byte_len} raw \
                 bytes retained); the item is present but its layout was not interpreted"
            ),
        }
    }
}

/// Audit a parsed `ITEMIDLIST` into a typed anomaly stream.
///
/// Returns an empty vector for ordinary items — a detector that fires on
/// everything reports nothing.
#[must_use]
pub fn audit(items: &[ShellItem]) -> Vec<ShellItemAnomaly> {
    let mut out = Vec::new();
    for item in items {
        for candidate in [item.long_name.as_deref(), item.name.as_deref()]
            .into_iter()
            .flatten()
        {
            if let Some(c) = candidate.chars().find(|c| bidi_control(*c)) {
                out.push(ShellItemAnomaly::BidiControlInName {
                    name: candidate.to_owned(),
                    codepoint: c as u32,
                });
            }
        }

        if let (Some(long), Some(short)) = (item.long_name.as_deref(), item.name.as_deref()) {
            if let (Some(le), Some(se)) = (extension(long), extension(short)) {
                if le != se {
                    out.push(ShellItemAnomaly::ExtensionMismatch {
                        long_name: long.to_owned(),
                        short_name: short.to_owned(),
                        long_ext: le,
                        short_ext: se,
                    });
                }
            }
        }

        if let (Some(created), Some(modified)) = (item.created, item.modified) {
            if created > modified {
                out.push(ShellItemAnomaly::TimestampOrderInversion {
                    name: item.display_name().map(str::to_owned),
                    created,
                    modified,
                });
            }
        }

        for (field, value) in [
            ("created", item.created),
            ("modified", item.modified),
            ("accessed", item.accessed),
        ] {
            if let Some(v) = value {
                if !(FAT_EPOCH..=FAR_FUTURE).contains(&v) {
                    out.push(ShellItemAnomaly::ImplausibleTimestamp {
                        name: item.display_name().map(str::to_owned),
                        field,
                        value: v,
                    });
                }
            }
        }

        if item.kind == ShellItemKind::Unknown {
            out.push(ShellItemAnomaly::UnrecognizedClass {
                class: item.class,
                byte_len: item.raw.len(),
            });
        }
    }
    out
}

/// Audit into normalized [`Finding`]s stamped with this analyzer's [`Source`].
#[must_use]
pub fn audit_findings(items: &[ShellItem], scope: impl Into<String>) -> Vec<Finding> {
    let src = source(scope);
    audit(items)
        .iter()
        .map(|a| a.to_finding(src.clone()))
        .collect()
}

/// The [`Source`] stamp for findings this analyzer emits.
#[must_use]
pub fn source(scope: impl Into<String>) -> Source {
    Source {
        analyzer: "shellitem-forensic".to_string(),
        scope: scope.into(),
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one_of_each() -> Vec<ShellItemAnomaly> {
        vec![
            ShellItemAnomaly::BidiControlInName {
                name: "invoice\u{202E}cod.exe".to_string(),
                codepoint: 0x202E,
            },
            ShellItemAnomaly::ExtensionMismatch {
                long_name: "readme.txt".to_string(),
                short_name: "SETUP~1.EXE".to_string(),
                long_ext: "txt".to_string(),
                short_ext: "exe".to_string(),
            },
            ShellItemAnomaly::TimestampOrderInversion {
                name: Some("old.txt".to_string()),
                created: 1_700_000_000,
                modified: 1_500_000_000,
            },
            ShellItemAnomaly::ImplausibleTimestamp {
                name: None,
                field: "created",
                value: 1,
            },
            ShellItemAnomaly::UnrecognizedClass {
                class: 0x4A,
                byte_len: 6,
            },
        ]
    }

    #[test]
    fn every_variant_reports_a_distinct_code_and_a_severity() {
        let all = one_of_each();
        let mut codes: Vec<&str> = all.iter().map(ShellItemAnomaly::code).collect();
        codes.sort_unstable();
        let before = codes.len();
        codes.dedup();
        assert_eq!(codes.len(), before, "anomaly codes must be unique");
        for a in &all {
            assert!(Observation::severity(a).is_some(), "{a:?} has no severity");
            assert!(!Observation::code(a).is_empty());
        }
    }

    #[test]
    fn every_variant_notes_the_evidence_and_hedges_the_claim() {
        for a in one_of_each() {
            let note = a.note();
            assert!(!note.is_empty());
            // Observations, never verdicts (ADR-0007).
            assert!(
                !note.contains("proves") && !note.contains("malicious"),
                "note states a conclusion: {note}"
            );
        }
        // The unrecognised-class note must carry the offending byte verbatim.
        let u = ShellItemAnomaly::UnrecognizedClass {
            class: 0x4A,
            byte_len: 6,
        };
        let note = u.note();
        assert!(note.contains("0x4A"), "offending byte elided: {note}");
    }

    #[test]
    fn categories_and_mitre_are_assigned_per_variant() {
        let all = one_of_each();
        assert_eq!(Observation::category(&all[0]), Category::Concealment);
        assert_eq!(Observation::category(&all[1]), Category::Concealment);
        assert_eq!(Observation::category(&all[2]), Category::History);
        assert_eq!(Observation::category(&all[3]), Category::Integrity);
        assert_eq!(Observation::category(&all[4]), Category::Structure);
        assert_eq!(Observation::mitre(&all[0]), &["T1036.002"]);
        assert_eq!(Observation::mitre(&all[1]), &["T1036"]);
        assert_eq!(Observation::mitre(&all[2]), &["T1070.006"]);
        assert!(Observation::mitre(&all[3]).is_empty());
        assert!(Observation::mitre(&all[4]).is_empty());
    }

    #[test]
    fn severity_ranks_display_spoofing_above_an_undecoded_class() {
        let all = one_of_each();
        assert_eq!(Observation::severity(&all[0]), Some(Severity::High));
        assert_eq!(Observation::severity(&all[1]), Some(Severity::Medium));
        assert_eq!(Observation::severity(&all[2]), Some(Severity::Medium));
        assert_eq!(Observation::severity(&all[3]), Some(Severity::Low));
        assert_eq!(Observation::severity(&all[4]), Some(Severity::Info));
    }

    #[test]
    fn extension_is_none_when_there_is_no_usable_suffix() {
        assert_eq!(extension("report.pdf").as_deref(), Some("pdf"));
        assert_eq!(extension("PHOTO.JPG").as_deref(), Some("jpg"));
        assert!(extension("no_extension_here").is_none());
        assert!(extension("trailing.").is_none());
        // A "." inside a directory-ish name is not an extension.
        assert!(extension("my. folder").is_none());
    }

    #[test]
    fn bidi_control_covers_the_marks_and_the_isolates() {
        for c in [
            '\u{200E}', '\u{200F}', '\u{202A}', '\u{202E}', '\u{2066}', '\u{2069}',
        ] {
            assert!(bidi_control(c), "{c:?} not flagged");
        }
        for c in ['a', '\u{0301}', '\u{FEFF}'] {
            assert!(!bidi_control(c), "{c:?} wrongly flagged");
        }
    }

    #[test]
    fn source_and_findings_carry_the_analyzer_stamp() {
        let src = source("case/shellbags");
        assert_eq!(src.analyzer, "shellitem-forensic");
        assert_eq!(src.scope, "case/shellbags");
        assert!(src.version.is_some());
        // No items -> no findings, and the call still stamps correctly.
        assert!(audit_findings(&[], "case/shellbags").is_empty());
    }
}
