//! Windows Shell Item / ITEMIDLIST (PIDL) parser.
//!
//! The reader moved to [`shellitem_core`] under the fleet's reader/analyzer
//! split (ADR-0008); the anomaly auditor is `shellitem-forensic`. This crate
//! stays as a re-export so existing `shellitem::…` paths keep resolving —
//! `shellitem` is published and has downstream users, and crates.io has no
//! rename.
pub use shellitem_core::*;
