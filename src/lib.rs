//! NootExtract: acquisition and evidence preparation for authorized Android
//! digital-forensics workflows.
//!
//! # Layering
//!
//! ```text
//! interactive/   guided session; a front end over the same commands
//! commands/      operator-facing workflows, exit-code mapping
//! acquisition/   backends that obtain bytes from a device
//! evidence/      layout, manifests, verification (knows nothing about Android)
//! imaging/       format identification and conversion
//! adb/           process execution and ADB protocol handling
//! device/        typed device state and identification metadata
//! hashing/       streaming SHA-256 / SHA-512
//! util/          path safety, cancellation, byte formatting
//! ```
//!
//! The boundary between `acquisition` and `evidence` is the one that matters:
//! backends never decide where bytes land, how they are named or how they are
//! recorded, so a new backend cannot weaken evidence handling.
//!
//! # Guarantees this crate implements
//!
//! * Original evidence is never modified, overwritten or deleted.
//! * Every artifact is hashed while it is written and recorded in a versioned
//!   manifest.
//! * No external command is ever assembled as a shell string.
//! * No protection mechanism is circumvented; limitations are reported instead.
//!
//! # What it does not do
//!
//! It does not defeat lock screens, passwords, biometrics, encryption, verified
//! boot or any access-control mechanism, and it contains no exploit or
//! privilege-escalation code.

pub mod acquisition;
pub mod adb;
pub mod cli;
pub mod commands;
pub mod device;
pub mod error;
pub mod evidence;
pub mod hashing;
pub mod imaging;
pub mod interactive;
pub mod logging;
pub mod output;
pub mod util;

/// Version of this build, as recorded in every manifest.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Name of this tool, as recorded in every manifest.
pub const NAME: &str = env!("CARGO_PKG_NAME");
