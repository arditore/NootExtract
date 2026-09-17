//! Typed error model and the documented process exit-code contract.
//!
//! Every failure path in NootExtract resolves to exactly one [`Error`] variant,
//! and every variant maps deterministically to one [`ExitCode`]. Callers and
//! automation scripts can therefore branch on the exit status without parsing
//! human-readable output. The mapping is documented in `docs/EXIT_CODES.md`.

use std::path::{Path, PathBuf};

/// Process exit codes produced by the binary.
///
/// The numeric values are part of the tool's public contract and must not be
/// reassigned between releases; new conditions receive new codes instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExitCode {
    /// Operation completed and every integrity check passed.
    Success = 0,
    /// Unclassified runtime failure (I/O, serialization, malformed input).
    Failure = 1,
    /// Command-line usage error. Matches clap's own convention.
    Usage = 2,
    /// Device is absent, offline, unauthorized, or otherwise unusable.
    Device = 3,
    /// Acquisition started but did not complete successfully.
    Acquisition = 4,
    /// Integrity verification reported a mismatch, a missing or an extra file.
    Integrity = 5,
    /// Destination is unsafe: already occupied, not a directory, or unwritable.
    Destination = 6,
    /// Destination filesystem does not have enough free space.
    InsufficientSpace = 7,
    /// A required external tool (for example `adb`) was not found.
    MissingTool = 8,
    /// The requested operation is not supported under the authorized methods
    /// available for this device or artifact. The limitation is reported, never
    /// circumvented.
    Unsupported = 9,
    /// Operator cancellation (Ctrl-C / SIGINT).
    Interrupted = 130,
}

impl ExitCode {
    pub fn as_i32(self) -> i32 {
        i32::from(self as u8)
    }
}

/// The crate-wide error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid usage: {0}")]
    Usage(String),

    #[error("{operation} failed for {}: {source}", .path.display())]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("{0}")]
    Device(String),

    #[error("acquisition failed: {0}")]
    Acquisition(String),

    #[error("integrity check failed: {0}")]
    Integrity(String),

    #[error("unsafe destination: {0}")]
    Destination(String),

    #[error(
        "insufficient free space on {}: {required} bytes required, {available} bytes available",
        .path.display()
    )]
    InsufficientSpace {
        path: PathBuf,
        required: u64,
        available: u64,
    },

    #[error("required external tool `{tool}` was not found: {hint}")]
    MissingTool { tool: String, hint: String },

    /// A limitation of the available authorized acquisition methods.
    ///
    /// This variant exists so that limitations are *reported* rather than
    /// worked around. It is never used to signal that a protection mechanism
    /// should be circumvented.
    #[error("unsupported under available authorized methods: {0}")]
    Unsupported(String),

    #[error("malformed input: {0}")]
    InvalidData(String),

    #[error("operation cancelled by operator")]
    Cancelled,
}

impl Error {
    /// Maps the error onto its documented process exit code.
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Self::Usage(_) => ExitCode::Usage,
            Self::Io { .. } | Self::InvalidData(_) => ExitCode::Failure,
            Self::Device(_) => ExitCode::Device,
            Self::Acquisition(_) => ExitCode::Acquisition,
            Self::Integrity(_) => ExitCode::Integrity,
            Self::Destination(_) => ExitCode::Destination,
            Self::InsufficientSpace { .. } => ExitCode::InsufficientSpace,
            Self::MissingTool { .. } => ExitCode::MissingTool,
            Self::Unsupported(_) => ExitCode::Unsupported,
            Self::Cancelled => ExitCode::Interrupted,
        }
    }

    /// Stable machine-readable discriminator, used in `--json` error output.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Usage(_) => "usage",
            Self::Io { .. } => "io",
            Self::Device(_) => "device",
            Self::Acquisition(_) => "acquisition",
            Self::Integrity(_) => "integrity",
            Self::Destination(_) => "destination",
            Self::InsufficientSpace { .. } => "insufficient_space",
            Self::MissingTool { .. } => "missing_tool",
            Self::Unsupported(_) => "unsupported",
            Self::InvalidData(_) => "invalid_data",
            Self::Cancelled => "cancelled",
        }
    }

    /// Builds an [`Error::Io`] carrying the operation name and the path.
    pub fn io(operation: &'static str, path: impl AsRef<Path>, source: std::io::Error) -> Self {
        Self::Io {
            operation,
            path: path.as_ref().to_path_buf(),
            source,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Extension trait attaching path context to `std::io::Result` values.
pub(crate) trait IoResultExt<T> {
    fn ctx(self, operation: &'static str, path: impl AsRef<Path>) -> Result<T>;
}

impl<T> IoResultExt<T> for std::io::Result<T> {
    fn ctx(self, operation: &'static str, path: impl AsRef<Path>) -> Result<T> {
        self.map_err(|source| Error::io(operation, path, source))
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::cast_possible_truncation,
        clippy::default_trait_access,
        clippy::format_push_string,
        clippy::integer_division,
        clippy::cast_sign_loss
    )]
    use super::*;

    #[test]
    fn exit_codes_are_stable() {
        assert_eq!(ExitCode::Success.as_i32(), 0);
        assert_eq!(ExitCode::Usage.as_i32(), 2);
        assert_eq!(ExitCode::Device.as_i32(), 3);
        assert_eq!(ExitCode::Acquisition.as_i32(), 4);
        assert_eq!(ExitCode::Integrity.as_i32(), 5);
        assert_eq!(ExitCode::Destination.as_i32(), 6);
        assert_eq!(ExitCode::InsufficientSpace.as_i32(), 7);
        assert_eq!(ExitCode::MissingTool.as_i32(), 8);
        assert_eq!(ExitCode::Unsupported.as_i32(), 9);
        assert_eq!(ExitCode::Interrupted.as_i32(), 130);
    }

    #[test]
    fn integrity_failures_never_exit_successfully() {
        let err = Error::Integrity("digest mismatch".into());
        assert_ne!(err.exit_code(), ExitCode::Success);
        assert_eq!(err.exit_code().as_i32(), 5);
    }

    #[test]
    fn io_errors_carry_path_context() {
        let err = Error::io(
            "read",
            "evidence/original/image.raw",
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
        );
        let rendered = err.to_string();
        assert!(rendered.contains("image.raw"), "{rendered}");
        assert!(rendered.contains("read"), "{rendered}");
    }
}
