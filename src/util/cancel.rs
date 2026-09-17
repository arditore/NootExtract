//! Cooperative cancellation shared between the CLI, the acquisition backends
//! and the hashing loops.
//!
//! Acquisition must end deterministically when the operator interrupts it: the
//! partial artifact is flushed, hashed and recorded as incomplete rather than
//! being left in an unknown state. A shared atomic flag is sufficient here and
//! avoids pulling in an async runtime for what is fundamentally blocking I/O.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::{Error, Result};

/// A clonable handle to a single cancellation flag.
#[derive(Debug, Clone, Default)]
pub struct CancellationToken {
    flag: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests cancellation. Idempotent and safe to call from a signal handler.
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// Returns [`Error::Cancelled`] if cancellation has been requested.
    pub fn check(&self) -> Result<()> {
        if self.is_cancelled() {
            Err(Error::Cancelled)
        } else {
            Ok(())
        }
    }
}

/// Installs a Ctrl-C / SIGINT handler that sets the returned token.
///
/// The handler only flips an atomic flag; all teardown happens on the worker
/// thread so that evidence writers can flush and finalize their digests.
/// A second interrupt is not escalated to an immediate abort, because that
/// would leave a partial artifact unhashed and unrecorded.
pub fn install_signal_handler() -> Result<CancellationToken> {
    let token = CancellationToken::new();
    let handler_token = token.clone();
    ctrlc::set_handler(move || handler_token.cancel())
        .map_err(|e| Error::InvalidData(format!("could not install signal handler: {e}")))?;
    Ok(token)
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
    fn token_starts_uncancelled() {
        let token = CancellationToken::new();
        assert!(!token.is_cancelled());
        assert!(token.check().is_ok());
    }

    #[test]
    fn cancellation_is_visible_through_clones() {
        let token = CancellationToken::new();
        let clone = token.clone();
        clone.cancel();
        assert!(token.is_cancelled());
        assert!(matches!(token.check(), Err(Error::Cancelled)));
    }

    #[test]
    fn cancellation_is_idempotent() {
        let token = CancellationToken::new();
        token.cancel();
        token.cancel();
        assert!(token.is_cancelled());
    }
}
