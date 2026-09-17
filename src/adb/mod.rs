//! Android Debug Bridge integration.
//!
//! Split into three layers so each concern can be tested in isolation:
//!
//! * [`runner`] launches host processes without a shell and bounds their output.
//! * [`remote`] builds the command that the *device* shell will parse.
//! * [`client`] turns ADB output into typed values, treating it as untrusted.

pub mod client;
pub mod remote;
pub mod runner;

pub use client::{AdbClient, DEFAULT_ADB_PROGRAM};
pub use remote::RemoteCommand;
pub use runner::{CommandOutput, CommandRunner, StreamOutcome, SystemRunner};
