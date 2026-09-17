//! Process execution boundary.
//!
//! Every external program is launched through [`std::process::Command`] with an
//! explicit argument vector. No command line is ever assembled as a string and
//! no shell interpreter is involved, which removes host-side command injection
//! as a class: an argument containing `;`, `&&`, backticks or quotes is passed
//! to the target program verbatim and is never re-parsed.
//!
//! Output is read with a hard cap. A malfunctioning or hostile device that
//! streams unbounded text on a metadata channel therefore cannot exhaust host
//! memory; the capture is truncated, flagged, and the remainder drained so the
//! child still terminates instead of blocking forever on a full pipe.
//!
//! The [`CommandRunner`] trait exists so acquisition logic can be exercised in
//! tests against scripted device behaviour without a physical handset.

use std::fmt;
use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::util::cancel::CancellationToken;

/// Default cap for captured stdout/stderr of metadata commands.
pub const DEFAULT_OUTPUT_LIMIT: usize = 4 * 1024 * 1024;
/// Cap for captured stderr while streaming bulk evidence data.
pub const STREAM_STDERR_LIMIT: usize = 256 * 1024;
/// Block size used when relaying a bulk stream.
pub const STREAM_CHUNK_SIZE: usize = 1024 * 1024;
/// Interval at which a cancelled child is re-checked for termination.
const KILL_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Wall-clock limit for a metadata command.
///
/// Metadata commands are short by nature: listing transports, reading system
/// properties, sizing a partition. A device that stops responding mid-command
/// leaves the pipe open without ever producing EOF, which would otherwise block
/// the tool indefinitely — not a hypothetical, since a handset can be unplugged,
/// suspend, or hang at any moment. Bulk transfers deliberately have no such
/// limit: a multi-hour image is legitimate, and cancellation covers that case.
pub const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(60);

/// Kills a child process if it is still running when the deadline passes.
///
/// The child is shared with a watchdog thread so the timeout covers the whole
/// command — including a blocking read on a pipe that never reaches EOF — rather
/// than only the final `wait`.
#[derive(Debug)]
struct Watchdog {
    child: Arc<Mutex<Option<Child>>>,
    timed_out: Arc<AtomicBool>,
    finished: Arc<AtomicBool>,
}

impl Watchdog {
    /// Arms a watchdog over `child`, returning the shared handle.
    fn arm(child: Child, timeout: Option<Duration>) -> Self {
        let shared = Arc::new(Mutex::new(Some(child)));
        let timed_out = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));

        if let Some(timeout) = timeout {
            let child = Arc::clone(&shared);
            let timed_out = Arc::clone(&timed_out);
            let finished = Arc::clone(&finished);
            std::thread::spawn(move || {
                let deadline = std::time::Instant::now() + timeout;
                while std::time::Instant::now() < deadline {
                    if finished.load(Ordering::SeqCst) {
                        return;
                    }
                    std::thread::sleep(KILL_POLL_INTERVAL);
                }
                if finished.load(Ordering::SeqCst) {
                    return;
                }
                timed_out.store(true, Ordering::SeqCst);
                // Killing closes the pipes, which unblocks the reader.
                if let Ok(mut guard) = child.lock()
                    && let Some(child) = guard.as_mut()
                {
                    let _ = child.kill();
                }
            });
        }

        Self {
            child: shared,
            timed_out,
            finished,
        }
    }

    fn timed_out(&self) -> bool {
        self.timed_out.load(Ordering::SeqCst)
    }

    /// Signals the watchdog to stand down.
    fn disarm(&self) {
        self.finished.store(true, Ordering::SeqCst);
    }

    fn with_child<T>(&self, action: impl FnOnce(&mut Child) -> T) -> Option<T> {
        let mut guard = self.child.lock().ok()?;
        guard.as_mut().map(action)
    }
}

/// Captured result of a short-lived command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    /// Process exit code, or `None` when terminated by a signal.
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Set when output exceeded the cap and was truncated.
    pub truncated: bool,
}

impl CommandOutput {
    pub fn success(&self) -> bool {
        self.exit_code == Some(0)
    }

    /// Lossy UTF-8 view of stdout. Device output is not guaranteed to be valid
    /// UTF-8, so invalid sequences are replaced rather than rejected.
    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

/// Outcome of a streamed command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamOutcome {
    pub exit_code: Option<i32>,
    pub stderr: Vec<u8>,
    pub stderr_truncated: bool,
    /// Set when the stream was stopped because cancellation was requested.
    pub cancelled: bool,
}

impl StreamOutcome {
    pub fn success(&self) -> bool {
        self.exit_code == Some(0) && !self.cancelled
    }

    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

/// Abstraction over launching external processes.
///
/// Implementations must never interpret arguments through a shell.
pub trait CommandRunner: fmt::Debug + Send + Sync {
    /// Runs a command to completion, capturing bounded output.
    fn run(&self, program: &str, args: &[String], output_limit: usize) -> Result<CommandOutput>;

    /// Runs a command, relaying stdout to `on_chunk` as it arrives.
    ///
    /// `on_chunk` returning an error aborts the stream and kills the child.
    fn stream(
        &self,
        program: &str,
        args: &[String],
        cancel: &CancellationToken,
        on_chunk: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<StreamOutcome>;
}

/// [`CommandRunner`] backed by real operating-system processes.
#[derive(Debug, Clone, Copy)]
pub struct SystemRunner {
    /// Wall-clock limit applied to metadata commands. Streams are unlimited.
    timeout: Option<Duration>,
}

impl Default for SystemRunner {
    fn default() -> Self {
        Self {
            timeout: Some(DEFAULT_COMMAND_TIMEOUT),
        }
    }
}

impl SystemRunner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Overrides the metadata-command timeout. `None` disables it.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Option<Duration>) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn shared() -> Arc<dyn CommandRunner> {
        Arc::new(Self::default())
    }

    fn spawn(program: &str, args: &[String]) -> Result<Child> {
        Command::new(program)
            .args(args)
            // stdin is closed: no external program driven by this tool is ever
            // interactive, and an inherited terminal could be consumed by it.
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| {
                if source.kind() == std::io::ErrorKind::NotFound {
                    Error::MissingTool {
                        tool: program.to_owned(),
                        hint: format!(
                            "`{program}` was not found on PATH; install the Android SDK \
                             platform-tools or pass --adb-path"
                        ),
                    }
                } else {
                    Error::io("spawn", program, source)
                }
            })
    }
}

/// Reads up to `limit` bytes, then drains and discards the remainder.
///
/// Draining matters: abandoning a pipe with a writer still blocked on it would
/// leave a child process hung and the acquisition unable to observe its exit
/// status.
fn read_capped<R: Read>(mut reader: R, limit: usize) -> std::io::Result<(Vec<u8>, bool)> {
    let mut captured = Vec::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut truncated = false;
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        let chunk = buffer.get(..read).unwrap_or(&[]);
        if captured.len() < limit {
            let remaining = limit - captured.len();
            if chunk.len() <= remaining {
                captured.extend_from_slice(chunk);
            } else {
                captured.extend_from_slice(chunk.get(..remaining).unwrap_or(&[]));
                truncated = true;
            }
        } else {
            truncated = true;
        }
    }
    Ok((captured, truncated))
}

impl CommandRunner for SystemRunner {
    fn run(&self, program: &str, args: &[String], output_limit: usize) -> Result<CommandOutput> {
        let mut child = Self::spawn(program, args)?;

        let stderr_pipe = child.stderr.take();
        // stderr is drained on a separate thread: reading both pipes serially
        // deadlocks as soon as one of them fills its kernel buffer.
        let stderr_handle = std::thread::spawn(move || match stderr_pipe {
            Some(pipe) => read_capped(pipe, output_limit),
            None => Ok((Vec::new(), false)),
        });

        let stdout_pipe = child.stdout.take();
        let watchdog = Watchdog::arm(child, self.timeout);

        let stdout_result = match stdout_pipe {
            Some(pipe) => read_capped(pipe, output_limit),
            None => Ok((Vec::new(), false)),
        };

        let status = watchdog
            .with_child(std::process::Child::wait)
            .transpose()
            .map_err(|source| Error::io("wait for", program, source))?;
        watchdog.disarm();

        if watchdog.timed_out() {
            return Err(Error::Device(format!(
                "`{program}` did not respond within {} seconds and was terminated; the device \
                 may have been disconnected or stopped responding",
                self.timeout.map_or(0, |t| t.as_secs())
            )));
        }

        let (stdout, stdout_truncated) =
            stdout_result.map_err(|source| Error::io("read stdout of", program, source))?;
        let (stderr, stderr_truncated) = stderr_handle
            .join()
            .map_err(|_| Error::InvalidData(format!("stderr reader for `{program}` panicked")))?
            .map_err(|source| Error::io("read stderr of", program, source))?;

        Ok(CommandOutput {
            exit_code: status.and_then(|status| status.code()),
            stdout,
            stderr,
            truncated: stdout_truncated || stderr_truncated,
        })
    }

    fn stream(
        &self,
        program: &str,
        args: &[String],
        cancel: &CancellationToken,
        on_chunk: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<StreamOutcome> {
        let mut child = Self::spawn(program, args)?;

        let stderr_pipe = child.stderr.take();
        let stderr_handle = std::thread::spawn(move || match stderr_pipe {
            Some(pipe) => read_capped(pipe, STREAM_STDERR_LIMIT),
            None => Ok((Vec::new(), false)),
        });

        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::InvalidData(format!("`{program}` produced no stdout pipe")))?;

        let mut buffer = vec![0u8; STREAM_CHUNK_SIZE];
        let mut cancelled = false;
        let mut relay_error: Option<Error> = None;

        loop {
            if cancel.is_cancelled() {
                cancelled = true;
                break;
            }
            let read = match stdout.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(source) => {
                    relay_error = Some(Error::io("read stdout of", program, source));
                    break;
                }
            };
            let chunk = buffer.get(..read).unwrap_or(&[]);
            if let Err(e) = on_chunk(chunk) {
                relay_error = Some(e);
                break;
            }
        }

        if cancelled || relay_error.is_some() {
            // The child is still writing; terminate it so the pipe closes and
            // `wait` can return instead of blocking indefinitely.
            let _ = child.kill();
        }
        drop(stdout);

        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) => std::thread::sleep(KILL_POLL_INTERVAL),
                Err(source) => {
                    if relay_error.is_none() {
                        relay_error = Some(Error::io("wait for", program, source));
                    }
                    break None;
                }
            }
        };

        let (stderr, stderr_truncated) = stderr_handle
            .join()
            .map_err(|_| Error::InvalidData(format!("stderr reader for `{program}` panicked")))?
            .unwrap_or_else(|_| (Vec::new(), false));

        if let Some(error) = relay_error {
            return Err(error);
        }

        Ok(StreamOutcome {
            exit_code: status.and_then(|s| s.code()),
            stderr,
            stderr_truncated,
            cancelled,
        })
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

    fn runner() -> SystemRunner {
        SystemRunner::new()
    }

    /// A portable no-op-ish program available on every supported host.
    fn echo_program() -> (String, Vec<String>) {
        if cfg!(windows) {
            (
                "cmd".to_owned(),
                vec!["/C".to_owned(), "echo hello".to_owned()],
            )
        } else {
            ("echo".to_owned(), vec!["hello".to_owned()])
        }
    }

    #[test]
    fn missing_program_is_reported_as_missing_tool() {
        let err = runner()
            .run("nootextract-nonexistent-program", &[], DEFAULT_OUTPUT_LIMIT)
            .unwrap_err();
        assert!(matches!(err, Error::MissingTool { .. }), "{err:?}");
        assert_eq!(err.exit_code().as_i32(), 8);
    }

    #[test]
    fn captures_stdout_and_exit_code() {
        let (program, args) = echo_program();
        let output = runner().run(&program, &args, DEFAULT_OUTPUT_LIMIT).unwrap();
        assert_eq!(output.exit_code, Some(0));
        assert!(output.stdout_text().contains("hello"), "{output:?}");
        assert!(!output.truncated);
    }

    #[test]
    fn the_program_name_is_never_parsed_by_a_shell() {
        // A shell would split this on `;` and run `echo`. Because the whole
        // string is passed to the OS as one executable name, the spawn simply
        // fails to find it.
        let err = runner()
            .run(
                "nootextract-nonexistent-program; echo pwned",
                &[],
                DEFAULT_OUTPUT_LIMIT,
            )
            .unwrap_err();
        assert!(matches!(err, Error::MissingTool { .. }), "{err:?}");
    }

    /// Argument verbatimness is asserted against a real non-shell binary.
    ///
    /// Windows has no equivalent of `/bin/echo` that is guaranteed present and
    /// is not itself a command interpreter, so the cross-platform coverage of
    /// this property lives in the CLI integration tests, which drive the real
    /// `nootextract` binary.
    #[cfg(unix)]
    #[test]
    fn arguments_reach_the_program_verbatim() {
        let payload = "a; whoami && echo pwned";
        let output = runner()
            .run("/bin/echo", &[payload.to_owned()], DEFAULT_OUTPUT_LIMIT)
            .unwrap();
        assert_eq!(output.stdout_text().trim_end(), payload);
    }

    /// A program that sleeps far longer than any timeout under test.
    ///
    /// PowerShell is used on Windows rather than `cmd /C timeout`, because a
    /// coreutils `timeout` earlier on PATH shadows the Windows one and rejects
    /// its arguments.
    fn sleeping_program(seconds: u32) -> (String, Vec<String>) {
        if cfg!(windows) {
            (
                "powershell".to_owned(),
                vec![
                    "-NoProfile".to_owned(),
                    "-Command".to_owned(),
                    format!("Start-Sleep -Seconds {seconds}"),
                ],
            )
        } else {
            ("sleep".to_owned(), vec![seconds.to_string()])
        }
    }

    #[test]
    fn an_unresponsive_command_is_terminated_by_the_timeout() {
        // Without a watchdog this blocks forever: the child holds the pipe open
        // without producing EOF, so the reader never returns.
        let (program, args) = sleeping_program(60);
        let started = std::time::Instant::now();

        let err = SystemRunner::new()
            .with_timeout(Some(Duration::from_millis(1500)))
            .run(&program, &args, DEFAULT_OUTPUT_LIMIT)
            .unwrap_err();

        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(20),
            "the timeout did not fire; waited {elapsed:?}"
        );
        assert!(matches!(err, Error::Device(_)), "{err:?}");
        assert!(err.to_string().contains("did not respond"), "{err}");
        assert_eq!(err.exit_code().as_i32(), 3);
    }

    #[test]
    fn a_prompt_command_is_unaffected_by_the_timeout() {
        let (program, args) = echo_program();
        let output = SystemRunner::new()
            .with_timeout(Some(Duration::from_secs(30)))
            .run(&program, &args, DEFAULT_OUTPUT_LIMIT)
            .unwrap();
        assert_eq!(output.exit_code, Some(0));
        assert!(output.stdout_text().contains("hello"));
    }

    #[test]
    fn the_timeout_can_be_disabled_for_long_operations() {
        let (program, args) = echo_program();
        let output = SystemRunner::new()
            .with_timeout(None)
            .run(&program, &args, DEFAULT_OUTPUT_LIMIT)
            .unwrap();
        assert_eq!(output.exit_code, Some(0));
    }

    #[test]
    fn streaming_has_no_timeout_because_long_transfers_are_legitimate() {
        // A multi-hour image is a normal acquisition; only cancellation may stop
        // it. This asserts the stream path never consults the timeout.
        let (program, args) = echo_program();
        let mut collected = Vec::new();
        let outcome = SystemRunner::new()
            .with_timeout(Some(Duration::from_nanos(1)))
            .stream(&program, &args, &CancellationToken::new(), &mut |chunk| {
                collected.extend_from_slice(chunk);
                Ok(())
            })
            .unwrap();
        assert!(outcome.success(), "{outcome:?}");
        assert!(String::from_utf8_lossy(&collected).contains("hello"));
    }

    #[test]
    fn output_is_capped_and_flagged() {
        let (program, args) = if cfg!(windows) {
            (
                "cmd".to_owned(),
                vec![
                    "/C".to_owned(),
                    "for /L %i in (1,1,2000) do @echo 0123456789012345678901234567890123456789"
                        .to_owned(),
                ],
            )
        } else {
            (
                "sh".to_owned(),
                vec![
                    "-c".to_owned(),
                    "i=0; while [ $i -lt 2000 ]; do echo 0123456789012345678901234567890123456789; i=$((i+1)); done"
                        .to_owned(),
                ],
            )
        };
        let output = runner().run(&program, &args, 1024).unwrap();
        assert!(output.stdout.len() <= 1024, "{}", output.stdout.len());
        assert!(output.truncated);
        // The child must still have been allowed to finish.
        assert_eq!(output.exit_code, Some(0));
    }

    #[test]
    fn streams_stdout_in_chunks() {
        let (program, args) = echo_program();
        let mut collected = Vec::new();
        let outcome = runner()
            .stream(&program, &args, &CancellationToken::new(), &mut |chunk| {
                collected.extend_from_slice(chunk);
                Ok(())
            })
            .unwrap();
        assert!(outcome.success(), "{outcome:?}");
        assert!(String::from_utf8_lossy(&collected).contains("hello"));
    }

    #[test]
    fn stream_reports_nonzero_exit_status() {
        let (program, args) = if cfg!(windows) {
            ("cmd".to_owned(), vec!["/C".to_owned(), "exit 3".to_owned()])
        } else {
            ("sh".to_owned(), vec!["-c".to_owned(), "exit 3".to_owned()])
        };
        let outcome = runner()
            .stream(&program, &args, &CancellationToken::new(), &mut |_| Ok(()))
            .unwrap();
        assert_eq!(outcome.exit_code, Some(3));
        assert!(!outcome.success());
    }

    #[test]
    fn stream_stops_when_cancelled_before_start() {
        let (program, args) = echo_program();
        let token = CancellationToken::new();
        token.cancel();
        let outcome = runner()
            .stream(&program, &args, &token, &mut |_| Ok(()))
            .unwrap();
        assert!(outcome.cancelled);
        assert!(!outcome.success());
    }

    #[test]
    fn relay_errors_propagate_and_kill_the_child() {
        let (program, args) = echo_program();
        let err = runner()
            .stream(&program, &args, &CancellationToken::new(), &mut |_| {
                Err(Error::Acquisition("sink is full".into()))
            })
            .unwrap_err();
        assert!(matches!(err, Error::Acquisition(_)), "{err:?}");
    }

    #[test]
    fn read_capped_truncates_without_losing_the_tail_of_the_stream() {
        let data = vec![7u8; 10_000];
        let (captured, truncated) = read_capped(std::io::Cursor::new(data), 100).unwrap();
        assert_eq!(captured.len(), 100);
        assert!(truncated);
    }

    #[test]
    fn read_capped_keeps_short_output_intact() {
        let (captured, truncated) =
            read_capped(std::io::Cursor::new(b"abc".to_vec()), 100).unwrap();
        assert_eq!(captured, b"abc");
        assert!(!truncated);
    }
}
