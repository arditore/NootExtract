//! Construction of commands that execute *on the device*.
//!
//! Host-side argument vectors are safe by construction because no shell is
//! involved (see [`crate::adb::runner`]). The device side is different: `adb
//! shell` and `adb exec-out` join their arguments with spaces and hand the
//! result to `/system/bin/sh` on the handset, which re-parses it. A remote path
//! interpolated naively there would be a genuine injection point.
//!
//! This module therefore builds the remote command as a single, fully
//! POSIX-quoted string and passes it to `adb` as one argument. Remote paths are
//! additionally validated before quoting, so malformed input is rejected rather
//! than merely neutralized.

use crate::error::{Error, Result};

/// Maximum accepted length of a remote path.
const MAX_REMOTE_PATH_LEN: usize = 1024;

/// Characters that never require quoting in a POSIX shell word.
fn is_shell_safe(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | ':' | '=' | '@' | '+' | ',')
}

/// Quotes a single word for a POSIX shell.
///
/// Single quotes suppress every form of expansion; an embedded single quote is
/// emitted as `'\''`, which closes the literal, escapes a quote and reopens it.
pub fn shell_quote(word: &str) -> String {
    if !word.is_empty() && word.chars().all(is_shell_safe) {
        return word.to_owned();
    }
    let mut out = String::with_capacity(word.len() + 2);
    out.push('\'');
    for ch in word.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Validates a path that will be referenced on the device.
///
/// Absolute paths only: a relative path would resolve against whatever working
/// directory the ADB shell happens to start in, which is not a reproducible
/// acquisition scope. Control characters are rejected outright so that device
/// paths cannot corrupt the JSON Lines log or terminal output.
pub fn validate_remote_path(path: &str) -> Result<String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err(Error::Usage("remote path must not be empty".into()));
    }
    if trimmed.len() > MAX_REMOTE_PATH_LEN {
        return Err(Error::Usage(format!(
            "remote path must be at most {MAX_REMOTE_PATH_LEN} characters"
        )));
    }
    if !trimmed.starts_with('/') {
        return Err(Error::Usage(format!(
            "remote path `{trimmed}` must be absolute"
        )));
    }
    if trimmed.chars().any(char::is_control) {
        return Err(Error::Usage(
            "remote path must not contain control characters".into(),
        ));
    }
    if trimmed.contains("..") {
        return Err(Error::Usage(format!(
            "remote path `{trimmed}` must not contain '..'"
        )));
    }
    Ok(trimmed.to_owned())
}

/// A command to be executed by the shell on the device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteCommand {
    argv: Vec<String>,
}

impl RemoteCommand {
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            argv: vec![program.into()],
        }
    }

    #[must_use]
    pub fn arg(mut self, value: impl Into<String>) -> Self {
        self.argv.push(value.into());
        self
    }

    #[must_use]
    pub fn args<I, S>(mut self, values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.argv.extend(values.into_iter().map(Into::into));
        self
    }

    /// Renders the command as one shell-quoted string.
    pub fn render(&self) -> String {
        self.argv
            .iter()
            .map(|word| shell_quote(word))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The unquoted argument vector, for logging and manifest records.
    pub fn argv(&self) -> &[String] {
        &self.argv
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
    fn leaves_plain_words_unquoted() {
        assert_eq!(shell_quote("tar"), "tar");
        assert_eq!(shell_quote("/sdcard/DCIM"), "/sdcard/DCIM");
        assert_eq!(shell_quote("bs=1M"), "bs=1M");
    }

    #[test]
    fn quotes_metacharacters() {
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("a;b"), "'a;b'");
        assert_eq!(shell_quote("$(id)"), "'$(id)'");
        assert_eq!(shell_quote("`id`"), "'`id`'");
        assert_eq!(shell_quote("a|b"), "'a|b'");
        assert_eq!(shell_quote("a&&b"), "'a&&b'");
        assert_eq!(shell_quote(">out"), "'>out'");
        assert_eq!(shell_quote("*"), "'*'");
        assert_eq!(shell_quote(""), "''");
    }

    /// Minimal POSIX word splitter used to check quoting from the shell's side.
    ///
    /// Handles exactly what [`shell_quote`] can emit: literal characters,
    /// single-quoted runs and backslash escapes. Returns the words an
    /// `sh`-compatible shell would produce.
    fn shell_split(input: &str) -> Vec<String> {
        let mut words = Vec::new();
        let mut current = String::new();
        let mut started = false;
        let mut in_quotes = false;
        let mut chars = input.chars();

        while let Some(ch) = chars.next() {
            match ch {
                '\'' if !in_quotes => {
                    in_quotes = true;
                    started = true;
                }
                '\'' if in_quotes => in_quotes = false,
                '\\' if !in_quotes => {
                    if let Some(escaped) = chars.next() {
                        current.push(escaped);
                        started = true;
                    }
                }
                c if c.is_whitespace() && !in_quotes => {
                    if started {
                        words.push(std::mem::take(&mut current));
                        started = false;
                    }
                }
                c => {
                    current.push(c);
                    started = true;
                }
            }
        }
        if started {
            words.push(current);
        }
        words
    }

    #[test]
    fn shell_split_helper_behaves_like_a_posix_shell() {
        assert_eq!(shell_split("a b"), vec!["a", "b"]);
        assert_eq!(shell_split("'a b'"), vec!["a b"]);
        assert_eq!(shell_split(r"'it'\''s'"), vec!["it's"]);
        assert_eq!(shell_split("''"), vec![""]);
    }

    #[test]
    fn escapes_embedded_single_quotes() {
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }

    #[test]
    fn quoted_payloads_survive_shell_parsing_as_one_inert_word() {
        // Each payload tries to break out of the quoting. Re-parsing the quoted
        // form the way a shell would must yield exactly one word, identical to
        // the input, with no command separator ever becoming syntax.
        for payload in [
            "'; rm -rf /; echo '",
            "$(id)",
            "`id`",
            "a && b",
            "x; reboot",
            "| nc attacker 1234",
            "a\nb",
            "*",
            "",
        ] {
            let quoted = shell_quote(payload);
            assert_eq!(
                shell_split(&quoted),
                vec![payload.to_owned()],
                "payload `{payload}` was not preserved as a single word"
            );
        }
    }

    #[test]
    fn renders_full_commands() {
        let command = RemoteCommand::new("tar")
            .arg("-c")
            .arg("-f")
            .arg("-")
            .arg("/sdcard/DCIM");
        assert_eq!(command.render(), "tar -c -f - /sdcard/DCIM");
    }

    #[test]
    fn renders_hostile_paths_as_a_single_word() {
        let path = "/sdcard/'; id; '";
        let command = RemoteCommand::new("tar").arg("-cf").arg("-").arg(path);
        let rendered = command.render();
        assert_eq!(rendered, r"tar -cf - '/sdcard/'\''; id; '\'''");
        // A shell parsing this sees four words, the last being the literal path,
        // so `id` is never a command.
        assert_eq!(shell_split(&rendered), vec!["tar", "-cf", "-", path]);
    }

    #[test]
    fn accepts_valid_remote_paths() {
        for path in [
            "/sdcard",
            "/sdcard/DCIM/Camera",
            "/dev/block/by-name/userdata",
            "/data/local/tmp",
        ] {
            assert!(validate_remote_path(path).is_ok(), "`{path}` must be valid");
        }
    }

    #[test]
    fn rejects_unsafe_remote_paths() {
        for path in [
            "",
            "sdcard",
            "./sdcard",
            "/sdcard/../data",
            "/sdcard/\nid",
            "/sdcard/\0",
        ] {
            assert!(
                validate_remote_path(path).is_err(),
                "`{path}` must be rejected"
            );
        }
    }

    #[test]
    fn rejects_overlong_remote_paths() {
        let long = format!("/{}", "a".repeat(MAX_REMOTE_PATH_LEN));
        assert!(validate_remote_path(&long).is_err());
    }

    #[test]
    fn shell_metacharacters_survive_validation_but_are_quoted() {
        // `;` is legal in a POSIX filename, so validation accepts it; safety
        // comes from quoting, which the rendered command must apply.
        let path = validate_remote_path("/sdcard/a;b").unwrap();
        let rendered = RemoteCommand::new("tar").arg(path).render();
        assert_eq!(rendered, "tar '/sdcard/a;b'");
    }
}
