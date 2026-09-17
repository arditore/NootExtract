//! Typed client for the Android Debug Bridge.
//!
//! The client only issues read-oriented commands: listing transports, reading
//! system properties, sizing a source, and streaming bytes out of the device.
//! It never pushes files, installs packages, changes settings, or attempts to
//! obtain privileges it was not already granted.

use std::collections::BTreeMap;
use std::sync::Arc;

use tracing::{debug, warn};

use crate::adb::remote::RemoteCommand;
use crate::adb::runner::{
    CommandOutput, CommandRunner, DEFAULT_OUTPUT_LIMIT, StreamOutcome, SystemRunner,
};
use crate::device::{
    ConnectionState, DeviceMetadata, DeviceSummary, IDENTIFICATION_PROPERTIES, validate_serial,
};
use crate::error::{Error, Result};
use crate::util::cancel::CancellationToken;
use crate::util::paths::sanitize_device_string;

/// Upper bound on properties retained from `getprop`.
///
/// A device controls how many properties it reports; without a cap a hostile
/// or broken handset could inflate the manifest without limit.
const MAX_PROPERTIES: usize = 4096;
/// Upper bound on device-list entries parsed from `adb devices -l`.
const MAX_DEVICE_ENTRIES: usize = 256;

/// Default program name looked up on `PATH`.
pub const DEFAULT_ADB_PROGRAM: &str = "adb";

/// Client for one ADB server instance.
#[derive(Debug, Clone)]
pub struct AdbClient {
    program: String,
    runner: Arc<dyn CommandRunner>,
}

impl AdbClient {
    /// Creates a client using real OS processes.
    pub fn new(program: impl Into<String>) -> Self {
        Self::with_runner(program, SystemRunner::shared())
    }

    /// Creates a client over an arbitrary [`CommandRunner`].
    ///
    /// Tests use this to script device behaviour deterministically.
    pub fn with_runner(program: impl Into<String>, runner: Arc<dyn CommandRunner>) -> Self {
        Self {
            program: program.into(),
            runner,
        }
    }

    pub fn program(&self) -> &str {
        &self.program
    }

    fn run(&self, args: &[String]) -> Result<CommandOutput> {
        debug!(program = %self.program, ?args, "running adb command");
        self.runner.run(&self.program, args, DEFAULT_OUTPUT_LIMIT)
    }

    /// Builds `adb -s <serial> <args...>`.
    fn device_args(serial: &str, args: &[&str]) -> Result<Vec<String>> {
        let serial = validate_serial(serial)?;
        let mut command = Vec::with_capacity(args.len() + 2);
        command.push("-s".to_owned());
        command.push(serial);
        command.extend(args.iter().map(|a| (*a).to_owned()));
        Ok(command)
    }

    /// Returns the ADB client version string, verifying the tool is usable.
    pub fn version(&self) -> Result<String> {
        let output = self.run(&["version".to_owned()])?;
        if !output.success() {
            return Err(Error::MissingTool {
                tool: self.program.clone(),
                hint: format!(
                    "`{} version` exited with {:?}: {}",
                    self.program,
                    output.exit_code,
                    sanitize_device_string(&output.stderr_text())
                ),
            });
        }
        Ok(output
            .stdout_text()
            .lines()
            .next()
            .map(sanitize_device_string)
            .unwrap_or_default())
    }

    /// Lists transports known to the ADB server.
    pub fn list_devices(&self) -> Result<Vec<DeviceSummary>> {
        let output = self.run(&["devices".to_owned(), "-l".to_owned()])?;
        if !output.success() {
            return Err(Error::Device(format!(
                "`{} devices -l` failed: {}",
                self.program,
                sanitize_device_string(&output.stderr_text())
            )));
        }
        Ok(parse_device_list(&output.stdout_text()))
    }

    /// Finds one device by serial, or reports why it is unusable.
    pub fn find_device(&self, serial: &str) -> Result<DeviceSummary> {
        let serial = validate_serial(serial)?;
        self.list_devices()?
            .into_iter()
            .find(|device| device.serial == serial)
            .ok_or_else(|| {
                Error::Device(format!(
                    "device `{serial}` is not connected; run `nootextract devices` to list \
                     available devices"
                ))
            })
    }

    /// Finds a device and requires it to be in an acquirable state.
    pub fn require_acquirable_device(&self, serial: &str) -> Result<DeviceSummary> {
        let device = self.find_device(serial)?;
        if !device.state.is_acquirable() {
            let reason = device
                .state
                .blocking_reason()
                .unwrap_or("the device is not in an acquirable state");
            return Err(Error::Device(format!(
                "device `{}` is {} and cannot be acquired: {reason}",
                device.serial,
                device.state.label()
            )));
        }
        Ok(device)
    }

    /// Reads all Android system properties from the device.
    pub fn properties(&self, serial: &str) -> Result<BTreeMap<String, String>> {
        let args = Self::device_args(serial, &["shell", "getprop"])?;
        let output = self.run(&args)?;
        if !output.success() {
            return Err(Error::Device(format!(
                "reading system properties from `{serial}` failed: {}",
                sanitize_device_string(&output.stderr_text())
            )));
        }
        if output.truncated {
            warn!(
                device_id = %serial,
                "system property output was truncated at the capture limit"
            );
        }
        Ok(parse_getprop(&output.stdout_text()))
    }

    /// Collects the identification metadata retained in manifests.
    pub fn metadata(&self, serial: &str) -> Result<DeviceMetadata> {
        let properties = self.properties(serial)?;
        let mut metadata = DeviceMetadata::from_properties(serial, &properties);
        metadata.shell_uid = self.shell_uid(serial).ok();
        Ok(metadata)
    }

    /// Returns the effective UID of the ADB shell on the device.
    ///
    /// Used only to determine whether a privileged read is *already* possible.
    /// A non-zero result is reported as a limitation; no escalation is
    /// attempted.
    pub fn shell_uid(&self, serial: &str) -> Result<u32> {
        let command = RemoteCommand::new("id").arg("-u");
        let output = self.exec_out(serial, &command)?;
        if !output.success() {
            return Err(Error::Device(format!(
                "could not determine the shell UID on `{serial}`: {}",
                sanitize_device_string(&output.stderr_text())
            )));
        }
        let text = sanitize_device_string(&output.stdout_text());
        text.trim().parse::<u32>().map_err(|_| {
            Error::Device(format!(
                "device `{serial}` reported an unparsable shell UID `{text}`"
            ))
        })
    }

    /// Runs a remote command and captures its bounded output.
    pub fn exec_out(&self, serial: &str, command: &RemoteCommand) -> Result<CommandOutput> {
        let rendered = command.render();
        let args = Self::device_args(serial, &["exec-out", rendered.as_str()])?;
        self.run(&args)
    }

    /// Streams the stdout of a remote command to `on_chunk`.
    ///
    /// `exec-out` is used rather than `shell` because it provides a binary-clean
    /// channel: `adb shell` may allocate a PTY and translate line endings, which
    /// would silently corrupt image data.
    pub fn stream_exec_out(
        &self,
        serial: &str,
        command: &RemoteCommand,
        cancel: &CancellationToken,
        on_chunk: &mut dyn FnMut(&[u8]) -> Result<()>,
    ) -> Result<StreamOutcome> {
        let rendered = command.render();
        let args = Self::device_args(serial, &["exec-out", rendered.as_str()])?;
        debug!(device_id = %serial, remote_command = %rendered, "streaming from device");
        self.runner.stream(&self.program, &args, cancel, on_chunk)
    }

    /// Returns the size in bytes of a regular file on the device, if readable.
    pub fn remote_file_size(&self, serial: &str, path: &str) -> Result<Option<u64>> {
        let command = RemoteCommand::new("stat").arg("-c").arg("%s").arg(path);
        let output = self.exec_out(serial, &command)?;
        if !output.success() {
            return Ok(None);
        }
        Ok(parse_size_output(&output.stdout_text()))
    }

    /// Best-effort size of a block device on the device.
    ///
    /// Android builds vary in which utilities exist, so two independent probes
    /// are tried. A failure is not fatal: it only means progress reporting is
    /// indeterminate and the free-space precheck is advisory.
    pub fn remote_block_size(&self, serial: &str, path: &str) -> Result<Option<u64>> {
        let command = RemoteCommand::new("blockdev").arg("--getsize64").arg(path);
        let output = self.exec_out(serial, &command)?;
        if output.success()
            && let Some(size) = parse_size_output(&output.stdout_text())
        {
            return Ok(Some(size));
        }

        // Fallback: the sysfs `size` attribute is expressed in 512-byte sectors.
        let Some(name) = path.rsplit('/').next().filter(|n| !n.is_empty()) else {
            return Ok(None);
        };
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
        {
            return Ok(None);
        }
        let sysfs = format!("/sys/class/block/{name}/size");
        let command = RemoteCommand::new("cat").arg(sysfs);
        let output = self.exec_out(serial, &command)?;
        if !output.success() {
            return Ok(None);
        }
        Ok(parse_size_output(&output.stdout_text()).and_then(|sectors| sectors.checked_mul(512)))
    }

    /// Resolves a path on the device, following symbolic links.
    ///
    /// This matters more than it looks. `/sdcard` is a symlink to
    /// `/storage/self/primary` on every modern Android build, and neither `tar`
    /// nor `du` follows a symlink given on the command line. Archiving
    /// `/sdcard` directly therefore yields an archive containing one entry —
    /// the link itself — and nothing else, while still exiting successfully.
    ///
    /// The returned path is device-controlled output and is validated before it
    /// is used to build another command.
    pub fn resolve_remote_path(&self, serial: &str, path: &str) -> Result<Option<String>> {
        let command = RemoteCommand::new("readlink").arg("-f").arg(path);
        let output = self.exec_out(serial, &command)?;
        if !output.success() {
            return Ok(None);
        }
        let text = sanitize_device_string(&output.stdout_text());
        let Some(first) = text.lines().map(str::trim).find(|line| !line.is_empty()) else {
            return Ok(None);
        };
        if let Ok(resolved) = crate::adb::remote::validate_remote_path(first) {
            Ok(Some(resolved))
        } else {
            warn!(
                device_id = %serial,
                "the device returned an unusable resolved path; using the requested path"
            );
            Ok(None)
        }
    }

    /// Checks whether a path exists on the device and is readable.
    pub fn remote_path_exists(&self, serial: &str, path: &str) -> Result<bool> {
        let command = RemoteCommand::new("ls").arg("-d").arg(path);
        Ok(self.exec_out(serial, &command)?.success())
    }

    /// Checks whether a utility is present on the device.
    pub fn remote_tool_available(&self, serial: &str, tool: &str) -> Result<bool> {
        let command = RemoteCommand::new("command").arg("-v").arg(tool);
        Ok(self.exec_out(serial, &command)?.success())
    }
}

/// Parses the output of `adb devices -l`.
///
/// Entries whose serial does not validate are dropped rather than trusted: a
/// serial is used to build argument vectors, so an unparsable one is treated as
/// a malformed device response.
pub fn parse_device_list(text: &str) -> Vec<DeviceSummary> {
    let mut devices = Vec::new();
    for line in text.lines() {
        if devices.len() >= MAX_DEVICE_ENTRIES {
            warn!("device list truncated at {MAX_DEVICE_ENTRIES} entries");
            break;
        }
        let line = line.trim();
        if line.is_empty()
            || line.starts_with("List of devices")
            || line.starts_with('*')
            || line.starts_with("adb server")
        {
            continue;
        }

        let mut tokens = line.split_whitespace();
        let Some(raw_serial) = tokens.next() else {
            continue;
        };
        let Ok(serial) = validate_serial(raw_serial) else {
            warn!(
                serial = %sanitize_device_string(raw_serial),
                "ignoring device entry with an unusable serial"
            );
            continue;
        };

        let mut state_words: Vec<&str> = Vec::new();
        let mut descriptors = BTreeMap::new();
        for token in tokens {
            if let Some((key, value)) = split_descriptor(token) {
                descriptors.insert(key, value);
            } else {
                state_words.push(token);
            }
        }

        let state = ConnectionState::parse(&state_words.join(" "));
        let mut summary = DeviceSummary::new(serial, state);
        summary.descriptors = descriptors;
        devices.push(summary);
    }
    devices
}

/// Splits a `key:value` descriptor token, rejecting anything that does not look
/// like one (for example a URL embedded in an error message).
fn split_descriptor(token: &str) -> Option<(String, String)> {
    let (key, value) = token.split_once(':')?;
    if key.is_empty()
        || value.is_empty()
        || !key.chars().all(|c| c.is_ascii_lowercase() || c == '_')
    {
        return None;
    }
    Some((sanitize_device_string(key), sanitize_device_string(value)))
}

/// Parses `getprop` output of the form `[key]: [value]`.
pub fn parse_getprop(text: &str) -> BTreeMap<String, String> {
    let mut properties = BTreeMap::new();
    for line in text.lines() {
        if properties.len() >= MAX_PROPERTIES {
            warn!("system property map truncated at {MAX_PROPERTIES} entries");
            break;
        }
        let line = line.trim();
        let Some(rest) = line.strip_prefix('[') else {
            continue;
        };
        let Some((key, rest)) = rest.split_once("]: [") else {
            continue;
        };
        let Some(value) = rest.strip_suffix(']') else {
            continue;
        };
        let key = sanitize_device_string(key);
        if key.is_empty()
            || !key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        {
            continue;
        }
        properties.insert(key, sanitize_device_string(value));
    }
    properties
}

/// Extracts a leading decimal byte count from command output.
fn parse_size_output(text: &str) -> Option<u64> {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .and_then(|line| line.parse::<u64>().ok())
}

/// Returns the identification properties that were absent from `properties`.
pub fn missing_identification_properties(properties: &BTreeMap<String, String>) -> Vec<String> {
    IDENTIFICATION_PROPERTIES
        .iter()
        .filter(|key| !properties.contains_key(**key))
        .map(|key| (*key).to_owned())
        .collect()
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
    fn parses_a_mixed_device_list() {
        let text = "List of devices attached\n\
                    emulator-5554          device product:sdk_gphone64 model:Pixel_7 device:emu64xa transport_id:1\n\
                    1A2B3C4D               unauthorized usb:1-4 transport_id:2\n\
                    9Z8Y7X6W               offline\n";
        let devices = parse_device_list(text);
        assert_eq!(devices.len(), 3);

        assert_eq!(devices[0].serial, "emulator-5554");
        assert_eq!(devices[0].state, ConnectionState::Authorized);
        assert_eq!(
            devices[0].descriptors.get("model").map(String::as_str),
            Some("Pixel_7")
        );
        assert!(devices[0].state.is_acquirable());

        assert_eq!(devices[1].state, ConnectionState::Unauthorized);
        assert!(!devices[1].state.is_acquirable());

        assert_eq!(devices[2].state, ConnectionState::Offline);
        assert!(!devices[2].state.is_acquirable());
    }

    #[test]
    fn parses_an_empty_device_list() {
        assert!(parse_device_list("List of devices attached\n\n").is_empty());
        assert!(parse_device_list("").is_empty());
    }

    #[test]
    fn ignores_daemon_chatter() {
        let text = "* daemon not running; starting now at tcp:5037\n\
                    * daemon started successfully\n\
                    List of devices attached\n\
                    ABC123   device\n";
        let devices = parse_device_list(text);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].serial, "ABC123");
    }

    #[test]
    fn parses_multiword_no_permissions_state() {
        let text = "List of devices attached\n\
                    ABC123  no permissions (user in plugdev group) usb:1-1\n";
        let devices = parse_device_list(text);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].state, ConnectionState::NoPermissions);
        assert!(!devices[0].state.is_acquirable());
    }

    #[test]
    fn drops_entries_with_hostile_serials() {
        let text = "List of devices attached\n\
                    ../../etc/passwd   device\n\
                    a;id               device\n\
                    GOOD123            device\n";
        let devices = parse_device_list(text);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].serial, "GOOD123");
    }

    #[test]
    fn device_list_is_bounded() {
        let mut text = String::from("List of devices attached\n");
        for i in 0..(MAX_DEVICE_ENTRIES + 50) {
            text.push_str(&format!("SERIAL{i:04}   device\n"));
        }
        assert_eq!(parse_device_list(&text).len(), MAX_DEVICE_ENTRIES);
    }

    #[test]
    fn parses_getprop_output() {
        let text = "[ro.product.model]: [Pixel 7]\n\
                    [ro.build.version.release]: [14]\n\
                    [ro.crypto.state]: [encrypted]\n\
                    [persist.sys.timezone]: [Europe/Paris]\n";
        let properties = parse_getprop(text);
        assert_eq!(
            properties.get("ro.product.model").map(String::as_str),
            Some("Pixel 7")
        );
        assert_eq!(
            properties
                .get("ro.build.version.release")
                .map(String::as_str),
            Some("14")
        );
        assert_eq!(properties.len(), 4);
    }

    #[test]
    fn ignores_malformed_getprop_lines() {
        let text = "garbage\n\
                    [unterminated: [x]\n\
                    [ro.x]: [ok]\n\
                    \n\
                    [ro.bad key!]: [v]\n";
        let properties = parse_getprop(text);
        assert_eq!(properties.len(), 1);
        assert_eq!(properties.get("ro.x").map(String::as_str), Some("ok"));
    }

    #[test]
    fn getprop_values_are_sanitized() {
        let text = "[ro.product.model]: [Pixel\u{1b}[31m 7]\n";
        let properties = parse_getprop(text);
        assert_eq!(
            properties.get("ro.product.model").map(String::as_str),
            Some("Pixel[31m 7")
        );
    }

    #[test]
    fn getprop_map_is_bounded() {
        let mut text = String::new();
        for i in 0..(MAX_PROPERTIES + 100) {
            text.push_str(&format!("[ro.prop{i:05}]: [value]\n"));
        }
        assert_eq!(parse_getprop(&text).len(), MAX_PROPERTIES);
    }

    #[test]
    fn parses_size_output() {
        assert_eq!(parse_size_output("123456\n"), Some(123_456));
        assert_eq!(parse_size_output("  42  \n"), Some(42));
        assert_eq!(parse_size_output("not a number\n"), None);
        assert_eq!(parse_size_output(""), None);
    }

    #[test]
    fn reports_missing_identification_properties() {
        let mut properties = BTreeMap::new();
        properties.insert("ro.product.model".to_owned(), "Pixel".to_owned());
        let missing = missing_identification_properties(&properties);
        assert!(missing.contains(&"ro.product.manufacturer".to_owned()));
        assert!(!missing.contains(&"ro.product.model".to_owned()));
    }

    #[test]
    fn device_args_reject_bad_serials() {
        assert!(AdbClient::device_args("-rf", &["shell"]).is_err());
        assert!(AdbClient::device_args("a b", &["shell"]).is_err());
        let args = AdbClient::device_args("ABC123", &["shell", "getprop"]).unwrap();
        assert_eq!(args, vec!["-s", "ABC123", "shell", "getprop"]);
    }
}
