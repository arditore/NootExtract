//! Device model: connection state, identification metadata and serial validation.
//!
//! Everything in this module originates from the device or from the ADB server
//! and is therefore treated as untrusted input. Strings are sanitized on the way
//! in (see [`crate::util::paths::sanitize_device_string`]) and serials are
//! validated against a narrow alphabet before they are ever placed in an
//! argument vector.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::util::paths::sanitize_device_string;

/// Maximum accepted length of a device serial.
const MAX_SERIAL_LEN: usize = 64;

/// Connection state of a device as reported by the ADB server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "state", content = "detail")]
pub enum ConnectionState {
    /// `device`: connected and USB debugging authorized for this host key.
    Authorized,
    /// `unauthorized`: connected, but the host key has not been accepted on the
    /// device. Acquisition is refused in this state.
    Unauthorized,
    /// `offline`: known to the ADB server but not currently responsive.
    Offline,
    /// `bootloader` / `fastboot`.
    Bootloader,
    /// `recovery`.
    Recovery,
    /// `sideload`.
    Sideload,
    /// `no permissions`: a host-side udev/driver problem, not a device lock.
    NoPermissions,
    /// Any other state string reported by the ADB server.
    Other(String),
}

impl ConnectionState {
    pub fn parse(value: &str) -> Self {
        let normalized = sanitize_device_string(value).to_ascii_lowercase();
        match normalized.as_str() {
            "device" => Self::Authorized,
            "unauthorized" => Self::Unauthorized,
            "offline" => Self::Offline,
            "bootloader" | "fastboot" => Self::Bootloader,
            "recovery" => Self::Recovery,
            "sideload" => Self::Sideload,
            _ if normalized.starts_with("no permissions") => Self::NoPermissions,
            other => Self::Other(other.to_owned()),
        }
    }

    /// Label shown to the operator.
    pub fn label(&self) -> &str {
        match self {
            Self::Authorized => "authorized",
            Self::Unauthorized => "unauthorized",
            Self::Offline => "offline",
            Self::Bootloader => "bootloader",
            Self::Recovery => "recovery",
            Self::Sideload => "sideload",
            Self::NoPermissions => "no-permissions",
            Self::Other(other) => other.as_str(),
        }
    }

    /// Whether an authorized acquisition may be attempted in this state.
    ///
    /// Only `Authorized` qualifies. An unauthorized device is never presented as
    /// available: accepting the host key on the device is an operator action
    /// performed on the handset, not something this tool works around.
    pub fn is_acquirable(&self) -> bool {
        matches!(self, Self::Authorized)
    }

    /// Operator-facing explanation of why a non-acquirable state blocks work.
    pub fn blocking_reason(&self) -> Option<&'static str> {
        match self {
            Self::Authorized => None,
            Self::Unauthorized => Some(
                "the device has not authorized this host's ADB key; accept the \
                 USB debugging prompt on the device and retry",
            ),
            Self::Offline => Some(
                "the device is offline; re-seat the cable, confirm the device is \
                 powered on and retry",
            ),
            Self::Bootloader => Some(
                "the device is in bootloader/fastboot mode, where no ADB acquisition \
                 backend is available",
            ),
            Self::Recovery => Some(
                "the device is in recovery mode; ADB access depends on the recovery \
                 image and is not assumed here",
            ),
            Self::Sideload => Some("the device is in sideload mode and cannot be acquired"),
            Self::NoPermissions => Some(
                "the host cannot access the USB device; fix the host udev rules or \
                 driver configuration and retry",
            ),
            Self::Other(_) => {
                Some("the device is in a state with no available acquisition backend")
            }
        }
    }
}

impl fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// One entry of the device list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSummary {
    /// ADB serial, used as the device identifier throughout the tool.
    pub serial: String,
    #[serde(flatten)]
    pub state: ConnectionState,
    /// Free-form descriptors advertised by the ADB server (`-l` output).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub descriptors: BTreeMap<String, String>,
    /// Identification metadata, populated only for authorized devices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<DeviceMetadata>,
}

impl DeviceSummary {
    pub fn new(serial: String, state: ConnectionState) -> Self {
        Self {
            serial,
            state,
            descriptors: BTreeMap::new(),
            metadata: None,
        }
    }

    /// Short model description for table output.
    pub fn display_model(&self) -> String {
        if let Some(metadata) = &self.metadata {
            let manufacturer = metadata.manufacturer.as_deref().unwrap_or("");
            let model = metadata.model.as_deref().unwrap_or("");
            let combined = format!("{manufacturer} {model}");
            let combined = combined.trim();
            if !combined.is_empty() {
                return combined.to_owned();
            }
        }
        self.descriptors
            .get("model")
            .or_else(|| self.descriptors.get("device"))
            .cloned()
            .unwrap_or_else(|| "-".to_owned())
    }
}

/// Non-invasive identification metadata read from Android system properties.
///
/// The selection is deliberately limited to acquisition-relevant build and
/// hardware identification. No subscriber, account, contact, location or
/// telephony identifier is collected: none of it is needed to document what was
/// acquired, and collecting it would widen the tool's exposure to personal data.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceMetadata {
    pub serial: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manufacturer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub brand: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub board_platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub android_release: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub android_sdk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_patch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_tags: Option<String>,
    /// `ro.crypto.state`: whether userdata is reported as encrypted. Recorded
    /// because it determines what a logical acquisition can actually read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crypto_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crypto_type: Option<String>,
    /// Effective UID of the ADB shell, when it was determined.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shell_uid: Option<u32>,
    /// Raw property names that were requested but not reported by the device.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_properties: Vec<String>,
}

/// System properties read for identification, in manifest order.
pub const IDENTIFICATION_PROPERTIES: [&str; 15] = [
    "ro.product.manufacturer",
    "ro.product.brand",
    "ro.product.model",
    "ro.product.name",
    "ro.product.device",
    "ro.hardware",
    "ro.board.platform",
    "ro.build.version.release",
    "ro.build.version.sdk",
    "ro.build.version.security_patch",
    "ro.build.id",
    "ro.build.fingerprint",
    "ro.build.type",
    "ro.build.tags",
    "ro.crypto.state",
];

impl DeviceMetadata {
    /// Builds metadata from a property map, recording which keys were absent.
    pub fn from_properties(serial: &str, properties: &BTreeMap<String, String>) -> Self {
        let mut missing = Vec::new();
        let mut take = |key: &str| -> Option<String> {
            match properties.get(key) {
                Some(value) if !value.is_empty() => Some(value.clone()),
                _ => {
                    missing.push(key.to_owned());
                    None
                }
            }
        };

        let manufacturer = take("ro.product.manufacturer");
        let brand = take("ro.product.brand");
        let model = take("ro.product.model");
        let product_name = take("ro.product.name");
        let device_name = take("ro.product.device");
        let hardware = take("ro.hardware");
        let board_platform = take("ro.board.platform");
        let android_release = take("ro.build.version.release");
        let android_sdk = take("ro.build.version.sdk");
        let security_patch = take("ro.build.version.security_patch");
        let build_id = take("ro.build.id");
        let build_fingerprint = take("ro.build.fingerprint");
        let build_type = take("ro.build.type");
        let build_tags = take("ro.build.tags");
        let crypto_state = take("ro.crypto.state");
        let crypto_type = properties.get("ro.crypto.type").cloned();

        Self {
            serial: sanitize_device_string(serial),
            manufacturer,
            brand,
            model,
            product_name,
            device_name,
            hardware,
            board_platform,
            android_release,
            android_sdk,
            security_patch,
            build_id,
            build_fingerprint,
            build_type,
            build_tags,
            crypto_state,
            crypto_type,
            shell_uid: None,
            missing_properties: missing,
        }
    }

    /// Whether the device reports userdata as encrypted.
    pub fn reports_encrypted_userdata(&self) -> bool {
        matches!(self.crypto_state.as_deref(), Some("encrypted"))
    }
}

/// Validates a device serial before it is used as a process argument.
///
/// Serials come from the ADB server and, indirectly, from the device. The
/// alphabet is restricted to what real serials use (including `host:port` forms
/// for network transports) and a leading `-` is rejected so that a serial can
/// never be interpreted as an option by `adb`.
pub fn validate_serial(serial: &str) -> Result<String> {
    let trimmed = serial.trim();
    if trimmed.is_empty() {
        return Err(Error::Usage("device identifier must not be empty".into()));
    }
    if trimmed.len() > MAX_SERIAL_LEN {
        return Err(Error::Usage(format!(
            "device identifier must be at most {MAX_SERIAL_LEN} characters"
        )));
    }
    if trimmed.starts_with('-') {
        return Err(Error::Usage(
            "device identifier must not start with '-'".into(),
        ));
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '_' | '-'))
    {
        return Err(Error::Usage(format!(
            "device identifier `{}` contains unsupported characters",
            sanitize_device_string(trimmed)
        )));
    }
    Ok(trimmed.to_owned())
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
    fn parses_known_states() {
        assert_eq!(
            ConnectionState::parse("device"),
            ConnectionState::Authorized
        );
        assert_eq!(
            ConnectionState::parse("unauthorized"),
            ConnectionState::Unauthorized
        );
        assert_eq!(ConnectionState::parse("offline"), ConnectionState::Offline);
        assert_eq!(
            ConnectionState::parse("recovery"),
            ConnectionState::Recovery
        );
        assert_eq!(
            ConnectionState::parse("no permissions (user in plugdev group)"),
            ConnectionState::NoPermissions
        );
    }

    #[test]
    fn unknown_states_are_preserved_but_not_acquirable() {
        let state = ConnectionState::parse("connecting");
        assert_eq!(state, ConnectionState::Other("connecting".into()));
        assert!(!state.is_acquirable());
        assert!(state.blocking_reason().is_some());
    }

    #[test]
    fn only_authorized_devices_are_acquirable() {
        assert!(ConnectionState::Authorized.is_acquirable());
        for state in [
            ConnectionState::Unauthorized,
            ConnectionState::Offline,
            ConnectionState::Bootloader,
            ConnectionState::Recovery,
            ConnectionState::Sideload,
            ConnectionState::NoPermissions,
            ConnectionState::Other("weird".into()),
        ] {
            assert!(!state.is_acquirable(), "{state:?} must not be acquirable");
            assert!(state.blocking_reason().is_some(), "{state:?}");
        }
    }

    #[test]
    fn state_parsing_strips_control_characters() {
        let state = ConnectionState::parse("device\r");
        assert_eq!(state, ConnectionState::Authorized);
    }

    #[test]
    fn accepts_real_world_serials() {
        for serial in [
            "emulator-5554",
            "1A2B3C4D",
            "192.168.1.20:5555",
            "R5CT10_ABC",
            "abc.def-1",
        ] {
            assert!(validate_serial(serial).is_ok(), "`{serial}` must be valid");
        }
    }

    #[test]
    fn rejects_serials_that_could_be_mistaken_for_flags() {
        assert!(validate_serial("-s").is_err());
        assert!(validate_serial("--help").is_err());
    }

    #[test]
    fn rejects_serials_with_injection_characters() {
        for serial in [
            "abc;rm -rf /",
            "abc def",
            "abc$(whoami)",
            "abc`id`",
            "abc\nid",
            "abc&&id",
            "abc|id",
            "abc/../x",
            "",
        ] {
            assert!(
                validate_serial(serial).is_err(),
                "`{serial}` must be rejected"
            );
        }
    }

    #[test]
    fn rejects_overlong_serials() {
        assert!(validate_serial(&"a".repeat(MAX_SERIAL_LEN + 1)).is_err());
    }

    #[test]
    fn metadata_records_missing_properties() {
        let mut properties = BTreeMap::new();
        properties.insert("ro.product.model".to_owned(), "Pixel 7".to_owned());
        properties.insert("ro.build.version.release".to_owned(), "14".to_owned());

        let metadata = DeviceMetadata::from_properties("ABC123", &properties);
        assert_eq!(metadata.model.as_deref(), Some("Pixel 7"));
        assert_eq!(metadata.android_release.as_deref(), Some("14"));
        assert!(metadata.manufacturer.is_none());
        assert!(
            metadata
                .missing_properties
                .contains(&"ro.product.manufacturer".to_owned())
        );
        assert!(!metadata.reports_encrypted_userdata());
    }

    #[test]
    fn metadata_detects_encrypted_userdata() {
        let mut properties = BTreeMap::new();
        properties.insert("ro.crypto.state".to_owned(), "encrypted".to_owned());
        let metadata = DeviceMetadata::from_properties("ABC123", &properties);
        assert!(metadata.reports_encrypted_userdata());
    }

    #[test]
    fn metadata_sanitizes_the_serial() {
        let metadata = DeviceMetadata::from_properties("ABC\n123", &BTreeMap::new());
        assert_eq!(metadata.serial, "ABC123");
    }

    #[test]
    fn empty_property_values_count_as_missing() {
        let mut properties = BTreeMap::new();
        properties.insert("ro.product.model".to_owned(), String::new());
        let metadata = DeviceMetadata::from_properties("ABC", &properties);
        assert!(metadata.model.is_none());
        assert!(
            metadata
                .missing_properties
                .contains(&"ro.product.model".to_owned())
        );
    }
}
