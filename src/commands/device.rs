//! Device discovery, identification and method listing.

use serde::Serialize;
use tracing::{info, warn};

use crate::acquisition::backend_catalog;
use crate::cli::{DevicesArgs, InfoArgs};
use crate::commands::CommandContext;
use crate::device::{DeviceSummary, validate_serial};
use crate::error::Result;
use crate::output::{print_json, print_line, print_table};

/// JSON shape of `nootextract devices`.
#[derive(Debug, Serialize)]
struct DevicesOutput {
    adb_version: String,
    devices: Vec<DeviceListEntry>,
}

#[derive(Debug, Serialize)]
struct DeviceListEntry {
    #[serde(flatten)]
    device: DeviceSummary,
    /// Whether an acquisition may be attempted against this device.
    acquirable: bool,
    /// Why not, when it may not.
    #[serde(skip_serializing_if = "Option::is_none")]
    blocked_reason: Option<String>,
}

/// `nootextract devices`
pub fn devices(context: &CommandContext, args: &DevicesArgs) -> Result<()> {
    let adb_version = context.adb.version()?;
    let mut devices = context.adb.list_devices()?;

    if !args.no_details {
        for device in &mut devices {
            if !device.state.is_acquirable() {
                continue;
            }
            match context.adb.metadata(&device.serial) {
                Ok(metadata) => device.metadata = Some(metadata),
                Err(e) => warn!(
                    device_id = %device.serial,
                    error = %e,
                    "could not read identification metadata"
                ),
            }
        }
    }

    let entries: Vec<DeviceListEntry> = devices
        .into_iter()
        .map(|device| {
            let acquirable = device.state.is_acquirable();
            let blocked_reason = device.state.blocking_reason().map(ToOwned::to_owned);
            DeviceListEntry {
                device,
                acquirable,
                blocked_reason,
            }
        })
        .collect();

    info!(count = entries.len(), "device discovery completed");

    if context.mode.json {
        return print_json(&DevicesOutput {
            adb_version,
            devices: entries,
        });
    }

    if entries.is_empty() {
        print_line(
            context.mode,
            "No devices are connected. Check the cable, confirm USB debugging is enabled, \
             and accept the authorization prompt on the device.",
        );
        return Ok(());
    }

    let rows: Vec<Vec<String>> = entries
        .iter()
        .map(|entry| {
            let metadata = entry.device.metadata.as_ref();
            vec![
                entry.device.serial.clone(),
                entry.device.state.label().to_owned(),
                entry.device.display_model(),
                metadata
                    .and_then(|m| m.android_release.clone())
                    .unwrap_or_else(|| "-".to_owned()),
                metadata
                    .and_then(|m| m.build_id.clone())
                    .unwrap_or_else(|| "-".to_owned()),
                if entry.acquirable { "yes" } else { "no" }.to_owned(),
            ]
        })
        .collect();

    print_table(
        context.mode,
        &[
            "DEVICE ID",
            "STATE",
            "MODEL",
            "ANDROID",
            "BUILD",
            "ACQUIRABLE",
        ],
        &rows,
    );

    for entry in &entries {
        if let Some(reason) = &entry.blocked_reason {
            print_line(
                context.mode,
                &format!("  {}: {reason}", entry.device.serial),
            );
        }
    }
    Ok(())
}

/// JSON shape of `nootextract info`.
#[derive(Debug, Serialize)]
struct InfoOutput {
    #[serde(flatten)]
    device: DeviceSummary,
    acquirable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    blocked_reason: Option<String>,
}

/// `nootextract info <DEVICE_ID>`
pub fn info(context: &CommandContext, args: &InfoArgs) -> Result<()> {
    let serial = validate_serial(&args.device_id)?;
    let mut device = context.adb.find_device(&serial)?;

    if device.state.is_acquirable() {
        device.metadata = Some(context.adb.metadata(&serial)?);
    }

    let acquirable = device.state.is_acquirable();
    let blocked_reason = device.state.blocking_reason().map(ToOwned::to_owned);

    if context.mode.json {
        return print_json(&InfoOutput {
            device,
            acquirable,
            blocked_reason,
        });
    }

    let mut rows: Vec<Vec<String>> = vec![
        vec!["device id".to_owned(), device.serial.clone()],
        vec![
            "connection state".to_owned(),
            device.state.label().to_owned(),
        ],
        vec![
            "acquirable".to_owned(),
            if acquirable { "yes" } else { "no" }.to_owned(),
        ],
    ];

    if let Some(metadata) = &device.metadata {
        let fields: [(&str, Option<String>); 14] = [
            ("manufacturer", metadata.manufacturer.clone()),
            ("brand", metadata.brand.clone()),
            ("model", metadata.model.clone()),
            ("product name", metadata.product_name.clone()),
            ("device name", metadata.device_name.clone()),
            ("hardware", metadata.hardware.clone()),
            ("board platform", metadata.board_platform.clone()),
            ("android release", metadata.android_release.clone()),
            ("android sdk", metadata.android_sdk.clone()),
            ("security patch", metadata.security_patch.clone()),
            ("build id", metadata.build_id.clone()),
            ("build fingerprint", metadata.build_fingerprint.clone()),
            ("build type", metadata.build_type.clone()),
            ("userdata encryption", metadata.crypto_state.clone()),
        ];
        for (label, value) in fields {
            rows.push(vec![
                label.to_owned(),
                value.unwrap_or_else(|| "-".to_owned()),
            ]);
        }
        if let Some(uid) = metadata.shell_uid {
            rows.push(vec!["adb shell uid".to_owned(), uid.to_string()]);
        }
        if !metadata.missing_properties.is_empty() {
            rows.push(vec![
                "properties not reported".to_owned(),
                metadata.missing_properties.len().to_string(),
            ]);
        }
    }

    print_table(context.mode, &["FIELD", "VALUE"], &rows);

    if let Some(reason) = &blocked_reason {
        print_line(context.mode, &format!("\nNot acquirable: {reason}"));
    }
    Ok(())
}

/// JSON shape of `nootextract methods`.
#[derive(Debug, Serialize)]
struct MethodEntry {
    id: String,
    summary: String,
    kind: String,
    output_format: String,
    requirements: Vec<String>,
    platform_notes: String,
}

/// `nootextract methods`
pub fn methods(context: &CommandContext) -> Result<()> {
    let entries: Vec<MethodEntry> = backend_catalog()
        .into_iter()
        .map(|info| MethodEntry {
            id: info.id.to_owned(),
            summary: info.summary.to_owned(),
            kind: info.kind.as_str().to_owned(),
            output_format: info.output_format.to_owned(),
            requirements: info.requirements.iter().map(|r| (*r).to_owned()).collect(),
            platform_notes: info.platform_notes.to_owned(),
        })
        .collect();

    if context.mode.json {
        return print_json(&entries);
    }

    for entry in &entries {
        print_line(context.mode, &format!("{} ({})", entry.id, entry.kind));
        print_line(context.mode, &format!("  {}", entry.summary));
        print_line(
            context.mode,
            &format!("  output format: {}", entry.output_format),
        );
        print_line(context.mode, "  requirements:");
        for requirement in &entry.requirements {
            print_line(context.mode, &format!("    - {requirement}"));
        }
        print_line(
            context.mode,
            &format!("  platform notes: {}", entry.platform_notes),
        );
        print_line(context.mode, "");
    }
    Ok(())
}
