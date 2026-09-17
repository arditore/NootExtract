//! Scripted stand-in for `adb`, used by the integration tests.
//!
//! Real acquisition behaviour depends on a physical handset, which cannot be
//! part of an automated suite. This binary speaks the subset of the ADB
//! command-line surface that NootExtract uses and is driven entirely by
//! environment variables, so device states, missing utilities, unprivileged
//! shells and mid-transfer failures can all be exercised deterministically.
//!
//! It is behind the `test-support` feature and is never built into a release.
//!
//! Scenarios are selected with `FAKE_ADB_SCENARIO`:
//!
//! | value          | behaviour                                              |
//! |----------------|--------------------------------------------------------|
//! | `authorized`   | one authorized device (default)                         |
//! | `unauthorized` | one device that has not accepted this host's key        |
//! | `offline`      | one device reported as offline                          |
//! | `mixed`        | one of each state                                       |
//! | `empty`        | no devices connected                                    |
//! | `no-tar`       | authorized device without a `tar` utility               |
//! | `root`         | authorized device whose shell runs as UID 0             |
//! | `fail-mid`     | transfer emits some data, then exits non-zero           |
//! | `stderr-noise` | transfer succeeds but writes warnings to stderr         |
//!
//! `FAKE_ADB_PAYLOAD_BYTES` sets how many bytes a transfer emits (default 4096).

use std::io::Write;
use std::process::ExitCode;

/// Serial reported for the scripted device.
const SERIAL: &str = "FAKEDEVICE01";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let scenario = std::env::var("FAKE_ADB_SCENARIO").unwrap_or_else(|_| "authorized".to_owned());
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();

    match refs.as_slice() {
        ["version"] => {
            println!("Android Debug Bridge version 1.0.41");
            println!("Version 00.0.0-fake");
            ExitCode::SUCCESS
        }
        ["devices", "-l"] => {
            print_device_list(&scenario);
            ExitCode::SUCCESS
        }
        ["-s", serial, "shell", "getprop"] => {
            if *serial != SERIAL {
                eprintln!("error: device '{serial}' not found");
                return ExitCode::from(1);
            }
            print_properties(&scenario);
            ExitCode::SUCCESS
        }
        ["-s", serial, "exec-out", command] => {
            if *serial != SERIAL {
                eprintln!("error: device '{serial}' not found");
                return ExitCode::from(1);
            }
            exec_out(&scenario, command)
        }
        _ => {
            eprintln!("fake-adb: unsupported invocation: {args:?}");
            ExitCode::from(1)
        }
    }
}

fn print_device_list(scenario: &str) {
    println!("List of devices attached");
    match scenario {
        "empty" => {}
        "unauthorized" => println!("{SERIAL}              unauthorized usb:1-4 transport_id:1"),
        "offline" => println!("{SERIAL}              offline transport_id:1"),
        "mixed" => {
            println!(
                "{SERIAL}              device product:fake model:Fake_Model device:fake transport_id:1"
            );
            println!("UNAUTH02              unauthorized transport_id:2");
            println!("OFFLINE03             offline transport_id:3");
        }
        _ => println!(
            "{SERIAL}              device product:fake model:Fake_Model device:fake transport_id:1"
        ),
    }
    println!();
}

fn print_properties(scenario: &str) {
    println!("[ro.product.manufacturer]: [FakeVendor]");
    println!("[ro.product.brand]: [fakebrand]");
    println!("[ro.product.model]: [Fake Model X]");
    println!("[ro.product.name]: [fake_x]");
    println!("[ro.product.device]: [fakedev]");
    println!("[ro.hardware]: [fakehw]");
    println!("[ro.board.platform]: [fakeplat]");
    println!("[ro.build.version.release]: [14]");
    println!("[ro.build.version.sdk]: [34]");
    println!("[ro.build.version.security_patch]: [2025-01-05]");
    println!("[ro.build.id]: [FAKE.240101.001]");
    println!(
        "[ro.build.fingerprint]: [fakebrand/fake_x/fakedev:14/FAKE.240101.001/1:user/release-keys]"
    );
    println!("[ro.build.type]: [user]");
    println!("[ro.build.tags]: [release-keys]");
    println!("[ro.crypto.state]: [encrypted]");
    println!("[ro.crypto.type]: [file]");
    if scenario == "root" {
        println!("[ro.debuggable]: [1]");
    }
}

fn exec_out(scenario: &str, command: &str) -> ExitCode {
    if command == "id -u" {
        println!("{}", if scenario == "root" { 0 } else { 2000 });
        return ExitCode::SUCCESS;
    }
    if let Some(tool) = command.strip_prefix("command -v ") {
        let available = match tool {
            "tar" => scenario != "no-tar",
            "dd" => true,
            _ => false,
        };
        if available {
            println!("/system/bin/{tool}");
            return ExitCode::SUCCESS;
        }
        return ExitCode::from(1);
    }
    if command.starts_with("ls -d ") {
        println!("path");
        return ExitCode::SUCCESS;
    }
    if command.starts_with("du -s -k ") {
        println!("{}\t/sdcard", payload_bytes().div_ceil(1024).max(1));
        return ExitCode::SUCCESS;
    }
    if command.starts_with("blockdev --getsize64 ") {
        println!("{}", payload_bytes());
        return ExitCode::SUCCESS;
    }
    if command.starts_with("cat /sys/class/block/") {
        return ExitCode::from(1);
    }
    if command.starts_with("tar -c -f - ") || command.starts_with("dd if=") {
        return emit_payload(scenario);
    }

    eprintln!("fake-adb: unsupported remote command: {command}");
    ExitCode::from(1)
}

/// Writes deterministic bytes so tests can assert on exact digests.
fn emit_payload(scenario: &str) -> ExitCode {
    let total = payload_bytes();
    let emit = if scenario == "fail-mid" {
        // Stop short of the announced size to model a truncated transfer.
        total.saturating_div(2)
    } else {
        total
    };

    let mut stdout = std::io::stdout().lock();
    let mut written: u64 = 0;
    let block: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    while written < emit {
        let remaining = usize::try_from(emit - written).unwrap_or(block.len());
        let take = remaining.min(block.len());
        let Some(chunk) = block.get(..take) else {
            break;
        };
        if stdout.write_all(chunk).is_err() {
            return ExitCode::from(1);
        }
        written += take as u64;
    }
    if stdout.flush().is_err() {
        return ExitCode::from(1);
    }

    match scenario {
        "fail-mid" => {
            eprintln!("tar: /sdcard/locked: Permission denied");
            eprintln!("tar: error exit delayed from previous errors");
            ExitCode::from(2)
        }
        "stderr-noise" => {
            eprintln!("tar: removing leading '/' from member names");
            ExitCode::SUCCESS
        }
        _ => ExitCode::SUCCESS,
    }
}

fn payload_bytes() -> u64 {
    std::env::var("FAKE_ADB_PAYLOAD_BYTES")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(4096)
}
