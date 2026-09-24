//! Interactive shell.
//!
//! Running `nootextract` with no arguments opens a prompt:
//!
//! ```text
//! nootextract> devices
//! nootextract> acquire 45280DLAQ003QS --case-id CASE-001 --evidence-id EV-1 -o ./evidence
//! nootextract> exit
//! ```
//!
//! What is typed at the prompt is parsed by the same `clap` definition the
//! command line uses and dispatched through the same function. There is no
//! second command surface to keep in step: every flag, default and validation
//! rule is the one the flags already have, and a command learned here works
//! unchanged in a script.
//!
//! # Guided acquisition
//!
//! A command that needs arguments and is given none asks for them instead of
//! printing a usage error — `acquire` alone walks through the whole thing,
//! previews it as a dry run, and prints the equivalent invocation once before
//! transferring anything. When the operator typed the command themselves, it is
//! not echoed back: the line they wrote is already the reproducible form.
//!
//! # Terminal only
//!
//! The shell refuses to start when standard input is not a terminal. Reaching a
//! prompt from a pipe or a CI job would either hang or consume unrelated input,
//! so a bare invocation there is a usage error instead.

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;

use clap::Parser as _;

use crate::acquisition::{DEFAULT_METHOD, backend_catalog};
use crate::cli::{AcquireArgs, Cli, GlobalArgs};
use crate::commands::{CommandContext, run_command};
use crate::error::{Error, Result};
use crate::util::paths::validate_identifier;

/// Commands the shell handles itself rather than passing to the parser.
const BUILTINS: &[(&str, &str)] = &[
    ("help", "list these commands"),
    ("exit", "leave the shell (Ctrl-D also works)"),
    ("quit", "leave the shell"),
];

/// Entry point for the interactive shell.
pub fn run(context: &CommandContext, global: &GlobalArgs) -> Result<()> {
    if !std::io::stdin().is_terminal() {
        return Err(Error::Usage(
            "the interactive shell needs a terminal, and standard input is not one. Use a \
             subcommand instead; `nootextract --help` lists them."
                .into(),
        ));
    }
    if global.json {
        return Err(Error::Usage(
            "--json describes machine-readable output and has no meaning for the shell. \
             Use a subcommand with --json instead."
                .into(),
        ));
    }

    banner();

    let mut input = Input::from_stdin();
    loop {
        let line = match input.line("nootextract>") {
            Ok(line) => line,
            // Ctrl-D.
            Err(Error::Cancelled) => break,
            Err(e) => return Err(e),
        };

        match handle(context, global, &mut input, &line) {
            Ok(true) => {}
            // Leaving by choice and reaching end of input end the same way.
            Ok(false) | Err(Error::Cancelled) => break,
            // A failed command is not a reason to close the shell.
            Err(e) => {
                eprintln!("error: {e}");
                eprintln!("  (exit code {} outside the shell)", e.exit_code().as_i32());
            }
        }
    }

    println!("noot noot.");
    Ok(())
}

fn banner() {
    println!();
    println!("   .--.");
    println!("  |o_o |   {} {}", crate::NAME, crate::VERSION);
    println!("  |:_/ |   interactive shell");
    println!();
    println!("Type a command, `help` for the list, `exit` to leave.");
    println!("Commands take the same flags as the command line, so anything that works");
    println!("here works in a script.");
    println!();
}

/// Handles one line. Returns false when the shell should close.
fn handle(
    context: &CommandContext,
    global: &GlobalArgs,
    input: &mut Input,
    line: &str,
) -> Result<bool> {
    let words = split_line(line)?;
    let Some(first) = words.first().map(String::as_str) else {
        return Ok(true);
    };

    match first {
        "exit" | "quit" | "q" => return Ok(false),
        "help" | "?" => {
            print_help();
            return Ok(true);
        }
        // Opening a shell inside the shell has no meaning.
        "interactive" => {
            println!("Already in the interactive shell.");
            return Ok(true);
        }
        _ => {}
    }

    // A command that needs an argument and was given none asks for it, rather
    // than answering a person at a prompt with a usage error.
    let Some(words) = complete_missing_arguments(input, words)? else {
        return Ok(true);
    };

    if words.first().map(String::as_str) == Some("acquire") && words.len() == 1 {
        return guided_acquisition(context, global, input).map(|()| true);
    }

    let argv = build_argv(global, &words);
    match Cli::try_parse_from(&argv) {
        Ok(mut cli) => {
            // A per-line context, so flags such as --quiet apply to this command
            // only. Built before the command is taken out of the parsed value.
            let line_context = CommandContext::new(&cli, context.cancel.clone());
            let line_global = cli.global.clone();
            let Some(command) = cli.command.take() else {
                return Ok(true);
            };
            run_command(&line_context, &line_global, command)?;
        }
        // Covers usage errors, `--help` and `--version`, all of which clap
        // renders for us.
        Err(e) => println!("{e}"),
    }
    Ok(true)
}

fn print_help() {
    println!();
    println!("Commands (each accepts the same flags as the command line):");
    for (name, detail) in [
        ("devices", "list connected devices and their state"),
        ("info <DEVICE>", "identification metadata for one device"),
        (
            "acquire",
            "guided acquisition; give flags to run it directly",
        ),
        ("verify <CASE>", "recompute every digest in a case"),
        (
            "extract <ARCHIVE>",
            "unpack a logical acquisition, manifested",
        ),
        (
            "convert <IMAGE>",
            "produce a derived image in another format",
        ),
        ("copy <ARTIFACT>", "produce a verified working copy"),
        ("hash <FILE>", "streaming SHA-256 of a file"),
        ("manifest <PATH>", "inspect and validate a manifest"),
        ("report <CASE>", "render a Markdown case report"),
        ("doctor", "check adb, devices, free space"),
        ("methods", "acquisition methods and their requirements"),
    ] {
        println!("  {name:<20} {detail}");
    }
    for (name, detail) in BUILTINS {
        println!("  {name:<20} {detail}");
    }
    println!();
    println!("Append --help to any command for its full options.");
    println!();
}

/// Asks for the one argument a command cannot run without.
///
/// Returns `None` when the operator declined by entering nothing.
fn complete_missing_arguments(
    input: &mut Input,
    mut words: Vec<String>,
) -> Result<Option<Vec<String>>> {
    let [command] = words.as_slice() else {
        return Ok(Some(words));
    };
    let prompt = match command.as_str() {
        "info" => "Device serial",
        "verify" | "report" => "Case directory",
        "extract" => "Archive to extract",
        "convert" | "copy" => "Artifact path",
        "hash" => "File to hash",
        "manifest" => "Manifest or case directory",
        _ => return Ok(Some(words)),
    };

    let answer = input.line(&format!("  {prompt} (blank to cancel):"))?;
    if answer.is_empty() {
        return Ok(None);
    }
    words.push(answer);
    Ok(Some(words))
}

/// Builds the argument vector handed to the parser.
///
/// Global options given when the shell was started carry into every command, so
/// `nootextract --adb-path X` then `devices` uses X.
fn build_argv(global: &GlobalArgs, words: &[String]) -> Vec<String> {
    let mut argv = vec!["nootextract".to_owned()];
    if global.adb_path != crate::adb::DEFAULT_ADB_PROGRAM
        && !words.iter().any(|word| word == "--adb-path")
    {
        argv.push("--adb-path".to_owned());
        argv.push(global.adb_path.clone());
    }
    argv.extend(words.iter().cloned());
    argv
}

/// Splits a line into words, honouring quotes so paths with spaces work.
fn split_line(line: &str) -> Result<Vec<String>> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut started = false;
    let mut quote: Option<char> = None;

    for ch in line.chars() {
        match ch {
            c if Some(c) == quote => quote = None,
            '"' | '\'' if quote.is_none() => {
                quote = Some(ch);
                started = true;
            }
            c if c.is_whitespace() && quote.is_none() => {
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

    if quote.is_some() {
        return Err(Error::Usage("unterminated quote".into()));
    }
    if started {
        words.push(current);
    }
    Ok(words)
}

/// Reads operator input.
///
/// The reader is injected rather than taken from `stdin` directly, so the shell
/// can be driven by a scripted transcript in tests. An interactive layer that
/// can only be exercised by hand is one that stops being exercised.
struct Input {
    reader: Box<dyn BufRead>,
}

impl Input {
    fn from_stdin() -> Self {
        Self {
            reader: Box::new(std::io::BufReader::new(std::io::stdin())),
        }
    }

    #[cfg(test)]
    fn scripted(script: &str) -> Self {
        Self {
            reader: Box::new(std::io::Cursor::new(script.as_bytes().to_vec())),
        }
    }

    /// Reads one line. End of input closes the shell rather than looping.
    fn line(&mut self, prompt: &str) -> Result<String> {
        print!("{prompt} ");
        let _ = std::io::stdout().flush();
        let mut buffer = String::new();
        let read = self
            .reader
            .read_line(&mut buffer)
            .map_err(|e| Error::io("read", "<stdin>", e))?;
        if read == 0 {
            println!();
            return Err(Error::Cancelled);
        }
        Ok(buffer.trim().to_owned())
    }

    fn line_default(&mut self, question: &str, default: &str) -> Result<String> {
        let answer = self.line(&format!("  {question} [{default}]:"))?;
        Ok(if answer.is_empty() {
            default.to_owned()
        } else {
            answer
        })
    }

    /// Reads a line, repeating until `validate` accepts it.
    fn line_validated(
        &mut self,
        question: &str,
        validate: impl Fn(&str) -> Result<String>,
    ) -> Result<String> {
        loop {
            let answer = self.line(&format!("  {question}:"))?;
            match validate(&answer) {
                Ok(value) => return Ok(value),
                Err(e) => println!("    {e}"),
            }
        }
    }

    fn confirm(&mut self, question: &str, default: bool) -> Result<bool> {
        let hint = if default { "Y/n" } else { "y/N" };
        loop {
            let answer = self.line(&format!("  {question} [{hint}]"))?.to_lowercase();
            match answer.as_str() {
                "" => return Ok(default),
                "y" | "yes" | "o" | "oui" => return Ok(true),
                "n" | "no" | "non" => return Ok(false),
                _ => println!("    answer y or n"),
            }
        }
    }

    fn choose(&mut self, title: &str, options: &[(String, String)]) -> Result<usize> {
        println!("  {title}");
        for (index, (label, detail)) in options.iter().enumerate() {
            println!("    {:>2}  {label:<24} {detail}", index + 1);
        }
        loop {
            let answer = self.line("  Choice:")?;
            if let Ok(index) = answer.parse::<usize>()
                && index >= 1
                && index <= options.len()
            {
                return Ok(index - 1);
            }
            println!("    enter a number between 1 and {}", options.len());
        }
    }
}

/// Walks through an acquisition, previewing it before anything is transferred.
fn guided_acquisition(
    context: &CommandContext,
    global: &GlobalArgs,
    input: &mut Input,
) -> Result<()> {
    let device_id = pick_device(context, input)?;

    let case_id = input.line_validated("Case identifier", |value| {
        validate_identifier(value, "case id")
    })?;
    let evidence_id = input.line_validated("Evidence identifier", |value| {
        validate_identifier(value, "evidence id")
    })?;
    let output =
        PathBuf::from(input.line_default("Case directory", &format!("./evidence/{case_id}"))?);

    let catalog = backend_catalog();
    let options: Vec<(String, String)> = catalog
        .iter()
        .map(|info| (info.id.to_owned(), info.summary.to_owned()))
        .collect();
    let index = input.choose("Acquisition method?", &options)?;
    let method = catalog
        .get(index)
        .map_or_else(|| DEFAULT_METHOD.to_owned(), |info| info.id.to_owned());

    let is_physical = method == crate::acquisition::physical::METHOD_ID;
    if is_physical {
        println!("  Physical acquisition needs an ADB shell already running as root, and the");
        println!("  block device must be named explicitly. It is never guessed.");
    }
    let source = if is_physical {
        input.line("  Block device (for example /dev/block/by-name/userdata):")?
    } else {
        input.line_default(
            "Scope on the device",
            crate::acquisition::logical::DEFAULT_SOURCE_PATH,
        )?
    };

    let sha512 = input.confirm("Also compute SHA-512? (slower, second digest)", false)?;
    let examiner = {
        let value = input.line("  Examiner name (blank to omit):")?;
        (!value.is_empty()).then_some(value)
    };
    let notes = {
        let value = input.line("  Note for the manifest (blank to omit):")?;
        (!value.is_empty()).then_some(value)
    };

    let build = |dry_run: bool| AcquireArgs {
        device_id: device_id.clone(),
        case_id: case_id.clone(),
        evidence_id: evidence_id.clone(),
        output: output.clone(),
        method: method.clone(),
        source: Some(source.clone()),
        sha512,
        examiner: examiner.clone(),
        notes: notes.clone(),
        allow_source_read_errors: false,
        no_post_verify: false,
        dry_run,
    };

    println!("\n--- Plan (nothing is transferred yet) ---");
    crate::commands::acquire::run(context, &build(true))?;

    if !input.confirm("\n  Start the acquisition with this plan?", false)? {
        println!("Nothing was transferred.");
        return Ok(());
    }

    // The operator did not type this one, so the reproducible form is printed
    // once: it is the line to keep in a case note or a script.
    println!("\nEquivalent command:");
    println!("  {}\n", rendered_command(global, &build(false)));

    let outcome = crate::commands::acquire::run(context, &build(false));

    // A source-read failure is the common case on a modern device, and the
    // remedy is a flag the operator is unlikely to know about.
    if let Err(Error::Acquisition(message)) = &outcome {
        println!("\nThe acquisition did not complete: {message}");
        println!(
            "On Android 11 and later the ADB shell cannot read parts of shared storage, which \
             makes the device's `tar` exit non-zero."
        );
        println!(
            "Re-run with --allow-source-read-errors to record every such error in the manifest \
             and continue, or narrow the scope, for example to /sdcard/DCIM."
        );
    }
    outcome
}

/// Lists acquirable devices and lets the operator choose one.
fn pick_device(context: &CommandContext, input: &mut Input) -> Result<String> {
    let devices = context.adb.list_devices()?;
    if devices.is_empty() {
        return Err(Error::Device(
            "no device is reported by the ADB server. Connect it by USB, enable USB \
             debugging, and accept the prompt on the device. If it is already connected, \
             the ADB server may have gone stale: run `adb kill-server` and try again."
                .into(),
        ));
    }

    for device in devices.iter().filter(|d| !d.state.is_acquirable()) {
        println!(
            "  (unavailable) {} — {}: {}",
            device.serial,
            device.state.label(),
            device.state.blocking_reason().unwrap_or("not acquirable")
        );
    }

    let selectable: Vec<_> = devices
        .iter()
        .filter(|device| device.state.is_acquirable())
        .collect();
    if selectable.is_empty() {
        return Err(Error::Device(
            "no connected device is in an acquirable state. Accept the USB debugging prompt \
             on the device, then try again."
                .into(),
        ));
    }
    if let [only] = selectable.as_slice() {
        println!("  Using {} ({}).", only.serial, only.display_model());
        return Ok(only.serial.clone());
    }

    let options: Vec<(String, String)> = selectable
        .iter()
        .map(|device| {
            (
                device.serial.clone(),
                format!("{} — {}", device.display_model(), device.state.label()),
            )
        })
        .collect();
    let index = input.choose("Which device?", &options)?;
    selectable
        .get(index)
        .map(|device| device.serial.clone())
        .ok_or_else(|| Error::InvalidData("device selection is out of range".into()))
}

/// Renders the invocation equivalent to a guided acquisition.
fn rendered_command(global: &GlobalArgs, args: &AcquireArgs) -> String {
    let mut words = vec!["nootextract".to_owned()];
    if global.adb_path != crate::adb::DEFAULT_ADB_PROGRAM {
        words.push("--adb-path".to_owned());
        words.push(global.adb_path.clone());
    }
    words.extend([
        "acquire".to_owned(),
        args.device_id.clone(),
        "--case-id".to_owned(),
        args.case_id.clone(),
        "--evidence-id".to_owned(),
        args.evidence_id.clone(),
        "--output".to_owned(),
        args.output.display().to_string(),
    ]);
    if args.method != DEFAULT_METHOD {
        words.push("--method".to_owned());
        words.push(args.method.clone());
    }
    if let Some(source) = &args.source {
        words.push("--source".to_owned());
        words.push(source.clone());
    }
    if args.sha512 {
        words.push("--sha512".to_owned());
    }
    if let Some(examiner) = &args.examiner {
        words.push("--examiner".to_owned());
        words.push(examiner.clone());
    }
    if let Some(notes) = &args.notes {
        words.push("--notes".to_owned());
        words.push(notes.clone());
    }
    words
        .iter()
        .map(|word| quote(word))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Quotes an argument for display, so a printed command can be pasted back.
fn quote(argument: &str) -> String {
    let safe = !argument.is_empty()
        && argument.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/' | ':' | '=' | '\\')
        });
    if safe {
        argument.to_owned()
    } else {
        format!("\"{}\"", argument.replace('"', "\\\""))
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]
    use super::*;
    use crate::cli::Command;

    #[test]
    fn a_line_splits_into_words() {
        assert_eq!(split_line("devices").unwrap(), vec!["devices"]);
        assert_eq!(
            split_line("info 45280DLAQ003QS").unwrap(),
            vec!["info", "45280DLAQ003QS"]
        );
        assert_eq!(split_line("   ").unwrap(), Vec::<String>::new());
        assert_eq!(split_line("").unwrap(), Vec::<String>::new());
    }

    #[test]
    fn quoted_arguments_survive_splitting() {
        // Case directories with spaces are ordinary on Windows.
        assert_eq!(
            split_line(r#"verify "C:\My Cases\CASE-001""#).unwrap(),
            vec!["verify", r"C:\My Cases\CASE-001"]
        );
        assert_eq!(
            split_line("acquire X --notes 'seized at 09:00'").unwrap(),
            vec!["acquire", "X", "--notes", "seized at 09:00"]
        );
        assert_eq!(split_line(r#"hash """#).unwrap(), vec!["hash", ""]);
    }

    #[test]
    fn an_unterminated_quote_is_a_usage_error() {
        let err = split_line(r#"verify "C:\Cases"#).unwrap_err();
        assert_eq!(err.exit_code().as_i32(), 2);
    }

    #[test]
    fn typed_lines_parse_with_the_command_line_definition() {
        // The shell must not drift from the flag interface, so what is typed
        // goes through the same parser.
        let global = GlobalArgs {
            verbose: 0,
            quiet: false,
            json: false,
            no_progress: false,
            adb_path: crate::adb::DEFAULT_ADB_PROGRAM.to_owned(),
        };

        for line in [
            "devices",
            "devices --json",
            "info ABC123",
            "hash image.raw --sha512",
            "verify ./evidence/CASE-001 --ignore-extra",
            "extract archive.tar --max-entries 10",
            "report ./evidence/CASE-001 --verify",
            "doctor",
            "methods",
            "acquire ABC --case-id C --evidence-id E --output ./out",
        ] {
            let words = split_line(line).unwrap();
            let argv = build_argv(&global, &words);
            assert!(
                Cli::try_parse_from(&argv).is_ok(),
                "`{line}` did not parse as a command line"
            );
        }
    }

    #[test]
    fn an_unknown_command_is_rejected_by_the_parser() {
        let global = GlobalArgs {
            verbose: 0,
            quiet: false,
            json: false,
            no_progress: false,
            adb_path: crate::adb::DEFAULT_ADB_PROGRAM.to_owned(),
        };
        let words = split_line("bypass-lockscreen").unwrap();
        assert!(Cli::try_parse_from(build_argv(&global, &words)).is_err());
    }

    #[test]
    fn the_outer_adb_path_carries_into_every_command() {
        let global = GlobalArgs {
            verbose: 0,
            quiet: false,
            json: false,
            no_progress: false,
            adb_path: "/opt/adb".to_owned(),
        };
        let argv = build_argv(&global, &["devices".to_owned()]);
        assert_eq!(
            argv,
            vec!["nootextract", "--adb-path", "/opt/adb", "devices"]
        );

        // A path typed on the line wins, rather than colliding with the outer one.
        let words = split_line("devices --adb-path /other/adb").unwrap();
        let argv = build_argv(&global, &words);
        assert_eq!(argv.iter().filter(|w| *w == "--adb-path").count(), 1);
    }

    #[test]
    fn a_command_given_no_argument_is_asked_for_one() {
        let mut input = Input::scripted("./evidence/CASE-001\n");
        let words = complete_missing_arguments(&mut input, vec!["verify".to_owned()])
            .unwrap()
            .unwrap();
        assert_eq!(words, vec!["verify", "./evidence/CASE-001"]);
    }

    #[test]
    fn declining_to_supply_an_argument_cancels_the_command() {
        let mut input = Input::scripted("\n");
        let outcome = complete_missing_arguments(&mut input, vec!["verify".to_owned()]).unwrap();
        assert!(outcome.is_none(), "an empty answer must cancel, not run");
    }

    #[test]
    fn a_command_given_its_argument_is_left_alone() {
        let mut input = Input::scripted("");
        let words =
            complete_missing_arguments(&mut input, vec!["verify".to_owned(), "./case".to_owned()])
                .unwrap()
                .unwrap();
        assert_eq!(words, vec!["verify", "./case"]);
    }

    #[test]
    fn commands_that_need_nothing_are_never_prompted() {
        for command in ["devices", "methods", "doctor"] {
            let mut input = Input::scripted("");
            let words = complete_missing_arguments(&mut input, vec![command.to_owned()])
                .unwrap()
                .unwrap();
            assert_eq!(words, vec![command]);
        }
    }

    #[test]
    fn confirmation_defaults_apply_on_an_empty_answer() {
        assert!(Input::scripted("\n").confirm("go?", true).unwrap());
        assert!(!Input::scripted("\n").confirm("go?", false).unwrap());
    }

    #[test]
    fn an_unrecognised_confirmation_is_reasked_rather_than_assumed() {
        // Guessing here could start a transfer the operator did not ask for.
        let mut input = Input::scripted("maybe\nwhat\nn\n");
        assert!(!input.confirm("start the acquisition?", true).unwrap());
    }

    #[test]
    fn an_out_of_range_choice_is_rejected_and_reasked() {
        let options = [("a", ""), ("b", ""), ("c", "")]
            .map(|(a, b)| (a.to_owned(), b.to_owned()))
            .to_vec();
        let mut input = Input::scripted("0\n9\nnope\n3\n");
        assert_eq!(input.choose("pick", &options).unwrap(), 2);
    }

    #[test]
    fn invalid_identifiers_are_reasked_using_the_same_validator_as_the_flags() {
        let mut input = Input::scripted("../evil\nCASE 001\nCON\nCASE-001\n");
        let value = input
            .line_validated("Case identifier", |v| validate_identifier(v, "case id"))
            .unwrap();
        assert_eq!(value, "CASE-001");
    }

    #[test]
    fn end_of_input_closes_the_shell_instead_of_looping() {
        let mut input = Input::scripted("");
        assert!(matches!(input.line("nootextract>"), Err(Error::Cancelled)));

        let mut input = Input::scripted("");
        assert!(matches!(input.confirm("go?", true), Err(Error::Cancelled)));
    }

    #[test]
    fn a_guided_acquisition_prints_a_command_that_can_be_pasted_back() {
        let global = GlobalArgs {
            verbose: 0,
            quiet: false,
            json: false,
            no_progress: false,
            adb_path: crate::adb::DEFAULT_ADB_PROGRAM.to_owned(),
        };
        let args = AcquireArgs {
            device_id: "45280DLAQ003QS".to_owned(),
            case_id: "CASE-001".to_owned(),
            evidence_id: "EV-1".to_owned(),
            output: PathBuf::from("./evidence/CASE-001"),
            method: DEFAULT_METHOD.to_owned(),
            source: Some("/sdcard/DCIM".to_owned()),
            sha512: true,
            examiner: Some("A. Examiner".to_owned()),
            notes: None,
            allow_source_read_errors: false,
            no_post_verify: false,
            dry_run: false,
        };

        let rendered = rendered_command(&global, &args);
        assert!(rendered.starts_with("nootextract acquire 45280DLAQ003QS"));
        assert!(rendered.contains("--sha512"));
        assert!(rendered.contains("\"A. Examiner\""), "{rendered}");

        // The printed line must parse back into the same command.
        let words = split_line(rendered.trim_start_matches("nootextract ")).unwrap();
        let reparsed = build_argv(&global, &words);
        let parsed = Cli::try_parse_from(&reparsed).expect("the printed command must parse");
        let Some(Command::Acquire(parsed)) = parsed.command else {
            panic!("expected an acquire command");
        };
        assert_eq!(parsed.device_id, args.device_id);
        assert_eq!(parsed.case_id, args.case_id);
        assert_eq!(parsed.source, args.source);
        assert!(parsed.sha512);
    }

    #[test]
    fn printed_commands_quote_anything_a_shell_would_act_on() {
        for argument in ["a;b", "a|b", "a&&b", "$(id)", "`id`", "a>b", "a b"] {
            let quoted = quote(argument);
            assert!(
                quoted.starts_with('"') && quoted.ends_with('"'),
                "`{argument}` was printed unquoted as `{quoted}`"
            );
        }
        assert_eq!(quote("/sdcard/DCIM"), "/sdcard/DCIM");
        assert_eq!(quote("CASE-001"), "CASE-001");
    }
}
