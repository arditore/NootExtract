//! Guided interactive session.
//!
//! Running `nootextract` with no arguments starts this. It is a front end and
//! nothing more: every choice is funnelled into the same argument structures and
//! the same command functions the flags produce, through the same validators. A
//! guided run therefore cannot reach a state the command line cannot, and cannot
//! bypass a safety check that only the flag path enforces.
//!
//! # Every operation prints its command line
//!
//! Before anything runs, the session prints the equivalent invocation. That is
//! not a convenience: an operation performed through a menu that leaves no
//! reproducible form behind is not auditable, and an examiner asked how evidence
//! was produced needs an answer more precise than "I clicked acquire". It also
//! means the session teaches the flag interface rather than replacing it.
//!
//! # Terminal only
//!
//! The session refuses to start when standard input is not a terminal. Reaching
//! an interactive prompt from a pipe or a CI job would either hang or consume
//! unrelated input; a bare invocation there is a usage error instead.
//!
//! # Destructive steps are confirmed
//!
//! An acquisition is always previewed with a dry run first, and the transfer
//! only starts once the operator has seen the plan and agreed to it.

use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;

use crate::acquisition::{DEFAULT_METHOD, backend_catalog};
use crate::cli::{
    AcquireArgs, DoctorArgs, ExtractArgs, GlobalArgs, InfoArgs, ReportArgs, VerifyArgs,
};
use crate::commands::{CommandContext, derive, device, doctor, evidence, report};
use crate::error::{Error, Result};
use crate::util::paths::validate_identifier;

/// Entry point for the guided session.
pub fn run(context: &CommandContext, global: &GlobalArgs) -> Result<()> {
    if !std::io::stdin().is_terminal() {
        return Err(Error::Usage(
            "the guided session needs a terminal, and standard input is not one. Use a \
             subcommand instead; `nootextract --help` lists them."
                .into(),
        ));
    }
    if global.json {
        return Err(Error::Usage(
            "--json describes machine-readable output and has no meaning for the guided \
             session. Use a subcommand with --json instead."
                .into(),
        ));
    }

    let mut session = Session {
        context,
        global,
        input: Input::from_stdin(),
    };
    Session::banner();

    loop {
        match session.main_menu() {
            Ok(true) => {}
            // Leaving by choice and reaching end of input end the same way.
            Ok(false) | Err(Error::Cancelled) => {
                println!("\nnoot noot.");
                return Ok(());
            }
            // An operation failing is not a reason to end the session; the
            // operator may want to fix the input and retry.
            Err(e) => {
                eprintln!("\nerror: {e}");
                eprintln!("exit code would be {}", e.exit_code().as_i32());
                if !session.input.confirm("Continue the session?", true)? {
                    return Ok(());
                }
            }
        }
    }
}

/// Reads operator input.
///
/// The reader is injected rather than taken from `stdin` directly, so the prompt
/// flows can be driven by a scripted transcript in tests. An interactive layer
/// that can only be exercised by hand is one that stops being exercised.
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

    /// Reads one line. End of input ends the session rather than looping.
    fn line(&mut self, question: &str) -> Result<String> {
        print!("{question} ");
        let _ = std::io::stdout().flush();
        let mut buffer = String::new();
        let read = self
            .reader
            .read_line(&mut buffer)
            .map_err(|e| Error::io("read", "<stdin>", e))?;
        if read == 0 {
            return Err(Error::Cancelled);
        }
        Ok(buffer.trim().to_owned())
    }

    fn line_default(&mut self, question: &str, default: &str) -> Result<String> {
        let answer = self.line(&format!("{question} [{default}]:"))?;
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
        default: Option<&str>,
        validate: impl Fn(&str) -> Result<String>,
    ) -> Result<String> {
        loop {
            let answer = match default {
                Some(default) => self.line_default(question, default)?,
                None => self.line(&format!("{question}:"))?,
            };
            match validate(&answer) {
                Ok(value) => return Ok(value),
                Err(e) => println!("  {e}"),
            }
        }
    }

    fn confirm(&mut self, question: &str, default: bool) -> Result<bool> {
        let hint = if default { "Y/n" } else { "y/N" };
        loop {
            let answer = self.line(&format!("{question} [{hint}]"))?.to_lowercase();
            match answer.as_str() {
                "" => return Ok(default),
                "y" | "yes" | "o" | "oui" => return Ok(true),
                "n" | "no" | "non" => return Ok(false),
                _ => println!("  answer y or n"),
            }
        }
    }

    /// Presents a numbered menu and returns the chosen index.
    fn choose(&mut self, title: &str, options: &[(String, String)]) -> Result<usize> {
        println!("\n{title}");
        for (index, (label, detail)) in options.iter().enumerate() {
            if detail.is_empty() {
                println!("  {:>2}  {label}", index + 1);
            } else {
                println!("  {:>2}  {label:<28} {detail}", index + 1);
            }
        }
        loop {
            let answer = self.line("\nChoice:")?;
            if let Ok(index) = answer.parse::<usize>()
                && index >= 1
                && index <= options.len()
            {
                return Ok(index - 1);
            }
            println!("  enter a number between 1 and {}", options.len());
        }
    }
}

struct Session<'a> {
    context: &'a CommandContext,
    global: &'a GlobalArgs,
    input: Input,
}

impl Session<'_> {
    fn banner() {
        println!();
        println!("   .--.");
        println!("  |o_o |   {} {}", crate::NAME, crate::VERSION);
        println!("  |:_/ |   guided session — noot noot.");
        println!();
        println!("Every operation prints the command line that performs it, so anything done");
        println!("here can be reproduced, scripted and audited.");
    }

    /// Runs one menu cycle. Returns false when the operator wants to leave.
    fn main_menu(&mut self) -> Result<bool> {
        let options = [
            ("Check the environment", "adb, devices, free space"),
            ("List devices", "who is connected, and whether it is usable"),
            ("Device details", "identification metadata for one device"),
            ("Acquire evidence", "guided, with a dry run first"),
            ("Verify a case", "recompute every digest"),
            (
                "Extract an archive",
                "unpack a logical acquisition, manifested",
            ),
            ("Case report", "Markdown summary for a case file"),
            (
                "Acquisition methods",
                "what this build can do, and what it needs",
            ),
            ("Quit", ""),
        ]
        .map(|(label, detail)| (label.to_owned(), detail.to_owned()));

        match self.input.choose("What would you like to do?", &options)? {
            0 => self.doctor(),
            1 => self.devices(),
            2 => self.info(),
            3 => self.acquire(),
            4 => self.verify(),
            5 => self.extract(),
            6 => self.report(),
            7 => self.methods(),
            _ => return Ok(false),
        }?;
        Ok(true)
    }

    /// Prints the invocation that performs what is about to run.
    fn show_command(args: &[String]) {
        let rendered: Vec<String> = args.iter().map(|arg| quote(arg)).collect();
        println!("\n  $ nootextract {}", rendered.join(" "));
        println!();
    }

    /// Global flags that must appear in a reproduced command line.
    fn global_args(&self) -> Vec<String> {
        let mut args = Vec::new();
        if self.global.adb_path != crate::adb::DEFAULT_ADB_PROGRAM {
            args.push("--adb-path".to_owned());
            args.push(self.global.adb_path.clone());
        }
        args
    }

    fn doctor(&mut self) -> Result<()> {
        let output = self
            .input
            .line("Destination directory to check (blank to skip):")?;
        let output = (!output.is_empty()).then(|| PathBuf::from(&output));

        let mut args = self.global_args();
        args.push("doctor".to_owned());
        if let Some(path) = &output {
            args.push("--output".to_owned());
            args.push(path.display().to_string());
        }
        Session::show_command(&args);

        doctor::run(
            self.context,
            &DoctorArgs {
                output,
                ewfacquire_path: crate::imaging::ewf::DEFAULT_ACQUIRE_PROGRAM.to_owned(),
            },
        )
    }

    fn devices(&mut self) -> Result<()> {
        let mut args = self.global_args();
        args.push("devices".to_owned());
        Session::show_command(&args);
        device::devices(self.context, &crate::cli::DevicesArgs { no_details: false })
    }

    fn info(&mut self) -> Result<()> {
        let device_id = self.pick_device(false)?;
        let mut args = self.global_args();
        args.push("info".to_owned());
        args.push(device_id.clone());
        Session::show_command(&args);
        device::info(self.context, &InfoArgs { device_id })
    }

    fn methods(&mut self) -> Result<()> {
        let mut args = self.global_args();
        args.push("methods".to_owned());
        Session::show_command(&args);
        device::methods(self.context)
    }

    /// Lists devices and lets the operator choose one.
    ///
    /// When `acquirable_only` is set, devices that cannot be acquired are shown
    /// with the reason but cannot be selected — the same rule the flag interface
    /// enforces, surfaced before the operator invests in filling a form.
    fn pick_device(&mut self, acquirable_only: bool) -> Result<String> {
        let devices = self.context.adb.list_devices()?;
        if devices.is_empty() {
            return Err(Error::Device(
                "no device is connected. Connect it by USB, enable USB debugging, and \
                 accept the prompt shown on the device."
                    .into(),
            ));
        }

        let selectable: Vec<_> = devices
            .iter()
            .filter(|device| !acquirable_only || device.state.is_acquirable())
            .collect();

        for device in &devices {
            if acquirable_only && !device.state.is_acquirable() {
                println!(
                    "  (unavailable) {} — {}: {}",
                    device.serial,
                    device.state.label(),
                    device.state.blocking_reason().unwrap_or("not acquirable")
                );
            }
        }

        if selectable.is_empty() {
            return Err(Error::Device(
                "no connected device is in an acquirable state. Accept the USB debugging \
                 prompt on the device, then try again."
                    .into(),
            ));
        }
        // A single candidate needs no menu.
        if let [only] = selectable.as_slice() {
            println!("\nUsing device {} ({}).", only.serial, only.display_model());
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
        let index = self.input.choose("Which device?", &options)?;
        selectable
            .get(index)
            .map(|device| device.serial.clone())
            .ok_or_else(|| Error::InvalidData("device selection is out of range".into()))
    }

    fn acquire(&mut self) -> Result<()> {
        let device_id = self.pick_device(true)?;

        let case_id = self
            .input
            .line_validated("Case identifier", None, |value| {
                validate_identifier(value, "case id")
            })?;
        let evidence_id = self
            .input
            .line_validated("Evidence identifier", None, |value| {
                validate_identifier(value, "evidence id")
            })?;

        let default_output = format!("./evidence/{case_id}");
        let output = PathBuf::from(self.input.line_default("Case directory", &default_output)?);

        let catalog = backend_catalog();
        let method_options: Vec<(String, String)> = catalog
            .iter()
            .map(|info| (info.id.to_owned(), info.summary.to_owned()))
            .collect();
        let method = if method_options.len() == 1 {
            DEFAULT_METHOD.to_owned()
        } else {
            let index = self.input.choose("Acquisition method?", &method_options)?;
            catalog
                .get(index)
                .map_or_else(|| DEFAULT_METHOD.to_owned(), |info| info.id.to_owned())
        };

        let is_physical = method == crate::acquisition::physical::METHOD_ID;
        if is_physical {
            println!(
                "\n  Physical acquisition needs an ADB shell that is already running as root,"
            );
            println!("  and the block device must be named explicitly. It is never guessed.");
        }
        let source_prompt = if is_physical {
            "Block device to image (for example /dev/block/by-name/userdata)"
        } else {
            "Scope on the device"
        };
        let source = if is_physical {
            Some(self.input.line(&format!("{source_prompt}:"))?)
        } else {
            let value = self.input.line_default(
                source_prompt,
                crate::acquisition::logical::DEFAULT_SOURCE_PATH,
            )?;
            Some(value)
        };

        let sha512 = self.input.confirm(
            "Also compute SHA-512? (slower, second independent digest)",
            false,
        )?;
        let examiner = {
            let value = self.input.line("Examiner name (blank to omit):")?;
            (!value.is_empty()).then_some(value)
        };
        let notes = {
            let value = self.input.line("Note for the manifest (blank to omit):")?;
            (!value.is_empty()).then_some(value)
        };

        let build = |dry_run: bool| AcquireArgs {
            device_id: device_id.clone(),
            case_id: case_id.clone(),
            evidence_id: evidence_id.clone(),
            output: output.clone(),
            method: method.clone(),
            source: source.clone(),
            sha512,
            examiner: examiner.clone(),
            notes: notes.clone(),
            allow_source_read_errors: false,
            no_post_verify: false,
            dry_run,
        };

        let mut args = self.global_args();
        args.extend([
            "acquire".to_owned(),
            device_id.clone(),
            "--case-id".to_owned(),
            case_id.clone(),
            "--evidence-id".to_owned(),
            evidence_id.clone(),
            "--output".to_owned(),
            output.display().to_string(),
        ]);
        if method != DEFAULT_METHOD {
            args.push("--method".to_owned());
            args.push(method.clone());
        }
        if let Some(source) = &source {
            args.push("--source".to_owned());
            args.push(source.clone());
        }
        if sha512 {
            args.push("--sha512".to_owned());
        }
        if let Some(examiner) = &examiner {
            args.push("--examiner".to_owned());
            args.push(examiner.clone());
        }
        if let Some(notes) = &notes {
            args.push("--notes".to_owned());
            args.push(notes.clone());
        }

        // The plan is always shown before any byte is transferred.
        println!("\n--- Plan (nothing is transferred yet) ---");
        let mut dry_args = args.clone();
        dry_args.push("--dry-run".to_owned());
        Session::show_command(&dry_args);
        crate::commands::acquire::run(self.context, &build(true))?;

        if !self
            .input
            .confirm("\nStart the acquisition with this plan?", false)?
        {
            println!("Nothing was transferred.");
            return Ok(());
        }

        println!("\n--- Acquiring ---");
        Session::show_command(&args);
        let outcome = crate::commands::acquire::run(self.context, &build(false));

        // A source-read failure is the common case on a modern device, and the
        // remedy is a flag the operator is unlikely to know about.
        if let Err(Error::Acquisition(message)) = &outcome {
            println!("\nThe acquisition did not complete: {message}");
            println!(
                "On Android 11 and later, parts of shared storage are unreadable by the ADB \
                 shell, which makes the device's `tar` exit non-zero."
            );
            println!(
                "Re-running with --allow-source-read-errors records every such error in the \
                 manifest and continues; the status becomes `completed-with-errors`."
            );
            println!("Narrowing the scope, for example to /sdcard/DCIM, is the other option.");
        }
        outcome
    }

    fn verify(&mut self) -> Result<()> {
        let path = PathBuf::from(self.input.line("Case directory:")?);
        let mut args = self.global_args();
        args.push("verify".to_owned());
        args.push(path.display().to_string());
        Session::show_command(&args);
        evidence::verify(
            self.context,
            &VerifyArgs {
                path,
                ignore_extra: false,
                no_sha512: false,
            },
        )
    }

    fn extract(&mut self) -> Result<()> {
        let path = PathBuf::from(self.input.line("Archive to extract:")?);
        let mut args = self.global_args();
        args.push("extract".to_owned());
        args.push(path.display().to_string());
        Session::show_command(&args);
        derive::extract(
            self.context,
            &ExtractArgs {
                path,
                output: None,
                name: None,
                case_id: None,
                evidence_id: None,
                sha512: false,
                max_entries: None,
                max_total_size: None,
            },
        )
    }

    fn report(&mut self) -> Result<()> {
        let path = PathBuf::from(self.input.line("Case directory:")?);
        let verify = self
            .input
            .confirm("Recompute every digest for the report?", false)?;
        let destination = self.input.line("Write to file (blank for screen):")?;
        let output = (!destination.is_empty()).then(|| PathBuf::from(&destination));

        let mut args = self.global_args();
        args.push("report".to_owned());
        args.push(path.display().to_string());
        if verify {
            args.push("--verify".to_owned());
        }
        if let Some(path) = &output {
            args.push("--output".to_owned());
            args.push(path.display().to_string());
        }
        Session::show_command(&args);

        report::run(
            self.context,
            &ReportArgs {
                path,
                output,
                verify,
            },
        )
    }
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

    fn options(labels: &[&str]) -> Vec<(String, String)> {
        labels
            .iter()
            .map(|label| ((*label).to_owned(), String::new()))
            .collect()
    }

    #[test]
    fn a_menu_choice_maps_to_its_index() {
        let mut input = Input::scripted(
            "2
",
        );
        let chosen = input.choose("pick", &options(&["a", "b", "c"])).unwrap();
        assert_eq!(
            chosen, 1,
            "menus are 1-based for the operator, 0-based here"
        );
    }

    #[test]
    fn an_out_of_range_choice_is_rejected_and_reasked() {
        // A mistyped menu number must never fall through to an operation.
        let mut input = Input::scripted(
            "0
9
nope
3
",
        );
        assert_eq!(input.choose("pick", &options(&["a", "b", "c"])).unwrap(), 2);
    }

    #[test]
    fn confirmation_defaults_apply_on_an_empty_answer() {
        assert!(
            Input::scripted(
                "
"
            )
            .confirm("go?", true)
            .unwrap()
        );
        assert!(
            !Input::scripted(
                "
"
            )
            .confirm("go?", false)
            .unwrap()
        );
    }

    #[test]
    fn confirmation_accepts_the_usual_answers() {
        for answer in ["y", "Y", "yes", "o", "oui"] {
            assert!(
                Input::scripted(&format!(
                    "{answer}
"
                ))
                .confirm("go?", false)
                .unwrap(),
                "`{answer}` should mean yes"
            );
        }
        for answer in ["n", "N", "no", "non"] {
            assert!(
                !Input::scripted(&format!(
                    "{answer}
"
                ))
                .confirm("go?", true)
                .unwrap(),
                "`{answer}` should mean no"
            );
        }
    }

    #[test]
    fn an_unrecognised_confirmation_is_reasked_rather_than_assumed() {
        // Guessing here could start a transfer the operator did not ask for.
        let mut input = Input::scripted(
            "maybe
what
n
",
        );
        assert!(!input.confirm("start the acquisition?", true).unwrap());
    }

    #[test]
    fn a_blank_answer_takes_the_offered_default() {
        let mut input = Input::scripted(
            "
",
        );
        assert_eq!(input.line_default("Scope", "/sdcard").unwrap(), "/sdcard");
    }

    #[test]
    fn invalid_identifiers_are_reasked_using_the_same_validator_as_the_flags() {
        // The guided path must not accept an identifier the flag path rejects.
        let mut input = Input::scripted(
            "../evil
CASE 001
CON
CASE-001
",
        );
        let value = input
            .line_validated("Case identifier", None, |v| {
                validate_identifier(v, "case id")
            })
            .unwrap();
        assert_eq!(value, "CASE-001");
    }

    #[test]
    fn end_of_input_ends_the_session_instead_of_looping() {
        // Without this, a closed stdin spins forever on a re-ask loop.
        let mut input = Input::scripted("");
        assert!(matches!(input.line("anything?"), Err(Error::Cancelled)));

        let mut input = Input::scripted("");
        assert!(matches!(
            input.choose("pick", &options(&["a"])),
            Err(Error::Cancelled)
        ));

        let mut input = Input::scripted("");
        assert!(matches!(input.confirm("go?", true), Err(Error::Cancelled)));
    }

    #[test]
    fn answers_are_trimmed() {
        let mut input = Input::scripted(
            "  CASE-001  
",
        );
        assert_eq!(input.line("id?").unwrap(), "CASE-001");
    }

    #[test]
    fn plain_arguments_are_shown_unquoted() {
        assert_eq!(quote("acquire"), "acquire");
        assert_eq!(quote("CASE-001"), "CASE-001");
        assert_eq!(quote("/sdcard/DCIM"), "/sdcard/DCIM");
        assert_eq!(quote("./evidence/CASE-001"), "./evidence/CASE-001");
        assert_eq!(quote("C:\\Cases\\A"), "C:\\Cases\\A");
    }

    #[test]
    fn arguments_needing_quoting_are_quoted() {
        assert_eq!(quote("A. Examiner"), "\"A. Examiner\"");
        assert_eq!(quote(""), "\"\"");
        assert_eq!(quote("note with spaces"), "\"note with spaces\"");
        assert_eq!(quote("say \"hi\""), "\"say \\\"hi\\\"\"");
    }

    #[test]
    fn a_printed_command_never_loses_a_shell_metacharacter() {
        // The printed form is for a human to paste back, so anything a shell
        // would act on has to end up inside quotes.
        for argument in ["a;b", "a|b", "a&&b", "$(id)", "`id`", "a>b", "a b"] {
            let quoted = quote(argument);
            assert!(
                quoted.starts_with('"') && quoted.ends_with('"'),
                "`{argument}` was printed unquoted as `{quoted}`"
            );
        }
    }
}
