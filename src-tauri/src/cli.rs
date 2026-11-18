// SPDX-License-Identifier: Apache-2.0
//! Explicit OpenSSH generation from an existing device-local profile.

use std::{
    collections::VecDeque,
    ffi::OsString,
    io::{self, BufRead, IsTerminal as _, Read as _, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

use scoplen_client_core::{
    inventory::{
        OpenSshExportAuthentication, OpenSshExportChoice, OpenSshExportSkipReason,
        OpenSshGeneratedAliasProblem, OpenSshGeneratedError, OpenSshGeneratedPreview,
        OpenSshGeneratedStatus,
    },
    profiles::OpenSshExportProfile,
};
use zeroize::Zeroizing;

use crate::generated_open_ssh::GeneratedOpenSshState;

const IDENTIFIER: &str = "com.scoplen.client";
const HELP: &str = "Scoplen configuration helper

Usage:
  spl config generate --list-profiles [--catalog-passphrase-file <path>]
  spl config generate --profile <local|profile-uuid>
    [--identity-file <login-uuid> <path>]...
    [--catalog-passphrase-file <path>] [--passphrase-file <path>]
    [--dry-run | --yes]
  spl --help
  spl --version

Use an installed device-local profile UUID from --list-profiles.
Passphrase files contain exact nonempty UTF-8; whitespace and final newlines count.
--dry-run prints the complete review without writing generated files.
Publication requires an interactive 'yes', or explicit --yes for noninteractive use.
Only compatible Logins are generated; the review includes every exclusion.
Add the printed Include line to your OpenSSH config manually.
";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Interactive,
    DryRun,
    Yes,
}

#[derive(Debug)]
struct Generate {
    profile: Option<uuid::Uuid>,
    list: bool,
    choices: Vec<OpenSshExportChoice>,
    catalog_passphrase: Option<PathBuf>,
    passphrase: Option<PathBuf>,
    mode: Mode,
}

#[derive(Debug)]
enum Command {
    Help,
    Version,
    Generate(Generate),
}

#[derive(Debug)]
struct Failure {
    code: u8,
    message: String,
}

impl Failure {
    fn usage(message: &str) -> Self {
        Self { code: 2, message: message.into() }
    }
    fn operation(message: impl ToString) -> Self {
        Self { code: 1, message: message.to_string() }
    }
}

impl From<io::Error> for Failure {
    fn from(_: io::Error) -> Self {
        Self::operation("Could not read or write the command's input/output.")
    }
}

/// Run the console helper without starting a desktop application or network runtime.
pub fn run() -> ExitCode {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let terminal = stdin.is_terminal() && stdout.is_terminal();
    let result = parse(std::env::args_os().skip(1).collect())
        .and_then(|command| execute(command, &mut stdin.lock(), &mut stdout.lock(), terminal));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "{}", error.message);
            ExitCode::from(error.code)
        }
    }
}

fn parse(mut args: VecDeque<OsString>) -> Result<Command, Failure> {
    if args.len() == 1 {
        match args.front().and_then(|arg| arg.to_str()) {
            Some("--help" | "-h") => return Ok(Command::Help),
            Some("--version" | "-V") => return Ok(Command::Version),
            _ => {}
        }
    }
    if args.pop_front().as_deref() != Some(std::ffi::OsStr::new("config")) {
        return Err(Failure::usage("Expected 'spl config generate'. Use --help for usage."));
    }
    if args.len() == 1 && args.front().is_some_and(|arg| arg == "--help" || arg == "-h") {
        return Ok(Command::Help);
    }
    if args.pop_front().as_deref() != Some(std::ffi::OsStr::new("generate")) {
        return Err(Failure::usage("Expected 'spl config generate'. Use --help for usage."));
    }
    if args.len() == 1 && args.front().is_some_and(|arg| arg == "--help" || arg == "-h") {
        return Ok(Command::Help);
    }
    let mut profile = None;
    let mut list = false;
    let mut choices = Vec::new();
    let mut catalog_passphrase = None;
    let mut passphrase = None;
    let mut mode = Mode::Interactive;
    while let Some(option) = args.pop_front() {
        match option.to_str() {
            Some("--list-profiles") if !list => list = true,
            Some("--profile") if profile.is_none() => {
                let value = argument(&mut args)?;
                profile = Some(if value == "local" { None } else { Some(identifier(value)?) });
            }
            Some("--catalog-passphrase-file") if catalog_passphrase.is_none() => {
                catalog_passphrase = Some(PathBuf::from(argument(&mut args)?));
            }
            Some("--passphrase-file") if passphrase.is_none() => {
                passphrase = Some(PathBuf::from(argument(&mut args)?));
            }
            Some("--identity-file") => {
                let login = identifier(argument(&mut args)?)?;
                let path = argument(&mut args)?
                    .into_string()
                    .map_err(|_| Failure::usage("Identity-file paths must be valid Unicode."))?;
                if choices
                    .iter()
                    .any(|choice: &OpenSshExportChoice| choice.profile_id == login.to_string())
                {
                    return Err(Failure::usage("Choose at most one identity file for each Login."));
                }
                choices.push(OpenSshExportChoice {
                    profile_id: login.to_string(),
                    identity_file: path,
                });
            }
            Some("--dry-run") if mode == Mode::Interactive => mode = Mode::DryRun,
            Some("--yes") if mode == Mode::Interactive => mode = Mode::Yes,
            _ => {
                return Err(Failure::usage(
                    "Unknown, repeated or conflicting argument. Use --help for usage.",
                ));
            }
        }
    }
    if list
        && (profile.is_some()
            || !choices.is_empty()
            || passphrase.is_some()
            || mode != Mode::Interactive)
    {
        return Err(Failure::usage("--list-profiles accepts only --catalog-passphrase-file."));
    }
    if !list && profile.is_none() {
        return Err(Failure::usage(
            "Choose --profile local or an installed profile UUID from --list-profiles.",
        ));
    }
    if profile == Some(None) && catalog_passphrase.is_some() {
        return Err(Failure::usage(
            "Local generation uses --passphrase-file. The catalog option is for Personal or listing.",
        ));
    }
    Ok(Command::Generate(Generate {
        profile: profile.flatten(),
        list,
        choices,
        catalog_passphrase,
        passphrase,
        mode,
    }))
}

fn argument(args: &mut VecDeque<OsString>) -> Result<OsString, Failure> {
    args.pop_front()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Failure::usage("A required argument is missing. Use --help for usage."))
}

fn identifier(value: OsString) -> Result<uuid::Uuid, Failure> {
    value
        .to_str()
        .and_then(|value| uuid::Uuid::parse_str(value).ok())
        .filter(|id| id.get_version_num() == 7)
        .ok_or_else(|| {
            Failure::usage("Use a valid version-7 UUID from the saved profile or Login.")
        })
}

fn data_directory() -> Result<PathBuf, Failure> {
    if let Some(directory) = std::env::var_os("SPL_DATA_DIR") {
        if directory.is_empty() {
            return Err(Failure::operation(
                "SPL_DATA_DIR must name the existing desktop data directory.",
            ));
        }
        // Keep its exact spelling: the platform keystore also uses this namespace.
        return Ok(PathBuf::from(directory));
    }
    scoplen_client_platform::data_directory::application_data_root()
        .map(|root| root.join(IDENTIFIER))
        .ok_or_else(|| {
            Failure::operation(
                "Could not locate desktop data. Set SPL_DATA_DIR to its existing directory.",
            )
        })
}

fn passphrase(path: Option<&Path>) -> Result<Option<Zeroizing<String>>, Failure> {
    let Some(path) = path else {
        return Ok(None);
    };
    let mut bytes = Zeroizing::new(Vec::new());
    std::fs::File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|_| Failure::operation("Could not read the passphrase file."))?;
    let text = std::str::from_utf8(&bytes)
        .ok()
        .filter(|text| !text.is_empty())
        .ok_or_else(|| Failure::operation("The passphrase file must contain nonempty UTF-8."))?;
    Ok(Some(Zeroizing::new(text.to_owned())))
}

fn execute(
    command: Command,
    input: &mut impl BufRead,
    output: &mut impl Write,
    terminal: bool,
) -> Result<(), Failure> {
    let options = match command {
        Command::Help => {
            output.write_all(HELP.as_bytes())?;
            return Ok(());
        }
        Command::Version => {
            writeln!(output, "spl {}", env!("CARGO_PKG_VERSION"))?;
            return Ok(());
        }
        Command::Generate(options) => options,
    };
    if !options.list && options.mode == Mode::Interactive && !terminal {
        return Err(Failure::usage(
            "Noninteractive publication requires --yes. Use --dry-run to review without publishing.",
        ));
    }
    let directory = data_directory()?;
    let catalog_passphrase = passphrase(options.catalog_passphrase.as_deref())?;
    if options.list {
        let profiles = OpenSshExportProfile::list(
            &directory,
            catalog_passphrase.as_deref().map(String::as_str),
        )
        .map_err(Failure::operation)?;
        writeln!(output, "Device-local profiles:\nlocal\tLocal")?;
        for profile in profiles {
            writeln!(
                output,
                "{}\torigin={:?}\tAccount={}",
                profile.id, profile.origin, profile.account_id
            )?;
        }
        return Ok(());
    }
    let selected_passphrase = passphrase(options.passphrase.as_deref())?;
    let opening = OpenSshExportProfile::open(
        &directory,
        options.profile,
        catalog_passphrase.as_deref().map(String::as_str),
        selected_passphrase.as_deref().map(String::as_str),
    )
    .map_err(Failure::operation)?;
    drop(catalog_passphrase);
    drop(selected_passphrase);
    let store = opening.store();
    let state = GeneratedOpenSshState::default();
    let receipt = uuid::Uuid::now_v7().to_string();
    let preview =
        state.preview(&store, receipt.clone(), options.choices).map_err(Failure::operation)?;
    let status = state.status(&store).map_err(Failure::operation)?;
    report(output, &status, &preview)?;
    output.flush()?;
    if options.mode == Mode::DryRun {
        writeln!(output, "Review only. No generated files were written.")?;
        return Ok(());
    }
    if options.mode == Mode::Interactive {
        write!(output, "Publish this compatible set, including the listed exclusions? Type yes: ")?;
        output.flush()?;
        if !confirmed(input)? {
            return Err(Failure {
                code: 3,
                message: "Publication declined. Generated files were not changed.".into(),
            });
        }
    }
    opening.recheck().map_err(Failure::operation)?;
    let published = state.generate(&store, &receipt, &preview.id).map_err(generation_error)?;
    writeln!(
        output,
        "Published {} compatible Logins in {} files.",
        published.hosts, published.files
    )?;
    Ok(())
}

fn generation_error(error: OpenSshGeneratedError) -> Failure {
    let message = match &error {
        OpenSshGeneratedError::WriteFailed { directory: Some(directory) } => {
            format!("{error}. Partial generated files remain at {directory:?}.")
        }
        _ => error.to_string(),
    };
    Failure::operation(message)
}

fn confirmed(input: &mut impl BufRead) -> Result<bool, Failure> {
    let mut answer = String::new();
    if input.read_line(&mut answer)? == 0 {
        return Ok(false);
    }
    let answer = answer.strip_suffix('\n').unwrap_or(&answer);
    Ok(answer.strip_suffix('\r').unwrap_or(answer) == "yes")
}

fn report(
    output: &mut impl Write,
    status: &OpenSshGeneratedStatus,
    preview: &OpenSshGeneratedPreview,
) -> Result<(), Failure> {
    writeln!(
        output,
        "Destination: {:?}\nGenerated Include: {:?}",
        preview.destination, status.include_path
    )?;
    writeln!(output, "{}", status.include_line)?;
    writeln!(output, "Compatible Logins ({}):", preview.report.entries.len())?;
    for entry in &preview.report.entries {
        writeln!(
            output,
            "  Login={} Host={} name={:?} login={:?} alias={:?}",
            entry.profile_id, entry.host_id, entry.host_name, entry.login_name, entry.alias
        )?;
        writeln!(
            output,
            "    user={:?} address={:?} port={} route={:?}",
            entry.username, entry.address, entry.port, entry.route
        )?;
        let requirement = match entry.authentication {
            OpenSshExportAuthentication::Password => {
                "OpenSSH prompts for the password; no saved password is exported."
            }
            OpenSshExportAuthentication::Agent => {
                "The exact public identity must be loaded in the external SSH agent."
            }
            OpenSshExportAuthentication::IdentityFile => {
                "OpenSSH uses the matching external private-key file and prompts for its passphrase when needed."
            }
        };
        writeln!(output, "    {requirement}")?;
        if let Some(path) = &entry.identity_file {
            writeln!(output, "    identity_file={path:?}")?;
        }
    }
    writeln!(output, "Excluded rows ({}):", preview.report.skipped.len())?;
    for row in &preview.report.skipped {
        let reason = match row.reason {
            OpenSshExportSkipReason::MissingLogin => "No saved Login.",
            OpenSshExportSkipReason::UnavailableCredential => {
                "The assigned Credential is unavailable."
            }
            OpenSshExportSkipReason::IdentityFileRequired => {
                "Choose a matching external private-key file with --identity-file."
            }
            OpenSshExportSkipReason::IdentityFileMismatch => {
                "The selected file does not match the saved private key."
            }
            OpenSshExportSkipReason::UnsupportedCredential => {
                "The Credential cannot be represented without exporting a secret."
            }
            OpenSshExportSkipReason::UnsupportedRoute => {
                "The route cannot be represented by this generator."
            }
            OpenSshExportSkipReason::RouteDependency => {
                "A required Direct Jump Login cannot be exported."
            }
            OpenSshExportSkipReason::UnsupportedOptions => {
                "Saved options or trust cannot be represented faithfully."
            }
            OpenSshExportSkipReason::InvalidValue => {
                "The endpoint or username cannot be represented safely."
            }
        };
        writeln!(
            output,
            "  Host={} Login={:?} name={:?} login={:?}: {reason}",
            row.host_id, row.profile_id, row.host_name, row.login_name
        )?;
    }
    writeln!(output, "Friendly alias outcomes ({}):", preview.aliases.len())?;
    for alias in &preview.aliases {
        let reason = match alias.problem {
            None => "Included.",
            Some(OpenSshGeneratedAliasProblem::InvalidName) => {
                "The complete Host name is outside the supported ASCII grammar."
            }
            Some(OpenSshGeneratedAliasProblem::DuplicateName) => {
                "Another Host has the same case-insensitive name."
            }
            Some(OpenSshGeneratedAliasProblem::ReservedName) => {
                "The Host name is reserved for UUID aliases."
            }
            Some(OpenSshGeneratedAliasProblem::MissingLogin) => "No live Login.",
            Some(OpenSshGeneratedAliasProblem::IncompatibleLogin) => {
                "The selected default or first Login is incompatible."
            }
        };
        writeln!(
            output,
            "  Host={} Login={:?} name={:?} alias={:?}: {reason}",
            alias.host_id, alias.profile_id, alias.host_name, alias.alias
        )?;
    }
    writeln!(
        output,
        "Ordinary trusted host-key records: {}. Missing trust requires OpenSSH first-use review.",
        preview.report.trust_records
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_requires_an_explicit_selection_and_single_mode() {
        for args in [
            vec![],
            vec!["config", "generate"],
            vec!["config", "generate", "--profile", "local", "--yes", "--dry-run"],
            vec!["config", "generate", "--list-profiles", "--yes"],
            vec!["config", "generate", "--profile", "local", "--profile", "local"],
            vec![
                "config",
                "generate",
                "--profile",
                "local",
                "--catalog-passphrase-file",
                "catalog",
            ],
        ] {
            assert_eq!(
                parse(args.into_iter().map(OsString::from).collect()).err().unwrap().code,
                2
            );
        }
    }

    #[test]
    fn confirmation_is_explicit_and_eof_declines() {
        for (answer, expected) in [
            ("yes\n", true),
            ("yes\r\n", true),
            ("", false),
            ("y\n", false),
            (" yes\n", false),
            ("YES\n", false),
        ] {
            assert_eq!(confirmed(&mut io::Cursor::new(answer)).unwrap(), expected);
        }
    }

    #[test]
    fn identity_choice_keeps_the_literal_external_path() {
        let id = uuid::Uuid::now_v7().to_string();
        let path = "folder with spaces/key";
        let command = parse(
            ["config", "generate", "--profile", "local", "--identity-file", &id, path, "--dry-run"]
                .into_iter()
                .map(OsString::from)
                .collect(),
        )
        .unwrap();
        let Command::Generate(options) = command else {
            panic!("generation");
        };
        assert_eq!(
            options.choices,
            vec![OpenSshExportChoice { profile_id: id, identity_file: path.into() }]
        );
        assert_eq!(options.mode, Mode::DryRun);
    }

    #[test]
    fn application_identifier_matches_the_desktop_configuration() {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        assert_eq!(config["identifier"], IDENTIFIER);
        assert!(config["app"]["appDirectoriesOverride"].is_null());
    }

    #[test]
    fn retained_partial_directory_is_reported_with_control_characters_escaped() {
        let failure = generation_error(OpenSshGeneratedError::WriteFailed {
            directory: Some("partial\n\u{1b}[31m".into()),
        });
        assert_eq!(failure.code, 1);
        assert!(failure.message.contains("partial\\n\\u{1b}[31m"));
        assert!(!failure.message.contains('\u{1b}'));
    }
}
