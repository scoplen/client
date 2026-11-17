// SPDX-License-Identifier: Apache-2.0

use super::*;

pub(crate) fn descriptor(path: impl Into<String>) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("type".into(), "command".into()),
        ("path".into(), path.into()),
        ("field".into(), "password".into()),
    ])
}

#[test]
fn command_arguments_are_literal_and_keep_portable_quotes() {
    let command = CommandPassword::parse(&descriptor(
        r#""helper path" '%h' %p %r %% $HOME | > '' a\ b C:\tools\helper "a\"b""#,
    ))
    .unwrap();
    assert_eq!(command.program, "helper path");
    assert_eq!(
        command.arguments,
        ["%h", "%p", "%r", "%%", "$HOME", "|", ">", "", "a b", r"C:\tools\helper", "a\"b"]
    );
    assert!(!format!("{command:?}").contains("helper path"));
}

#[test]
fn invalid_descriptors_and_command_bounds_fail_without_echoing_input() {
    let mut unknown = descriptor("helper private-argument");
    unknown.insert("secret".into(), "private-value".into());
    let mut wrong_type = descriptor("helper");
    wrong_type.insert("type".into(), "vault".into());
    let mut wrong_field = descriptor("helper");
    wrong_field.insert("field".into(), "private-key".into());
    let mut missing = descriptor("helper");
    missing.remove("path");
    for provider in [unknown, wrong_type, wrong_field, missing, BTreeMap::new()] {
        let error = CommandPassword::parse(&provider).unwrap_err();
        assert!(matches!(error, SshConnectionError::InvalidCommandPassword));
        assert!(!error.to_string().contains("private-"));
    }
    for path in [
        "".into(),
        "''".into(),
        "helper '".into(),
        "helper\nargument".into(),
        "helper\0argument".into(),
        "x".repeat(4097),
        format!("helper {}", "x".repeat(4097)),
        format!("helper {}", "x ".repeat(65)),
        "x".repeat(scoplen_model::MAX_TEXT_BYTES + 1),
    ] {
        assert!(CommandPassword::parse(&descriptor(path)).is_err());
    }
    assert!(CommandPassword::parse(&descriptor(format!("helper {}", "x ".repeat(64)))).is_ok());
    #[cfg(windows)]
    for path in ["helper.cmd", "helper.BAT", "helper.cmd. "] {
        assert!(CommandPassword::parse(&descriptor(format!("\"{path}\""))).is_err());
    }
}

#[test]
fn output_removes_one_line_ending_and_preserves_every_other_byte() {
    for (output, password) in [
        (b" password \t".as_slice(), b" password \t".as_slice()),
        (b" password \n", b" password "),
        (b" password \r\n", b" password "),
        (b"password\n\n", b"password\n"),
        (b"password\r", b"password\r"),
        (b"\0\xff\r\n", b"\0\xff"),
    ] {
        let secret = decode_output(Zeroizing::new(output.to_vec())).unwrap();
        assert_eq!(secret.as_bytes(), password);
        assert_eq!(format!("{secret:?}"), "[REDACTED]");
    }
    for output in [vec![], b"\n".to_vec(), b"\r\n".to_vec()] {
        assert!(matches!(
            decode_output(Zeroizing::new(output)),
            Err(SshConnectionError::CommandPasswordEmpty)
        ));
    }
    for ending in [b"".as_slice(), b"\n", b"\r\n"] {
        let mut output = vec![b'x'; MAX_PASSWORD];
        output.extend(ending);
        assert_eq!(decode_output(Zeroizing::new(output)).unwrap().len(), MAX_PASSWORD);
    }
    assert!(matches!(
        decode_output(Zeroizing::new(vec![b'x'; MAX_PASSWORD + 1])),
        Err(SshConnectionError::CommandPasswordTooLarge)
    ));
}

fn helper(windows: &str, unix: &str) -> CommandPassword {
    if cfg!(windows) {
        CommandPassword {
            program: "powershell.exe".into(),
            arguments: vec![
                "-NoProfile".into(),
                "-NonInteractive".into(),
                "-Command".into(),
                windows.into(),
            ],
        }
    } else {
        CommandPassword { program: "/bin/sh".into(), arguments: vec!["-c".into(), unix.into()] }
    }
}

#[tokio::test]
async fn runner_requires_complete_successful_bounded_output_and_redacts_failures() {
    let secret = helper(
        "[Console]::Out.Write(' pass '); [Console]::Error.Write('discarded')",
        "printf ' pass '; printf discarded >&2",
    )
    .password()
    .await
    .unwrap();
    assert_eq!(secret.as_bytes(), b" pass ");
    for (command, expected) in [
        (
            helper(
                "[Console]::Out.Write('plausible-password'); exit 7",
                "printf plausible-password; exit 7",
            ),
            "failed",
        ),
        (helper("exit 0", "exit 0"), "empty"),
        (helper("[Console]::Out.Write(('x' * 17000))", "head -c 17000 /dev/zero"), "too much"),
        (
            CommandPassword {
                program: "scoplen-fixture-nonexistent-password-helper".into(),
                arguments: vec![],
            },
            "could not start",
        ),
    ] {
        let error = command.password().await.unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
        assert!(!format!("{error:?}").contains("plausible-password"));
        assert!(!error.to_string().contains("nonexistent-password-helper"));
    }
}

#[cfg(windows)]
#[tokio::test]
async fn windows_helper_has_no_console_window() {
    let command = helper(
        r#"Add-Type -MemberDefinition '[DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();' -Name ConsoleProbe -Namespace Scoplen; if ([Scoplen.ConsoleProbe]::GetConsoleWindow() -ne [IntPtr]::Zero) { exit 7 }; [Console]::Out.Write('hidden')"#,
        "unused",
    );
    assert_eq!(command.password().await.unwrap().as_bytes(), b"hidden");
}
