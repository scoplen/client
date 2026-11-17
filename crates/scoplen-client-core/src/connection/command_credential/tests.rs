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
    let command = CommandCredential::parse(&descriptor(
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

#[tokio::test]
async fn private_key_field_returns_transient_private_key_material() {
    let mut command = helper("[Console]::Out.Write('key-material')", "printf key-material");
    command.field = CommandField::PrivateKey;
    let CredentialMaterial::PrivateKey(secret) = command.credential().await.unwrap() else {
        panic!("private_key field returned another credential kind")
    };
    assert_eq!(secret.as_bytes(), b"key-material");
    let mut provider = descriptor("helper");
    provider.insert("field".into(), "private_key".into());
    assert!(CommandCredential::parse(&provider).is_ok());
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
        let error = CommandCredential::parse(&provider).unwrap_err();
        assert!(matches!(error, SshConnectionError::InvalidCommandCredential));
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
        assert!(CommandCredential::parse(&descriptor(path)).is_err());
    }
    assert!(CommandCredential::parse(&descriptor(format!("helper {}", "x ".repeat(64)))).is_ok());
    #[cfg(windows)]
    for path in ["helper.cmd", "helper.BAT", "helper.cmd. "] {
        assert!(CommandCredential::parse(&descriptor(format!("\"{path}\""))).is_err());
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
            Err(SshConnectionError::CommandCredentialEmpty)
        ));
    }
    for ending in [b"".as_slice(), b"\n", b"\r\n"] {
        let mut output = vec![b'x'; MAX_MATERIAL];
        output.extend(ending);
        assert_eq!(decode_output(Zeroizing::new(output)).unwrap().len(), MAX_MATERIAL);
    }
    assert!(matches!(
        decode_output(Zeroizing::new(vec![b'x'; MAX_MATERIAL + 1])),
        Err(SshConnectionError::CommandCredentialTooLarge)
    ));
}

fn helper(windows: &str, unix: &str) -> CommandCredential {
    if cfg!(windows) {
        CommandCredential {
            program: "powershell.exe".into(),
            arguments: vec![
                "-NoProfile".into(),
                "-NonInteractive".into(),
                "-Command".into(),
                windows.into(),
            ],
            field: CommandField::Password,
        }
    } else {
        CommandCredential {
            program: "/bin/sh".into(),
            arguments: vec!["-c".into(), unix.into()],
            field: CommandField::Password,
        }
    }
}

#[tokio::test]
async fn runner_requires_complete_successful_bounded_output_and_redacts_failures() {
    let CredentialMaterial::Password(secret) = helper(
        "[Console]::Out.Write(' pass '); [Console]::Error.Write('discarded')",
        "printf ' pass '; printf discarded >&2",
    )
    .credential()
    .await
    .unwrap() else {
        panic!("password field returned another credential kind")
    };
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
            CommandCredential {
                program: "scoplen-fixture-nonexistent-password-helper".into(),
                arguments: vec![],
                field: CommandField::Password,
            },
            "could not start",
        ),
    ] {
        let error = command.credential().await.unwrap_err();
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
    let CredentialMaterial::Password(secret) = command.credential().await.unwrap() else {
        panic!("password field returned another credential kind")
    };
    assert_eq!(secret.as_bytes(), b"hidden");
}
