// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;

use scoplen_ssh::{
    MAX_PROXY_COMMAND_ARGUMENT, MAX_PROXY_COMMAND_ARGUMENTS, MAX_PROXY_COMMAND_PROGRAM,
};

use super::SshConnectionError;

pub(super) fn resolve(
    command: &str,
    host: &str,
    port: u16,
    username: &str,
) -> Result<(OsString, Vec<OsString>), SshConnectionError> {
    let words = tokenize(command)?;
    let mut expanded = words.into_iter().enumerate().map(|(index, word)| {
        expand(
            &word,
            host,
            &port.to_string(),
            username,
            if index == 0 { MAX_PROXY_COMMAND_PROGRAM } else { MAX_PROXY_COMMAND_ARGUMENT },
        )
    });
    let program = expanded.next().ok_or(invalid("enter a program"))??;
    if program.is_empty() {
        return Err(invalid("enter a nonempty program"));
    }
    Ok((program.into(), expanded.map(|word| word.map(OsString::from)).collect::<Result<_, _>>()?))
}

fn invalid(reason: &'static str) -> SshConnectionError {
    SshConnectionError::InvalidProxyCommand(reason)
}

fn tokenize(command: &str) -> Result<Vec<String>, SshConnectionError> {
    if command.len() > scoplen_model::MAX_TEXT_BYTES {
        return Err(invalid("the saved command exceeds 16384 bytes"));
    }
    if command.chars().any(|ch| ch.is_control() && ch != '\t') {
        return Err(invalid("control characters are not allowed"));
    }
    let mut words = Vec::new();
    let mut word = String::new();
    let mut started = false;
    let mut quote = None;
    let mut characters = command.chars().peekable();
    while let Some(ch) = characters.next() {
        match ch {
            '\'' | '"' if quote == Some(ch) => quote = None,
            '\'' | '"' if quote.is_none() => {
                quote = Some(ch);
                started = true;
            }
            '\\' if quote != Some('\'')
                && characters
                    .peek()
                    .is_some_and(|next| matches!(next, '\'' | '"' | '\\' | ' ' | '\t')) =>
            {
                word.push(characters.next().expect("peeked escape"));
                started = true;
            }
            ' ' | '\t' if quote.is_none() => {
                if started {
                    finish_word(&mut words, &mut word)?;
                    started = false;
                }
            }
            _ => {
                word.push(ch);
                started = true;
            }
        }
    }
    if quote.is_some() {
        return Err(invalid("close the quoted argument"));
    }
    if started {
        finish_word(&mut words, &mut word)?;
    }
    Ok(words)
}

fn finish_word(words: &mut Vec<String>, word: &mut String) -> Result<(), SshConnectionError> {
    if words.len() > MAX_PROXY_COMMAND_ARGUMENTS {
        return Err(invalid("at most 64 arguments are allowed"));
    }
    words.push(std::mem::take(word));
    Ok(())
}

fn expand(
    word: &str,
    host: &str,
    port: &str,
    username: &str,
    limit: usize,
) -> Result<String, SshConnectionError> {
    let mut output = String::new();
    let mut characters = word.chars();
    while let Some(ch) = characters.next() {
        let mut bytes = [0; 4];
        let part = if ch == '%' {
            match characters.next() {
                Some('h') => host,
                Some('p') => port,
                Some('r') => username,
                Some('%') => "%",
                _ => return Err(invalid("use only %h, %p, %r, or %% substitutions")),
            }
        } else {
            ch.encode_utf8(&mut bytes)
        };
        if part.contains('\0') {
            return Err(invalid("NUL is not allowed in a process argument"));
        }
        if output.len() + part.len() > limit {
            return Err(invalid("each expanded program or argument must fit 4096 bytes"));
        }
        output.push_str(part);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(command: &str) -> (OsString, Vec<OsString>) {
        resolve(command, "host.example", 2222, "remote user").unwrap()
    }

    #[test]
    fn quotes_and_windows_paths_are_portable_without_a_shell() {
        let (program, args) = arguments(
            r#""C:\Program Files\proxy.exe" --host=%h '%r' %p '' a\ b "a\"b" C:\tools\bridge $HOME | >"#,
        );
        assert_eq!(program, r"C:\Program Files\proxy.exe");
        assert_eq!(
            args,
            [
                "--host=host.example",
                "remote user",
                "2222",
                "",
                "a b",
                "a\"b",
                r"C:\tools\bridge",
                "$HOME",
                "|",
                ">",
            ]
            .map(OsString::from),
        );
        assert_eq!(
            arguments(r"proxy 'C:\path\file' 'a\ b'").1,
            [r"C:\path\file", r"a\ b"].map(OsString::from)
        );
    }

    #[test]
    fn substitutions_are_single_literal_arguments_and_never_reparsed() {
        let host = "host \";$(ignored)%r";
        let username = "user ' | `ignored` \\";
        let (program, args) = resolve("bridge %h %r %%h", host, 22, username).unwrap();
        assert_eq!(program, "bridge");
        assert_eq!(args, [host, username, "%h"].map(OsString::from));
    }

    #[test]
    fn malformed_and_oversized_commands_fail_without_disclosing_input() {
        for command in [
            "",
            " \t ",
            "''",
            "bridge '",
            "bridge \"",
            "bridge %",
            "bridge %x",
            "bridge\narg",
            "bridge\0arg",
        ] {
            let error = resolve(command, "host", 22, "user").unwrap_err();
            assert!(matches!(error, SshConnectionError::InvalidProxyCommand(_)));
        }
        for command in [
            "x".repeat(4097),
            format!("bridge {}", "x".repeat(4097)),
            "x".repeat(scoplen_model::MAX_TEXT_BYTES + 1),
            format!("bridge {}", "x ".repeat(65)),
        ] {
            assert!(resolve(&command, "host", 22, "user").is_err());
        }
        let route =
            super::super::ConnectionRoute::Command { command: "private-command-data".into() };
        assert!(!format!("{route:?}").contains("private-command-data"));
        assert!(
            !resolve("bridge private-command-data %x", "host", 22, "user")
                .unwrap_err()
                .to_string()
                .contains("private-command-data")
        );
    }

    #[test]
    fn bounds_apply_after_expansion_in_utf8_bytes() {
        assert!(
            resolve(&format!("bridge {}", "%h".repeat(17)), &"h".repeat(255), 22, "user").is_err()
        );
        assert!(resolve("bridge %r", "host", 22, &"\u{1f980}".repeat(1025)).is_err());
        assert!(resolve("bridge %r", "host", 22, &"\u{1f980}".repeat(1024)).is_ok());
        assert!(resolve(&format!("bridge {}", "x ".repeat(64)), "host", 22, "user").is_ok());
        assert!(resolve("bridge %h", "bad\0host", 22, "user").is_err());
    }
}
