// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::BTreeMap,
    io::Read,
    path::{Component, Path, PathBuf},
};

use sha2::{Digest, Sha256};
use ssh_key::{
    PublicKey,
    known_hosts::{Entry, HostPatterns, Marker},
};
use zeroize::Zeroizing;

use super::*;

const MAX_BYTES: usize = 8 * 1024 * 1024;
const MAX_FILES: usize = 64;
const MAX_HOSTS: usize = 256;
const MAX_LINE: usize = 4096;

pub(super) struct Sources {
    files: BTreeMap<PathBuf, Zeroizing<Vec<u8>>>,
    bytes: usize,
    pub home: PathBuf,
    pub user: String,
    cwd: PathBuf,
}

impl Sources {
    fn new() -> Self {
        Self {
            files: BTreeMap::new(),
            bytes: 0,
            home: std::env::var_os("USERPROFILE")
                .or_else(|| std::env::var_os("HOME"))
                .map(PathBuf::from)
                .unwrap_or_default(),
            user: std::env::var("USER")
                .or_else(|_| std::env::var("USERNAME"))
                .unwrap_or_else(|_| "unknown".into()),
            cwd: std::env::current_dir().unwrap_or_default(),
        }
    }

    pub fn read(&mut self, path: &Path, limit: usize) -> Result<Vec<u8>, OpenSshImportError> {
        let path = path.canonicalize().map_err(|_| OpenSshImportError::FileNotFound)?;
        if let Some(bytes) = self.files.get(&path) {
            if bytes.len() > limit {
                return Err(OpenSshImportError::TooLarge);
            }
            return Ok(bytes.to_vec());
        }
        if self.files.len() >= MAX_FILES {
            return Err(OpenSshImportError::TooLarge);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        std::fs::File::open(&path)
            .map_err(|_| OpenSshImportError::FileNotFound)?
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| OpenSshImportError::FileNotFound)?;
        self.bytes += bytes.len();
        if bytes.len() > limit || self.bytes > MAX_BYTES {
            return Err(OpenSshImportError::TooLarge);
        }
        let result = bytes.to_vec();
        self.files.insert(path, bytes);
        Ok(result)
    }

    pub fn revision(&self) -> String {
        let mut hash = Sha256::new();
        for (path, bytes) in &self.files {
            let path = display(path);
            hash.update((path.len() as u64).to_be_bytes());
            hash.update(path.as_bytes());
            hash.update((bytes.len() as u64).to_be_bytes());
            hash.update(bytes.as_slice());
        }
        format!("{:x}", hash.finalize())
    }

    pub fn count(&self) -> u32 {
        self.files.len() as u32
    }
}

#[derive(Clone)]
struct Directive {
    file: String,
    line: u32,
    keyword: String,
    words: Vec<String>,
    value: String,
    includes: Vec<Vec<Directive>>,
}

pub(super) struct Host {
    pub row: OpenSshImportEntry,
    pub keys: Vec<PathBuf>,
    pub trust: BTreeMap<String, PublicKey>,
    known_files: Vec<PathBuf>,
}

pub(super) struct Parsed {
    pub path: String,
    pub sources: Sources,
    pub hosts: Vec<Host>,
    pub skipped: Vec<OpenSshSkippedHost>,
    pub unsupported: Vec<OpenSshUnsupportedDirective>,
}

pub(super) fn read(path: &str) -> Result<Parsed, OpenSshImportError> {
    let path = Path::new(path).canonicalize().map_err(|_| OpenSshImportError::FileNotFound)?;
    let mut sources = Sources::new();
    let mut unsupported = Vec::new();
    let ast = read_config(&path, &mut sources, &mut Vec::new(), &mut unsupported)?;
    let mut aliases = BTreeMap::new();
    discover(&ast, &mut aliases);
    if aliases.len() > MAX_HOSTS {
        return Err(OpenSshImportError::TooLarge);
    }
    let mut hosts = Vec::new();
    let mut skipped = Vec::new();
    for (alias, (file, line)) in aliases {
        match evaluate(&ast, &alias, &file, line, &sources) {
            Ok(host) => hosts.push(host),
            Err(reason) => {
                skipped.push(OpenSshSkippedHost { alias, source_file: file, line, reason })
            }
        }
    }
    // The orchestrator supports explicit direct hops. A nested route cannot be flattened faithfully.
    let direct = hosts
        .iter()
        .filter(|host| matches!(host.row.route, OpenSshImportRoute::Direct))
        .map(|host| host.row.alias.clone())
        .collect::<BTreeSet<_>>();
    hosts.retain(|host| {
        if let OpenSshImportRoute::Jump { hops } = &host.row.route
            && let Some(alias) =
                hops.iter().find(|alias| !direct.contains(*alias) || **alias == host.row.alias)
        {
            skipped.push(OpenSshSkippedHost {
                alias: host.row.alias.clone(),
                source_file: host.row.source_file.clone(),
                line: host.row.line,
                reason: OpenSshSkipReason::RouteDependency { alias: alias.clone() },
            });
            return false;
        }
        true
    });
    for host in &mut hosts {
        let mut conflicted = BTreeSet::new();
        let mut revoked = Vec::new();
        let configured = host.keys.clone();
        host.keys = configured.into_iter().filter(|path| path.is_file()).collect();
        host.row.identity_files = host.keys.iter().map(|path| display(path)).collect();
        for known in host.known_files.clone() {
            if !known.is_file() {
                continue;
            }
            let bytes = sources.read(&known, 1024 * 1024)?;
            let text = String::from_utf8(bytes).map_err(|_| OpenSshImportError::NotText)?;
            for (index, raw) in text.lines().enumerate() {
                let raw = raw.split('#').next().unwrap_or_default().trim();
                if raw.is_empty() {
                    continue;
                }
                let normalized = raw.split_whitespace().collect::<Vec<_>>().join(" ");
                let entry = normalized.parse::<Entry>();
                let diagnostic = || OpenSshUnsupportedDirective {
                    source_file: display(&known),
                    line: (index + 1) as u32,
                    directive: "known_hosts".into(),
                };
                let Ok(entry) = entry else {
                    unsupported.push(diagnostic());
                    continue;
                };
                if let Some(marker) = entry.marker() {
                    // Preserve explicit marker semantics; these are not ordinary trusted host keys.
                    unsupported.push(diagnostic());
                    if *marker == Marker::Revoked {
                        revoked.push(entry.public_key().clone());
                    }
                    continue;
                }
                let HostPatterns::Patterns(patterns) = entry.host_patterns() else {
                    unsupported.push(diagnostic());
                    continue;
                };
                if patterns.iter().any(|pattern| pattern.contains(['*', '?', '!'])) {
                    unsupported.push(diagnostic());
                    continue;
                }
                let endpoint = if host.row.port == 22 {
                    host.row.address.clone()
                } else {
                    format!("[{}]:{}", host.row.address, host.row.port)
                };
                if patterns.iter().any(|pattern| pattern.eq_ignore_ascii_case(&endpoint)) {
                    let mut key = entry.public_key().clone();
                    key.set_comment("");
                    let algorithm = key.algorithm().as_str().to_owned();
                    if conflicted.contains(&algorithm) {
                        continue;
                    }
                    if host
                        .trust
                        .get(&algorithm)
                        .is_some_and(|previous| previous.key_data() != key.key_data())
                    {
                        unsupported.push(diagnostic());
                        host.trust.remove(&algorithm);
                        conflicted.insert(algorithm);
                    } else {
                        host.trust.insert(algorithm, key);
                    }
                }
            }
        }
        host.trust
            .retain(|_, key| !revoked.iter().any(|revoked| revoked.key_data() == key.key_data()));
        host.row.trust_records = host.trust.len() as u32;
    }
    unsupported.sort_by(|a, b| {
        (&a.source_file, a.line, &a.directive).cmp(&(&b.source_file, b.line, &b.directive))
    });
    unsupported.dedup();
    Ok(Parsed { path: display(&path), sources, hosts, skipped, unsupported })
}

fn read_config(
    path: &Path,
    sources: &mut Sources,
    stack: &mut Vec<PathBuf>,
    unsupported: &mut Vec<OpenSshUnsupportedDirective>,
) -> Result<Vec<Directive>, OpenSshImportError> {
    let path = path.canonicalize().map_err(|_| OpenSshImportError::FileNotFound)?;
    if stack.contains(&path) || stack.len() >= 16 {
        return Err(OpenSshImportError::Failed {
            reference: "the OpenSSH Include chain is recursive or too deep".into(),
        });
    }
    stack.push(path.clone());
    let text = String::from_utf8(sources.read(&path, 1024 * 1024)?)
        .map_err(|_| OpenSshImportError::NotText)?;
    let mut nodes = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        if raw.len() > MAX_LINE {
            return Err(OpenSshImportError::TooLarge);
        }
        let Some((keyword, words, value)) = lex(raw) else {
            continue;
        };
        let mut node = Directive {
            file: display(&path),
            line: (index + 1) as u32,
            keyword,
            words,
            value,
            includes: Vec::new(),
        };
        if node.keyword == "include" {
            if node.words.is_empty() || node.words.iter().any(|word| word.contains(['[', ']'])) {
                unsupported.push(report(&node));
                node.keyword = "unsupported-include".into();
            }
            for pattern in &node.words {
                if node.keyword != "include" {
                    break;
                }
                let Some(pattern) = path_value(pattern, sources, None) else {
                    unsupported.push(report(&node));
                    node.keyword = "unsupported-include".into();
                    break;
                };
                for included in glob(&pattern)? {
                    node.includes.push(read_config(&included, sources, stack, unsupported)?);
                }
            }
        } else if !matches!(
            node.keyword.as_str(),
            "host"
                | "hostname"
                | "user"
                | "port"
                | "identityfile"
                | "proxyjump"
                | "proxycommand"
                | "userknownhostsfile"
        ) || node.keyword == "proxycommand"
            && node.value != "none"
            && !proxy_command_supported(&node.value, "example", 22, "user")
        {
            unsupported.push(report(&node));
        }
        nodes.push(node);
    }
    stack.pop();
    Ok(nodes)
}

fn report(node: &Directive) -> OpenSshUnsupportedDirective {
    OpenSshUnsupportedDirective {
        source_file: node.file.clone(),
        line: node.line,
        directive: node.keyword.clone(),
    }
}

fn discover(nodes: &[Directive], aliases: &mut BTreeMap<String, (String, u32)>) {
    for node in nodes {
        if node.keyword == "host" {
            for alias in &node.words {
                if !alias.is_empty() && !alias.contains(['*', '?', '!', '%']) {
                    aliases
                        .entry(alias.to_ascii_lowercase())
                        .or_insert((node.file.clone(), node.line));
                }
            }
        }
        for included in &node.includes {
            discover(included, aliases);
        }
    }
}

fn evaluate(
    nodes: &[Directive],
    alias: &str,
    file: &str,
    line: u32,
    sources: &Sources,
) -> Result<Host, OpenSshSkipReason> {
    let mut values = BTreeMap::<String, Vec<String>>::new();
    let mut identities = Vec::new();
    let mut declared = false;
    evaluate_nodes(nodes, alias, true, &mut values, &mut identities, &mut declared)?;
    if !declared {
        return Err(OpenSshSkipReason::GlobalRules { directive: "Include".into() });
    }
    let single = |key: &str| values.get(key).and_then(|v| (v.len() == 1).then(|| v[0].clone()));
    let address =
        single("hostname").unwrap_or_else(|| alias.into()).replace("%h", alias).replace("%%", "%");
    let username = single("user").unwrap_or_else(|| sources.user.clone());
    let invalid = |directive: &str| OpenSshSkipReason::InvalidValue { directive: directive.into() };
    if address.is_empty() || address.contains('%') || address.chars().any(char::is_whitespace) {
        return Err(invalid("HostName"));
    }
    if username.is_empty() || username.contains('%') {
        return Err(invalid("User"));
    }
    let port = match single("port") {
        Some(port) => {
            port.parse::<u16>().ok().filter(|p| *p != 0).ok_or_else(|| invalid("Port"))?
        }
        None => 22,
    };
    let route = if let Some(command) = single("proxycommand").filter(|v| v != "none") {
        if !proxy_command_supported(&command, &address, port, &username) {
            return Err(invalid("ProxyCommand"));
        }
        OpenSshImportRoute::Command { command }
    } else if let Some(jump) = single("proxyjump").filter(|v| v != "none") {
        let hops = jump.split(',').map(str::to_ascii_lowercase).collect::<Vec<_>>();
        if hops.is_empty()
            || hops.iter().any(|h| h.is_empty() || h.contains(['@', ':', '[', ']', '%']))
        {
            return Err(invalid("ProxyJump"));
        }
        if hops.iter().collect::<BTreeSet<_>>().len() != hops.len() {
            return Err(invalid("ProxyJump"));
        }
        OpenSshImportRoute::Jump { hops }
    } else {
        OpenSshImportRoute::Direct
    };
    if identities.is_empty() {
        identities = ["id_ed25519", "id_ecdsa", "id_rsa"]
            .iter()
            .map(|name| format!("~/.ssh/{name}"))
            .collect();
    }
    let mut keys = Vec::new();
    for identity in identities {
        if identity == "none" {
            continue;
        }
        let identity = identity.replace("%h", &address).replace("%r", &username);
        let path = path_value(&identity, sources, Some(&sources.cwd))
            .ok_or_else(|| invalid("IdentityFile"))?;
        if !keys.contains(&path) {
            keys.push(path);
        }
    }
    let known = values
        .get("userknownhostsfile")
        .cloned()
        .unwrap_or_else(|| vec!["~/.ssh/known_hosts".into(), "~/.ssh/known_hosts2".into()]);
    let mut known_files = Vec::new();
    for known in known {
        if known == "none" {
            continue;
        }
        known_files.push(
            path_value(&known, sources, Some(&sources.cwd))
                .ok_or_else(|| invalid("UserKnownHostsFile"))?,
        );
    }
    Ok(Host {
        row: OpenSshImportEntry {
            alias: alias.into(),
            address,
            port,
            username,
            source_file: file.into(),
            line,
            identity_file: None,
            identity_files: Vec::new(),
            credential_id: None,
            needs_credential: true,
            route,
            action: OpenSshImportAction::Create,
            trust_records: 0,
        },
        keys,
        trust: BTreeMap::new(),
        known_files,
    })
}

fn proxy_command_supported(command: &str, host: &str, port: u16, user: &str) -> bool {
    !command.contains(['|', '&', ';', '<', '>', '$', '`', '~'])
        && crate::connection::proxy_command::resolve(command, host, port, user).is_ok()
}

fn evaluate_nodes(
    nodes: &[Directive],
    alias: &str,
    mut active: bool,
    values: &mut BTreeMap<String, Vec<String>>,
    identities: &mut Vec<String>,
    declared: &mut bool,
) -> Result<(), OpenSshSkipReason> {
    for node in nodes {
        match node.keyword.as_str() {
            "host" => {
                active = patterns_match(&node.words, alias);
                *declared |= node.words.iter().any(|word| word.eq_ignore_ascii_case(alias));
            }
            "match" => return Err(OpenSshSkipReason::GlobalRules { directive: "Match".into() }),
            "include" => {
                if active {
                    for included in &node.includes {
                        evaluate_nodes(included, alias, active, values, identities, declared)?;
                    }
                }
            }
            _ if !active => (),
            "identityfile" => {
                if node.words.len() != 1 {
                    return Err(OpenSshSkipReason::InvalidValue {
                        directive: "IdentityFile".into(),
                    });
                }
                if !identities.contains(&node.words[0]) {
                    identities.push(node.words[0].clone());
                }
            }
            "hostname" | "user" | "port" | "userknownhostsfile" => {
                if node.words.is_empty()
                    || node.keyword != "userknownhostsfile" && node.words.len() != 1
                {
                    return Err(OpenSshSkipReason::InvalidValue {
                        directive: node.keyword.clone(),
                    });
                }
                values.entry(node.keyword.clone()).or_insert_with(|| node.words.clone());
            }
            "proxyjump" | "proxycommand" => {
                if values.contains_key("proxyjump") || values.contains_key("proxycommand") {
                    continue;
                }
                let value = if node.keyword == "proxycommand" {
                    node.value.clone()
                } else if node.words.len() == 1 {
                    node.words[0].clone()
                } else {
                    return Err(OpenSshSkipReason::InvalidValue { directive: "ProxyJump".into() });
                };
                values.insert(node.keyword.clone(), vec![value]);
            }
            _ => {
                return Err(OpenSshSkipReason::UnsupportedDirective {
                    directive: node.keyword.clone(),
                });
            }
        }
    }
    Ok(())
}

fn path_value(value: &str, sources: &Sources, relative: Option<&Path>) -> Option<PathBuf> {
    let value = value
        .replace("%d", &display(&sources.home))
        .replace("%u", &sources.user)
        .replace("%%", "%");
    if value.contains('%')
        || value.contains("${")
        || value.starts_with('~') && !value.starts_with("~/")
    {
        return None;
    }
    let path = if let Some(rest) = value.strip_prefix("~/") {
        sources.home.join(rest)
    } else {
        PathBuf::from(value)
    };
    Some(if path.is_absolute() {
        path
    } else {
        relative.map(Path::to_path_buf).unwrap_or_else(|| sources.home.join(".ssh")).join(path)
    })
}

fn glob(pattern: &Path) -> Result<Vec<PathBuf>, OpenSshImportError> {
    let mut paths = vec![PathBuf::new()];
    for part in pattern.components() {
        if let Component::Normal(name) = part {
            let name = name.to_string_lossy();
            if name.contains(['*', '?']) {
                let mut next = Vec::new();
                for base in &paths {
                    if !base.is_dir() {
                        continue;
                    }
                    for child in
                        std::fs::read_dir(base).map_err(|_| OpenSshImportError::FileNotFound)?
                    {
                        let child = child.map_err(|_| OpenSshImportError::FileNotFound)?;
                        if wildcard(&name, &child.file_name().to_string_lossy()) {
                            next.push(child.path());
                        }
                    }
                }
                paths = next;
            } else {
                for path in &mut paths {
                    path.push(name.as_ref());
                }
            }
        } else {
            for path in &mut paths {
                path.push(part.as_os_str());
            }
        }
        if paths.len() > MAX_FILES {
            return Err(OpenSshImportError::TooLarge);
        }
    }
    paths.retain(|path| path.is_file());
    paths.sort();
    Ok(paths)
}

fn patterns_match(patterns: &[String], alias: &str) -> bool {
    let mut matched = false;
    for pattern in patterns {
        if let Some(negative) = pattern.strip_prefix('!') {
            if wildcard(&negative.to_ascii_lowercase(), alias) {
                return false;
            }
        } else if wildcard(&pattern.to_ascii_lowercase(), alias) {
            matched = true;
        }
    }
    matched
}

fn wildcard(pattern: &str, value: &str) -> bool {
    let p = pattern.as_bytes();
    let v = value.as_bytes();
    let (mut i, mut j, mut star, mut retry) = (0, 0, None, 0);
    while j < v.len() {
        if i < p.len() && (p[i] == b'?' || p[i] == v[j]) {
            i += 1;
            j += 1;
        } else if i < p.len() && p[i] == b'*' {
            star = Some(i);
            i += 1;
            retry = j;
        } else if let Some(s) = star {
            retry += 1;
            j = retry;
            i = s + 1;
        } else {
            return false;
        }
    }
    while i < p.len() && p[i] == b'*' {
        i += 1;
    }
    i == p.len()
}

fn lex(raw: &str) -> Option<(String, Vec<String>, String)> {
    let raw = raw.trim();
    if raw.is_empty() || raw.starts_with('#') {
        return None;
    }
    let split = raw.find(|c: char| c.is_whitespace() || c == '=').unwrap_or(raw.len());
    let keyword = raw[..split].to_ascii_lowercase();
    let value = raw[split..]
        .trim_start()
        .strip_prefix('=')
        .unwrap_or(raw[split..].trim_start())
        .trim_start();
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quoted = false;
    let mut started = false;
    let mut end = value.len();
    let mut chars = value.char_indices().peekable();
    while let Some((index, ch)) = chars.next() {
        match ch {
            '"' => {
                quoted = !quoted;
                started = true;
            }
            '#' if !quoted => {
                end = index;
                break;
            }
            '\\' if chars
                .peek()
                .is_some_and(|(_, next)| matches!(next, '"' | '\\' | ' ' | '\t')) =>
            {
                word.push(chars.next()?.1);
                started = true;
            }
            ' ' | '\t' if !quoted => {
                if started {
                    words.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            _ => {
                word.push(ch);
                started = true;
            }
        }
    }
    if quoted {
        return Some(("invalid-syntax".into(), Vec::new(), String::new()));
    }
    if started {
        words.push(word);
    }
    Some((keyword, words, value[..end].trim_end().into()))
}

pub(super) fn display(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
