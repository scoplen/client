// SPDX-License-Identifier: Apache-2.0

//! Device-local terminal appearance; independent of replicated Login references and colors.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use specta::Type;
use unicode_normalization::is_nfc;

use super::Store;

/// Installed-font fallbacks used by the shipped Default.
pub const DEFAULT_FONT_FAMILY: &str = "ui-monospace, SFMono-Regular, Consolas, monospace";
/// Named entries, excluding the separate Default.
pub const MAX_TERMINAL_PROFILES: usize = 32;

/// Cursor shapes supported by the terminal component.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
#[serde(rename_all = "camelCase")]
pub enum TerminalCursorStyle {
    /// Filled character cell.
    Block,
    /// Line under the character.
    Underline,
    /// Vertical line.
    Bar,
}

/// Editable appearance fields; colors retain their existing global owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Type)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TerminalProfileSettings {
    /// CSS font-family list resolved from installed fonts.
    pub font_family: String,
    /// Font size in CSS pixels, from 8 through 48.
    pub font_size: u32,
    /// Cursor shape.
    pub cursor_style: TerminalCursorStyle,
    /// Whether the cursor blinks.
    pub cursor_blink: bool,
    /// Retained rows above the current screen, from zero through 100,000.
    pub scrollback: u32,
}

impl Default for TerminalProfileSettings {
    fn default() -> Self {
        Self {
            font_family: DEFAULT_FONT_FAMILY.into(),
            font_size: 14,
            cursor_style: TerminalCursorStyle::Block,
            cursor_blink: true,
            scrollback: 2_000,
        }
    }
}

/// An immutable case-sensitive name and its editable appearance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct NamedTerminalProfile {
    /// Exact key stored by a Login.
    pub name: String,
    /// Current local appearance.
    pub settings: TerminalProfileSettings,
}

/// Complete directory for the current Store.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Type)]
#[serde(rename_all = "camelCase")]
pub struct TerminalProfileDirectory {
    /// Separate, editable Default, never a named alias.
    pub default_profile: TerminalProfileSettings,
    /// Up to 32 exact named entries in name order.
    pub named: Vec<NamedTerminalProfile>,
}

/// Safe failures for native commands and localized rendering.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Type, thiserror::Error)]
#[serde(rename_all = "camelCase")]
pub enum TerminalProfileIssue {
    /// Invalid exact name.
    #[error("use an NFC name of 1 to 128 UTF-8 bytes without controls or surrounding whitespace")]
    InvalidName,
    /// Invalid installed font list.
    #[error("use a nonempty font list of at most 256 UTF-8 bytes without controls")]
    InvalidFontFamily,
    /// Font size outside the supported integer range.
    #[error("font size must be an integer from 8 to 48")]
    InvalidFontSize,
    /// Scrollback outside the supported integer range.
    #[error("scrollback must be an integer from 0 to 100000")]
    InvalidScrollback,
    /// Exact key already exists.
    #[error("a terminal profile with that exact name already exists")]
    AlreadyExists,
    /// The named entry no longer exists.
    #[error("the terminal profile no longer exists")]
    NotFound,
    /// Directory capacity reached.
    #[error("at most 32 named terminal profiles are allowed")]
    Limit,
    /// Captured Account generation is no longer admitted.
    #[error("the current profile is unavailable")]
    Unavailable,
    /// Encrypted local persistence failed.
    #[error("terminal profiles could not be read or saved")]
    Storage,
}

fn name_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.trim() == name
        && !name.chars().any(char::is_control)
        && is_nfc(name)
}

fn validate(settings: &TerminalProfileSettings) -> Result<(), TerminalProfileIssue> {
    if settings.font_family.trim().is_empty()
        || settings.font_family.len() > 256
        || settings.font_family.chars().any(char::is_control)
    {
        return Err(TerminalProfileIssue::InvalidFontFamily);
    }
    if !(8..=48).contains(&settings.font_size) {
        return Err(TerminalProfileIssue::InvalidFontSize);
    }
    if settings.scrollback > 100_000 {
        return Err(TerminalProfileIssue::InvalidScrollback);
    }
    Ok(())
}

fn directory(conn: &Connection) -> Result<TerminalProfileDirectory, TerminalProfileIssue> {
    let mut result = TerminalProfileDirectory {
        default_profile: TerminalProfileSettings::default(),
        named: Vec::new(),
    };
    let mut stmt = conn
        .prepare("SELECT name,settings FROM terminal_profiles ORDER BY name")
        .map_err(|_| TerminalProfileIssue::Storage)?;
    let rows = stmt
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
        .map_err(|_| TerminalProfileIssue::Storage)?;
    for row in rows {
        let (name, json) = row.map_err(|_| TerminalProfileIssue::Storage)?;
        let settings: TerminalProfileSettings =
            serde_json::from_str(&json).map_err(|_| TerminalProfileIssue::Storage)?;
        validate(&settings).map_err(|_| TerminalProfileIssue::Storage)?;
        if name.is_empty() {
            result.default_profile = settings;
        } else {
            if !name_valid(&name) || result.named.len() == MAX_TERMINAL_PROFILES {
                return Err(TerminalProfileIssue::Storage);
            }
            result.named.push(NamedTerminalProfile { name, settings });
        }
    }
    Ok(result)
}

impl Store {
    /// Read local appearance without changing inventory or initiating a connection.
    pub fn terminal_profiles(&self) -> Result<TerminalProfileDirectory, TerminalProfileIssue> {
        directory(&self.conn())
    }

    /// Create an exact name by copying the current Default atomically.
    pub fn create_terminal_profile(
        &self,
        name: &str,
    ) -> Result<TerminalProfileDirectory, TerminalProfileIssue> {
        if !name_valid(name) {
            return Err(TerminalProfileIssue::InvalidName);
        }
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| TerminalProfileIssue::Storage)?;
        let current = directory(&tx)?;
        if current.named.iter().any(|entry| entry.name == name) {
            return Err(TerminalProfileIssue::AlreadyExists);
        }
        if current.named.len() == MAX_TERMINAL_PROFILES {
            return Err(TerminalProfileIssue::Limit);
        }
        let json = serde_json::to_string(&current.default_profile)
            .map_err(|_| TerminalProfileIssue::Storage)?;
        tx.execute(
            "INSERT INTO terminal_profiles(name,settings) VALUES(?1,?2)",
            params![name, json],
        )
        .map_err(|_| TerminalProfileIssue::Storage)?;
        let result = directory(&tx)?;
        tx.commit().map_err(|_| TerminalProfileIssue::Storage)?;
        Ok(result)
    }

    /// Edit the separate Default (`None`) or one existing exact named entry.
    pub fn save_terminal_profile(
        &self,
        name: Option<&str>,
        settings: &TerminalProfileSettings,
    ) -> Result<TerminalProfileDirectory, TerminalProfileIssue> {
        if name.is_some_and(|name| !name_valid(name)) {
            return Err(TerminalProfileIssue::InvalidName);
        }
        validate(settings)?;
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| TerminalProfileIssue::Storage)?;
        if let Some(name) = name {
            let present = tx
                .query_row("SELECT 1 FROM terminal_profiles WHERE name=?1", [name], |_| Ok(()))
                .optional()
                .map_err(|_| TerminalProfileIssue::Storage)?;
            if present.is_none() {
                return Err(TerminalProfileIssue::NotFound);
            }
        }
        let json = serde_json::to_string(settings).map_err(|_| TerminalProfileIssue::Storage)?;
        tx.execute("INSERT INTO terminal_profiles(name,settings) VALUES(?1,?2) ON CONFLICT(name) DO UPDATE SET settings=excluded.settings", params![name.unwrap_or(""), json])
            .map_err(|_| TerminalProfileIssue::Storage)?;
        let result = directory(&tx)?;
        tx.commit().map_err(|_| TerminalProfileIssue::Storage)?;
        Ok(result)
    }

    /// Delete only a local named appearance; Login references stay unchanged.
    pub fn delete_terminal_profile(
        &self,
        name: &str,
    ) -> Result<TerminalProfileDirectory, TerminalProfileIssue> {
        if !name_valid(name) {
            return Err(TerminalProfileIssue::InvalidName);
        }
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| TerminalProfileIssue::Storage)?;
        if tx
            .execute("DELETE FROM terminal_profiles WHERE name=?1", [name])
            .map_err(|_| TerminalProfileIssue::Storage)?
            == 0
        {
            return Err(TerminalProfileIssue::NotFound);
        }
        let result = directory(&tx)?;
        tx.commit().map_err(|_| TerminalProfileIssue::Storage)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repository::{AccessProfile, AccessProfileChange, Edit, Repository};
    use scoplen_crypto::LocalDatabaseKey;

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store =
            Store::open(&dir.path().join("local.db"), &LocalDatabaseKey::new([7; 32])).unwrap();
        (dir, store)
    }

    #[test]
    fn defaults_copy_edit_reset_and_reopen_without_replicating() {
        let (dir, store) = store();
        let initial = store.terminal_profiles().unwrap();
        assert_eq!(initial.default_profile, TerminalProfileSettings::default());
        assert!(initial.named.is_empty());
        let customized = TerminalProfileSettings {
            font_family: "Consolas, monospace".into(),
            font_size: 18,
            cursor_style: TerminalCursorStyle::Bar,
            cursor_blink: false,
            scrollback: 0,
        };
        store.save_terminal_profile(None, &customized).unwrap();
        let copy = store.create_terminal_profile("Work").unwrap();
        assert_eq!(copy.named[0].settings, customized);
        let named = TerminalProfileSettings { scrollback: 100_000, ..customized.clone() };
        store.save_terminal_profile(Some("Work"), &named).unwrap();
        store.save_terminal_profile(None, &TerminalProfileSettings::default()).unwrap();
        assert!(store.list(scoplen_model::ObjectType::ACCESS_PROFILE).unwrap().is_empty());
        drop(store);
        let reopened =
            Store::open(&dir.path().join("local.db"), &LocalDatabaseKey::new([7; 32])).unwrap();
        let saved = reopened.terminal_profiles().unwrap();
        assert_eq!(saved.default_profile, TerminalProfileSettings::default());
        assert_eq!(saved.named[0].name, "Work");
        assert_eq!(saved.named[0].settings, named);
    }

    #[test]
    fn names_are_exact_immutable_utf8_keys_and_default_is_separate() {
        let (_dir, store) = store();
        for invalid in [
            "",
            " leading",
            "trailing ",
            "\tname",
            "a\0b",
            "a\nb",
            "\u{2003}name",
            "e\u{301}",
            &"x".repeat(129),
            &"界".repeat(43),
        ] {
            assert_eq!(
                store.create_terminal_profile(invalid),
                Err(TerminalProfileIssue::InvalidName)
            );
        }
        for name in ["Work", "work", "Default", "é", &"x".repeat(128), &"界".repeat(42)] {
            store.create_terminal_profile(name).unwrap();
        }
        assert_eq!(store.create_terminal_profile("Work"), Err(TerminalProfileIssue::AlreadyExists));
        assert_eq!(
            store.save_terminal_profile(Some("new name"), &TerminalProfileSettings::default()),
            Err(TerminalProfileIssue::NotFound)
        );
        assert_eq!(store.delete_terminal_profile(""), Err(TerminalProfileIssue::InvalidName));
        store.delete_terminal_profile("Default").unwrap();
        assert_eq!(
            store.terminal_profiles().unwrap().default_profile,
            TerminalProfileSettings::default()
        );
    }

    #[test]
    fn named_capacity_excludes_default_and_releases_after_delete() {
        let (_dir, store) = store();
        for index in 0..MAX_TERMINAL_PROFILES {
            store.create_terminal_profile(&format!("Profile {index}")).unwrap();
        }
        assert_eq!(store.create_terminal_profile("overflow"), Err(TerminalProfileIssue::Limit));
        assert_eq!(
            store.create_terminal_profile("Profile 0"),
            Err(TerminalProfileIssue::AlreadyExists)
        );
        store.save_terminal_profile(None, &TerminalProfileSettings::default()).unwrap();
        store.delete_terminal_profile("Profile 0").unwrap();
        assert_eq!(store.create_terminal_profile("replacement").unwrap().named.len(), 32);
    }

    #[test]
    fn field_limits_are_enforced_before_any_write() {
        let (_dir, store) = store();
        let base = TerminalProfileSettings::default();
        for font in ["", "   ", "font\nname", "font\u{7f}", &"x".repeat(257), &"界".repeat(86)] {
            assert_eq!(
                store.save_terminal_profile(
                    None,
                    &TerminalProfileSettings { font_family: font.into(), ..base.clone() }
                ),
                Err(TerminalProfileIssue::InvalidFontFamily)
            );
        }
        for size in [0, 7, 49, u32::MAX] {
            assert_eq!(
                store.save_terminal_profile(
                    None,
                    &TerminalProfileSettings { font_size: size, ..base.clone() }
                ),
                Err(TerminalProfileIssue::InvalidFontSize)
            );
        }
        for rows in [100_001, u32::MAX] {
            assert_eq!(
                store.save_terminal_profile(
                    None,
                    &TerminalProfileSettings { scrollback: rows, ..base.clone() }
                ),
                Err(TerminalProfileIssue::InvalidScrollback)
            );
        }
        assert_eq!(store.terminal_profiles().unwrap().default_profile, base);
        for (size, rows, style) in
            [(8, 0, TerminalCursorStyle::Underline), (48, 100_000, TerminalCursorStyle::Bar)]
        {
            store
                .save_terminal_profile(
                    None,
                    &TerminalProfileSettings {
                        font_family: "x".repeat(256),
                        font_size: size,
                        scrollback: rows,
                        cursor_style: style,
                        ..base.clone()
                    },
                )
                .unwrap();
        }
        let json = serde_json::to_value(&base).unwrap();
        for (field, value) in [
            ("fontSize", serde_json::json!(8.5)),
            ("scrollback", serde_json::json!(-1)),
            ("cursorStyle", serde_json::json!("invalid")),
            ("cursorBlink", serde_json::json!(1)),
        ] {
            let mut malformed = json.clone();
            malformed[field] = value;
            assert!(serde_json::from_value::<TerminalProfileSettings>(malformed).is_err());
        }
    }

    #[test]
    fn deletion_preserves_login_reference_and_does_not_change_inventory() {
        let (_dir, store) = store();
        let login = Repository::<AccessProfile>::new(&store)
            .create(AccessProfileChange {
                host: Some(uuid::Uuid::now_v7()),
                username: Some("operator".into()),
                terminal_profile: Edit::Set("Work".into()),
                ..Default::default()
            })
            .unwrap();
        let original = store.get(login.meta.id).unwrap().unwrap();
        store.create_terminal_profile("Work").unwrap();
        store.delete_terminal_profile("Work").unwrap();
        assert_eq!(store.get(login.meta.id).unwrap().unwrap(), original);
        assert_eq!(
            Repository::<AccessProfile>::new(&store)
                .get(login.meta.id)
                .unwrap()
                .unwrap()
                .terminal_profile
                .as_deref(),
            Some("Work")
        );
        assert_eq!(store.delete_terminal_profile("Work"), Err(TerminalProfileIssue::NotFound));
    }

    #[test]
    fn independent_local_and_account_stores_never_share_directory() {
        use super::super::profiles::ProfileRecord;
        use crate::profiles::AccountProfile;
        let (dir, local) = store();
        let record = ProfileRecord {
            profile: AccountProfile {
                id: uuid::Uuid::now_v7(),
                origin: "https://example.test".into(),
                account_id: uuid::Uuid::now_v7(),
                personal_vault_id: uuid::Uuid::now_v7(),
                device_id: uuid::Uuid::now_v7(),
                operation_id: uuid::Uuid::now_v7(),
                ready: true,
            },
            payload: scoplen_crypto::SecretVec::new(vec![1]),
            signature: [2; 64],
            confirmation: scoplen_crypto::SecretVec::new(vec![3]),
        };
        let account = Store::open_profile(
            &dir.path().join("account.db"),
            &LocalDatabaseKey::new([8; 32]),
            Some(&record),
        )
        .unwrap();
        local.create_terminal_profile("Local").unwrap();
        account.create_terminal_profile("Account").unwrap();
        assert_eq!(local.terminal_profiles().unwrap().named[0].name, "Local");
        assert_eq!(account.terminal_profiles().unwrap().named[0].name, "Account");
        let changed = TerminalProfileSettings { font_size: 20, ..Default::default() };
        account.save_terminal_profile(None, &changed).unwrap();
        assert_eq!(local.terminal_profiles().unwrap().default_profile.font_size, 14);
        drop(account);
        let reopened = Store::open_profile(
            &dir.path().join("account.db"),
            &LocalDatabaseKey::new([8; 32]),
            Some(&record),
        )
        .unwrap();
        assert_eq!(reopened.terminal_profiles().unwrap().default_profile.font_size, 20);
    }

    #[test]
    fn unreadable_persisted_settings_refuse_reads_and_roll_back_changes() {
        let (_dir, store) = store();
        store.create_terminal_profile("Work").unwrap();
        store
            .conn()
            .execute("UPDATE terminal_profiles SET settings='{}' WHERE name='Work'", [])
            .unwrap();
        assert_eq!(store.terminal_profiles(), Err(TerminalProfileIssue::Storage));
        assert_eq!(store.create_terminal_profile("Other"), Err(TerminalProfileIssue::Storage));
        assert_eq!(
            store.save_terminal_profile(None, &TerminalProfileSettings::default()),
            Err(TerminalProfileIssue::Storage)
        );
        let count: u32 = store
            .conn()
            .query_row("SELECT COUNT(*) FROM terminal_profiles", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }
}
