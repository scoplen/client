// SPDX-License-Identifier: Apache-2.0

//! Versioned schema migrations of the local store.
//!
//! Migrations run at startup, all pending ones in one transaction, so a store
//! is never left between versions (`scoplen-docs/11-client-architecture.md` §2).
//! A migration is never edited once released; a change is a new migration.

/// The ordered migrations. Version `n` is `MIGRATIONS[n - 1]`.
pub(crate) const MIGRATIONS: &[&str] = &[
    // 1: device identity and replicated objects.
    r#"
    CREATE TABLE device (
        singleton  INTEGER PRIMARY KEY CHECK (singleton = 1),
        device_id  BLOB    NOT NULL CHECK (length(device_id) = 16),
        clock      INTEGER NOT NULL,
        created_at INTEGER NOT NULL
    ) STRICT;

    -- Replicated objects in their merged form, as the deterministic CBOR
    -- envelope with per-field clocks (`04-object-model.md` §4). A NULL vault is
    -- this device's own collection before sync enrollment.
    CREATE TABLE objects (
        id         BLOB    PRIMARY KEY CHECK (length(id) = 16),
        vault      BLOB    CHECK (vault IS NULL OR length(vault) = 16),
        type       INTEGER NOT NULL,
        envelope   BLOB    NOT NULL,
        deleted    INTEGER NOT NULL CHECK (deleted IN (0, 1)),
        updated_at INTEGER NOT NULL
    ) STRICT, WITHOUT ROWID;

    CREATE INDEX objects_by_type ON objects (type, deleted);
    CREATE INDEX objects_by_vault ON objects (vault);
    "#,
    // 2: device-local records, which never replicate (`04-object-model.md` §4.9).
    r#"
    -- This device's own half of a credential whose binding is device: the
    -- secret held here, or a handle to a key held by a keystore or hardware.
    CREATE TABLE device_credentials (
        credential      BLOB    PRIMARY KEY CHECK (length(credential) = 16),
        secret          BLOB,
        keystore_handle TEXT,
        updated_at      INTEGER NOT NULL,
        CHECK (secret IS NOT NULL OR keystore_handle IS NOT NULL)
    ) STRICT, WITHOUT ROWID;

    -- The device key pair used for sync enrollment, private parts included.
    CREATE TABLE device_key_pair (
        singleton  INTEGER PRIMARY KEY CHECK (singleton = 1),
        signing    BLOB    NOT NULL,
        kem        BLOB    NOT NULL,
        created_at INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE session_history (
        id         BLOB    PRIMARY KEY CHECK (length(id) = 16),
        profile    BLOB    NOT NULL CHECK (length(profile) = 16),
        kind       INTEGER NOT NULL CHECK (kind IN (1, 2, 3)),
        started_at INTEGER NOT NULL,
        ended_at   INTEGER,
        outcome    INTEGER CHECK (outcome IS NULL OR outcome IN (1, 2))
    ) STRICT, WITHOUT ROWID;
    CREATE INDEX session_history_by_start ON session_history (started_at);

    CREATE TABLE scrollback (
        session    BLOB    PRIMARY KEY CHECK (length(session) = 16),
        data       BLOB    NOT NULL,
        updated_at INTEGER NOT NULL
    ) STRICT, WITHOUT ROWID;

    CREATE TABLE window_state (
        window     TEXT    PRIMARY KEY,
        state      BLOB    NOT NULL,
        updated_at INTEGER NOT NULL
    ) STRICT, WITHOUT ROWID;
    "#,
    // 3: local concept exposure metadata. Implicit objects are created by
    // tier-0 flows and promoted when they are reused or inspected. This
    // table is device-local: the object itself remains a normal replicated
    // object and carries no UI-only state.
    r#"
    CREATE TABLE implicit_objects (
        object_id   BLOB    PRIMARY KEY CHECK (length(object_id) = 16),
        object_type INTEGER NOT NULL,
        created_at  INTEGER NOT NULL
    ) STRICT, WITHOUT ROWID;
    CREATE INDEX implicit_objects_by_type ON implicit_objects (object_type);
    "#,
    // 4: a pending Personal identity is durable before its first network request.
    r#"
    CREATE TABLE personal_server (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        origin TEXT NOT NULL,
        account_id BLOB NOT NULL CHECK (length(account_id) = 16),
        personal_vault_id BLOB NOT NULL CHECK (length(personal_vault_id) = 16),
        device_name TEXT NOT NULL,
        private_material BLOB NOT NULL,
        enrollment_request BLOB,
        recovery_saved INTEGER NOT NULL DEFAULT 0 CHECK (recovery_saved IN (0, 1)),
        recovery_confirmed INTEGER NOT NULL DEFAULT 0 CHECK (recovery_confirmed IN (0, 1)),
        enrollment_attempted INTEGER NOT NULL DEFAULT 0 CHECK (enrollment_attempted IN (0, 1)),
        access_token BLOB,
        refresh_token BLOB,
        access_expires_at INTEGER,
        refresh_expires_at INTEGER,
        CHECK (recovery_confirmed = 0 OR recovery_saved = 1)
    ) STRICT;
    "#,
];
