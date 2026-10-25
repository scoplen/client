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
    // 5: publish a complete, verified Personal bootstrap as one encrypted snapshot.
    r#"
    CREATE TABLE personal_sync (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        generation INTEGER NOT NULL CHECK (generation > 0),
        session BLOB NOT NULL CHECK (length(session) BETWEEN 1 AND 4194304),
        account_keys BLOB NOT NULL CHECK (length(account_keys) BETWEEN 1 AND 4194304),
        vault_keys BLOB NOT NULL CHECK (length(vault_keys) BETWEEN 1 AND 4194304)
    ) STRICT;
    "#,
    // 6: explicit Personal adoption, durable merge bases, and the applied cursor.
    // Sequences are big-endian bytes so the complete K-4 u64 range is retained.
    r#"
    CREATE TABLE personal_sync_progress (
        vault BLOB PRIMARY KEY CHECK (length(vault) = 16),
        cursor BLOB NOT NULL CHECK (length(cursor) = 8),
        acknowledged BLOB NOT NULL CHECK (length(acknowledged) = 8)
    ) STRICT, WITHOUT ROWID;
    CREATE TABLE personal_sync_objects (
        object_id BLOB PRIMARY KEY REFERENCES objects(id) CHECK (length(object_id) = 16),
        vault BLOB NOT NULL REFERENCES personal_sync_progress(vault),
        base BLOB CHECK (base IS NULL OR length(base) = 8),
        dirty INTEGER NOT NULL CHECK (dirty IN (0, 1))
    ) STRICT, WITHOUT ROWID;
    CREATE INDEX personal_sync_pending ON personal_sync_objects(vault, dirty);
    CREATE TABLE personal_sync_backups (
        object_id BLOB PRIMARY KEY CHECK (length(object_id) = 16),
        vault BLOB NOT NULL CHECK (length(vault) = 16),
        envelope BLOB NOT NULL,
        adopted_at INTEGER NOT NULL
    ) STRICT, WITHOUT ROWID;
    "#,
    // 7: immutable edits whose server objects disappeared beyond the purge horizon.
    r#"
    CREATE TABLE personal_sync_recovery (
        id BLOB PRIMARY KEY CHECK (length(id) = 16),
        vault BLOB NOT NULL CHECK (length(vault) = 16),
        object_id BLOB NOT NULL CHECK (length(object_id) = 16),
        envelope BLOB NOT NULL,
        recovered_at INTEGER NOT NULL
    ) STRICT, WITHOUT ROWID;
    CREATE INDEX personal_sync_recovery_by_vault ON personal_sync_recovery(vault);
    "#,
    // 8: fence native authentication and consume single-use refresh credentials before I/O.
    // Older sessions lack a verified scope ceiling and must authenticate afresh.
    r#"
    ALTER TABLE personal_server ADD COLUMN auth_generation INTEGER NOT NULL DEFAULT 0 CHECK (auth_generation >= 0);
    ALTER TABLE personal_server ADD COLUMN auth_scope TEXT CHECK (auth_scope IS NULL OR length(auth_scope) BETWEEN 1 AND 512);
    ALTER TABLE personal_server ADD COLUMN refresh_claimed INTEGER NOT NULL DEFAULT 0 CHECK (refresh_claimed IN (0, 1));
    ALTER TABLE personal_server ADD COLUMN session_established INTEGER NOT NULL DEFAULT 0 CHECK (session_established IN (0, 1));
    ALTER TABLE personal_server ADD COLUMN refresh_retry_at INTEGER;
    UPDATE personal_server SET session_established = 1 WHERE access_token IS NOT NULL;
    "#,
    // 9: the last completely verified, explicitly requested account/device snapshot.
    r#"
    CREATE TABLE personal_account_snapshot (
        singleton INTEGER PRIMARY KEY REFERENCES personal_server(singleton) ON DELETE CASCADE CHECK (singleton = 1),
        origin TEXT NOT NULL,
        account_id BLOB NOT NULL CHECK (length(account_id) = 16),
        queried_at INTEGER NOT NULL CHECK (queried_at >= 0),
        profile BLOB NOT NULL CHECK (length(profile) BETWEEN 1 AND 4096),
        devices BLOB NOT NULL CHECK (length(devices) BETWEEN 1 AND 6291456)
    ) STRICT;
    "#,
    // 10: an authenticated pairing handoff is its own account trust provenance.
    r#"
    ALTER TABLE personal_server ADD COLUMN paired_handoff BLOB
        CHECK (paired_handoff IS NULL OR length(paired_handoff) BETWEEN 1 AND 4456408);
    CREATE TABLE personal_pairing_device (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        origin TEXT NOT NULL CHECK (length(origin) BETWEEN 1 AND 2048),
        device_name TEXT NOT NULL CHECK (length(device_name) BETWEEN 1 AND 128),
        signing BLOB NOT NULL CHECK (length(signing) = 32),
        kem BLOB NOT NULL CHECK (length(kem) = 32),
        created_at INTEGER NOT NULL CHECK (created_at >= 0)
    ) STRICT;
    CREATE TABLE personal_pairing (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        generation INTEGER NOT NULL CHECK (generation > 0),
        side INTEGER NOT NULL CHECK (side IN (1, 2)),
        origin TEXT NOT NULL CHECK (length(origin) BETWEEN 1 AND 2048),
        pairing_id BLOB NOT NULL CHECK (length(pairing_id) = 16),
        peer_id BLOB CHECK (peer_id IS NULL OR length(peer_id) = 16),
        expires_at INTEGER NOT NULL CHECK (expires_at > 0),
        local_expires_at INTEGER NOT NULL CHECK (local_expires_at > 0 AND local_expires_at <= expires_at),
        attempt_started INTEGER NOT NULL CHECK (attempt_started IN (0, 1)),
        phase TEXT NOT NULL,
        capability BLOB CHECK (capability IS NULL OR length(capability) = 32),
        transcript BLOB NOT NULL CHECK (length(transcript) BETWEEN 1 AND 8388608),
        certificate BLOB CHECK (certificate IS NULL OR length(certificate) BETWEEN 1 AND 65536),
        key_update BLOB CHECK (key_update IS NULL OR length(key_update) BETWEEN 1 AND 4194304),
        handoff BLOB CHECK (handoff IS NULL OR length(handoff) BETWEEN 41 AND 4456448),
        acceptance BLOB CHECK (acceptance IS NULL OR length(acceptance) = 64),
        approval_request BLOB CHECK (approval_request IS NULL OR length(approval_request) BETWEEN 1 AND 6291456)
    ) STRICT;
    CREATE TABLE personal_pairing_attempts (
        pairing_id BLOB PRIMARY KEY CHECK (length(pairing_id) = 16),
        origin TEXT NOT NULL,
        side INTEGER NOT NULL CHECK (side IN (1, 2))
    ) STRICT, WITHOUT ROWID;
    "#,
    // 11: locally verified admission is independent of retired enrollment ceremonies.
    r#"
    CREATE TABLE personal_admission (
        singleton INTEGER PRIMARY KEY REFERENCES personal_server(singleton) CHECK (singleton = 1),
        origin TEXT NOT NULL CHECK (length(origin) BETWEEN 1 AND 2048),
        account_id BLOB NOT NULL CHECK (length(account_id) = 16),
        personal_vault_id BLOB NOT NULL CHECK (length(personal_vault_id) = 16),
        device_id BLOB NOT NULL CHECK (length(device_id) = 16),
        anchors BLOB NOT NULL CHECK (length(anchors) BETWEEN 1 AND 524288)
    ) STRICT;
    CREATE TRIGGER personal_admission_binding BEFORE INSERT ON personal_admission
    WHEN NOT EXISTS (SELECT 1 FROM personal_server p, device d WHERE p.singleton=1
        AND d.singleton=1 AND p.origin=NEW.origin AND p.account_id=NEW.account_id
        AND p.personal_vault_id=NEW.personal_vault_id AND d.device_id=NEW.device_id)
    BEGIN SELECT RAISE(ABORT, 'Personal account context mismatch'); END;
    CREATE TRIGGER personal_admission_immutable BEFORE UPDATE ON personal_admission
    BEGIN SELECT RAISE(ABORT, 'Personal admission is immutable'); END;
    CREATE TRIGGER personal_admission_no_replace BEFORE INSERT ON personal_admission
    WHEN EXISTS (SELECT 1 FROM personal_admission)
    BEGIN SELECT RAISE(ABORT, 'Personal admission already belongs to this profile'); END;
    CREATE TRIGGER personal_admission_retained BEFORE DELETE ON personal_admission
    BEGIN SELECT RAISE(ABORT, 'Personal admission belongs to this profile'); END;
    CREATE TRIGGER personal_identity_immutable
    BEFORE UPDATE OF origin, account_id, personal_vault_id, private_material ON personal_server
    WHEN EXISTS (SELECT 1 FROM personal_admission) AND
        (NEW.origin IS NOT OLD.origin OR NEW.account_id IS NOT OLD.account_id
        OR NEW.personal_vault_id IS NOT OLD.personal_vault_id
        OR NEW.private_material IS NOT OLD.private_material)
    BEGIN SELECT RAISE(ABORT, 'Personal account context is immutable'); END;
    CREATE TRIGGER personal_identity_no_replace BEFORE INSERT ON personal_server
    WHEN EXISTS (SELECT 1 FROM personal_admission)
    BEGIN SELECT RAISE(ABORT, 'Personal account already belongs to this profile'); END;
    CREATE TRIGGER personal_device_immutable BEFORE UPDATE OF device_id ON device
    WHEN EXISTS (SELECT 1 FROM personal_admission) AND NEW.device_id IS NOT OLD.device_id
    BEGIN SELECT RAISE(ABORT, 'Personal device context is immutable'); END;
    CREATE TRIGGER personal_device_no_replace BEFORE INSERT ON device
    WHEN EXISTS (SELECT 1 FROM personal_admission) AND
        NEW.device_id IS NOT (SELECT device_id FROM personal_admission WHERE singleton=1)
    BEGIN SELECT RAISE(ABORT, 'Personal device already belongs to this profile'); END;
    CREATE TRIGGER personal_device_retained BEFORE DELETE ON device
    WHEN EXISTS (SELECT 1 FROM personal_admission)
    BEGIN SELECT RAISE(ABORT, 'Personal device belongs to this profile'); END;
    CREATE TRIGGER personal_device_keys_immutable BEFORE UPDATE ON device_key_pair
    WHEN EXISTS (SELECT 1 FROM personal_admission) AND
        (NEW.signing IS NOT OLD.signing OR NEW.kem IS NOT OLD.kem)
    BEGIN SELECT RAISE(ABORT, 'Personal device keys are immutable'); END;
    CREATE TRIGGER personal_device_keys_no_replace BEFORE INSERT ON device_key_pair
    WHEN EXISTS (SELECT 1 FROM personal_admission) AND NOT EXISTS (
        SELECT 1 FROM device_key_pair WHERE singleton=1 AND signing=NEW.signing AND kem=NEW.kem)
    BEGIN SELECT RAISE(ABORT, 'Personal device keys already belong to this profile'); END;
    CREATE TRIGGER personal_device_keys_retained BEFORE DELETE ON device_key_pair
    WHEN EXISTS (SELECT 1 FROM personal_admission)
    BEGIN SELECT RAISE(ABORT, 'Personal device keys belong to this profile'); END;
    "#,
];
