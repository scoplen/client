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
    // 12: D-128 preparation is separate from an admitted identity and local writer id.
    r#"
    CREATE TABLE personal_registration (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        payload BLOB NOT NULL CHECK (length(payload) BETWEEN 1 AND 262144),
        account_signature BLOB NOT NULL CHECK (length(account_signature) = 64),
        private_material BLOB NOT NULL CHECK (length(private_material) = 225),
        recovery_saved INTEGER NOT NULL DEFAULT 0 CHECK (recovery_saved IN (0, 1)),
        recovery_confirmed INTEGER NOT NULL DEFAULT 0 CHECK (recovery_confirmed IN (0, 1)),
        phase INTEGER NOT NULL DEFAULT 0 CHECK (phase IN (0, 1, 2)),
        confirmation BLOB CHECK (confirmation IS NULL OR length(confirmation) BETWEEN 1 AND 1024),
        CHECK (recovery_confirmed = 0 OR recovery_saved = 1),
        CHECK (phase = 0 OR recovery_confirmed = 1),
        CHECK ((phase = 2) = (confirmation IS NOT NULL))
    ) STRICT;
    CREATE TRIGGER personal_registration_unbound BEFORE INSERT ON personal_registration
    WHEN EXISTS (SELECT 1 FROM personal_server) OR EXISTS (SELECT 1 FROM personal_admission)
        OR EXISTS (SELECT 1 FROM personal_pairing) OR EXISTS (SELECT 1 FROM personal_pairing_device)
        OR EXISTS (SELECT 1 FROM personal_pairing_attempts) OR EXISTS (SELECT 1 FROM device_key_pair)
    BEGIN SELECT RAISE(ABORT, 'Personal profile already contains an identity'); END;
    CREATE TRIGGER personal_registration_immutable
    BEFORE UPDATE OF payload, account_signature, private_material ON personal_registration
    WHEN NEW.payload IS NOT OLD.payload OR NEW.account_signature IS NOT OLD.account_signature
        OR NEW.private_material IS NOT OLD.private_material
    BEGIN SELECT RAISE(ABORT, 'Pending registration identity is immutable'); END;
    CREATE TRIGGER personal_registration_monotonic BEFORE UPDATE ON personal_registration
    WHEN NEW.phase < OLD.phase OR NEW.phase > OLD.phase + 1
        OR NEW.recovery_saved < OLD.recovery_saved
        OR NEW.recovery_confirmed < OLD.recovery_confirmed
        OR (OLD.confirmation IS NOT NULL AND NEW.confirmation IS NOT OLD.confirmation)
    BEGIN SELECT RAISE(ABORT, 'Pending registration outcome cannot be forgotten'); END;
    CREATE TRIGGER personal_registration_retained BEFORE DELETE ON personal_registration
    WHEN OLD.phase != 0
    BEGIN SELECT RAISE(ABORT, 'Attempted registration requires exact confirmation'); END;
    CREATE TRIGGER personal_registration_no_replace BEFORE INSERT ON personal_registration
    WHEN EXISTS (SELECT 1 FROM personal_registration)
    BEGIN SELECT RAISE(ABORT, 'Pending registration already exists'); END;
    CREATE TRIGGER personal_registration_blocks_identity BEFORE INSERT ON personal_server
    WHEN EXISTS (SELECT 1 FROM personal_registration)
    BEGIN SELECT RAISE(ABORT, 'Pending registration is not an admitted profile'); END;
    CREATE TRIGGER personal_registration_blocks_device_keys BEFORE INSERT ON device_key_pair
    WHEN EXISTS (SELECT 1 FROM personal_registration)
    BEGIN SELECT RAISE(ABORT, 'Pending registration keys belong only to its operation'); END;
    "#,
    // 13: retain dispatch evidence while allowing only explicitly confirmed unchanged retries.
    r#"
    ALTER TABLE personal_registration ADD COLUMN dispatch_generation INTEGER NOT NULL DEFAULT 0
        CHECK (dispatch_generation >= 0);
    ALTER TABLE personal_registration ADD COLUMN unchanged_generation INTEGER NOT NULL DEFAULT 0
        CHECK (unchanged_generation >= 0);
    ALTER TABLE personal_registration ADD COLUMN retry_not_before_ms INTEGER NOT NULL DEFAULT 0
        CHECK (retry_not_before_ms >= 0);
    UPDATE personal_registration SET dispatch_generation=1 WHERE phase>0;
    CREATE TRIGGER personal_registration_attempt_insert BEFORE INSERT ON personal_registration
    WHEN NEW.phase != 0 OR NEW.dispatch_generation != 0 OR NEW.unchanged_generation != 0
        OR NEW.retry_not_before_ms != 0
    BEGIN SELECT RAISE(ABORT, 'Registration must begin without dispatch evidence'); END;
    CREATE TRIGGER personal_registration_attempt_monotonic BEFORE UPDATE ON personal_registration
    WHEN NEW.dispatch_generation < OLD.dispatch_generation
        OR NEW.dispatch_generation - OLD.dispatch_generation > 1
        OR NEW.unchanged_generation < OLD.unchanged_generation
        OR NEW.unchanged_generation > NEW.dispatch_generation
        OR (NEW.dispatch_generation != OLD.dispatch_generation AND (
            NEW.phase != 1 OR OLD.phase=2 OR
            (OLD.phase=1 AND OLD.unchanged_generation != OLD.dispatch_generation)))
        OR (NEW.unchanged_generation != OLD.unchanged_generation AND (
            NEW.phase != 1 OR NEW.dispatch_generation != OLD.dispatch_generation OR
            NEW.unchanged_generation != NEW.dispatch_generation))
        OR (NEW.retry_not_before_ms != OLD.retry_not_before_ms AND
            NEW.unchanged_generation=OLD.unchanged_generation)
        OR (NEW.phase=0 AND NEW.dispatch_generation != 0)
        OR (NEW.phase>0 AND NEW.dispatch_generation=0)
    BEGIN SELECT RAISE(ABORT, 'Registration dispatch evidence cannot be replaced'); END;
    "#,
    // 14: Local owns the catalog; Account stores have an immutable, independent identity.
    r#"
    CREATE TABLE account_profiles (
        profile_id BLOB PRIMARY KEY CHECK (length(profile_id)=16),
        origin TEXT NOT NULL CHECK (length(origin) BETWEEN 1 AND 2048),
        account_id BLOB NOT NULL CHECK (length(account_id)=16),
        vault_id BLOB NOT NULL CHECK (length(vault_id)=16),
        device_id BLOB NOT NULL CHECK (length(device_id)=16),
        operation_id BLOB NOT NULL UNIQUE CHECK (length(operation_id)=16),
        payload BLOB NOT NULL CHECK (length(payload) BETWEEN 1 AND 262144),
        signature BLOB NOT NULL CHECK (length(signature)=64),
        confirmation BLOB NOT NULL CHECK (length(confirmation) BETWEEN 1 AND 1024),
        ready INTEGER NOT NULL DEFAULT 0 CHECK (ready IN (0,1)),
        UNIQUE(origin,account_id)
    ) STRICT, WITHOUT ROWID;
    CREATE TABLE profile_selection (
        singleton INTEGER PRIMARY KEY CHECK (singleton=1),
        generation INTEGER NOT NULL DEFAULT 0 CHECK (generation>=0),
        profile_id BLOB REFERENCES account_profiles(profile_id)
    ) STRICT;
    INSERT INTO profile_selection(singleton) VALUES(1);
    CREATE TABLE account_profile_binding (
        singleton INTEGER PRIMARY KEY CHECK (singleton=1),
        profile_id BLOB NOT NULL CHECK (length(profile_id)=16),
        origin TEXT NOT NULL CHECK (length(origin) BETWEEN 1 AND 2048),
        account_id BLOB NOT NULL CHECK (length(account_id)=16),
        vault_id BLOB NOT NULL CHECK (length(vault_id)=16),
        device_id BLOB NOT NULL CHECK (length(device_id)=16),
        operation_id BLOB NOT NULL CHECK (length(operation_id)=16),
        payload BLOB NOT NULL CHECK (length(payload) BETWEEN 1 AND 262144),
        signature BLOB NOT NULL CHECK (length(signature)=64),
        confirmation BLOB NOT NULL CHECK (length(confirmation) BETWEEN 1 AND 1024)
    ) STRICT;
    CREATE TRIGGER account_catalog_local BEFORE INSERT ON account_profiles
    WHEN EXISTS (SELECT 1 FROM account_profile_binding) OR EXISTS (SELECT 1 FROM personal_server)
        OR NEW.ready!=0 OR (SELECT count(*) FROM account_profiles)>=128
        OR EXISTS (SELECT 1 FROM account_profiles WHERE profile_id=NEW.profile_id
            OR operation_id=NEW.operation_id OR (origin=NEW.origin AND account_id=NEW.account_id))
    BEGIN SELECT RAISE(ABORT, 'Account catalogs belong to Local'); END;
    CREATE TRIGGER account_catalog_immutable BEFORE UPDATE ON account_profiles
    WHEN NEW.profile_id IS NOT OLD.profile_id OR NEW.origin IS NOT OLD.origin
        OR NEW.account_id IS NOT OLD.account_id OR NEW.vault_id IS NOT OLD.vault_id
        OR NEW.device_id IS NOT OLD.device_id OR NEW.operation_id IS NOT OLD.operation_id
        OR NEW.payload IS NOT OLD.payload OR NEW.signature IS NOT OLD.signature
        OR NEW.confirmation IS NOT OLD.confirmation OR NEW.ready < OLD.ready
    BEGIN SELECT RAISE(ABORT, 'Account catalog identity is immutable'); END;
    CREATE TRIGGER account_catalog_retained BEFORE DELETE ON account_profiles
    BEGIN SELECT RAISE(ABORT, 'Account profiles must be retained'); END;
    CREATE TRIGGER account_binding_empty BEFORE INSERT ON account_profile_binding
    WHEN EXISTS (SELECT 1 FROM account_profile_binding) OR EXISTS (SELECT 1 FROM account_profiles)
        OR EXISTS (SELECT 1 FROM objects) OR EXISTS (SELECT 1 FROM personal_server)
        OR EXISTS (SELECT 1 FROM device_key_pair) OR EXISTS (SELECT 1 FROM personal_registration)
        OR EXISTS (SELECT 1 FROM personal_pairing) OR EXISTS (SELECT 1 FROM personal_pairing_device)
        OR EXISTS (SELECT 1 FROM personal_pairing_attempts)
        OR NOT EXISTS (SELECT 1 FROM device WHERE device_id=NEW.device_id AND clock=0)
    BEGIN SELECT RAISE(ABORT, 'Account identity requires its own empty store'); END;
    CREATE TRIGGER account_binding_immutable BEFORE UPDATE ON account_profile_binding
    BEGIN SELECT RAISE(ABORT, 'Account profile binding is immutable'); END;
    CREATE TRIGGER account_binding_retained BEFORE DELETE ON account_profile_binding
    BEGIN SELECT RAISE(ABORT, 'Account profile binding must be retained'); END;
    CREATE TRIGGER profile_selection_monotonic BEFORE UPDATE ON profile_selection
    WHEN NEW.generation != OLD.generation+1
    BEGIN SELECT RAISE(ABORT, 'Profile owner generation must advance'); END;
    CREATE TRIGGER profile_selection_insert BEFORE INSERT ON profile_selection
    WHEN EXISTS (SELECT 1 FROM profile_selection)
    BEGIN SELECT RAISE(ABORT, 'Profile owner generation cannot be replaced'); END;
    CREATE TRIGGER profile_selection_retained BEFORE DELETE ON profile_selection
    BEGIN SELECT RAISE(ABORT, 'Profile owner generation must be retained'); END;
    CREATE TRIGGER account_profile_identity_insert BEFORE INSERT ON personal_server
    WHEN EXISTS (SELECT 1 FROM account_profiles) OR (EXISTS (SELECT 1 FROM account_profile_binding) AND
        (EXISTS (SELECT 1 FROM personal_server) OR NOT EXISTS (
            SELECT 1 FROM account_profile_binding WHERE origin=NEW.origin
                AND account_id=NEW.account_id AND vault_id=NEW.personal_vault_id)))
    BEGIN SELECT RAISE(ABORT, 'Account identity does not match its store'); END;
    CREATE TRIGGER account_profile_identity_update BEFORE UPDATE ON personal_server
    WHEN EXISTS (SELECT 1 FROM account_profile_binding) AND
        (NEW.origin IS NOT OLD.origin OR NEW.account_id IS NOT OLD.account_id
            OR NEW.personal_vault_id IS NOT OLD.personal_vault_id
            OR NEW.private_material IS NOT OLD.private_material)
    BEGIN SELECT RAISE(ABORT, 'Account profile identity cannot be replaced'); END;
    CREATE TRIGGER account_profile_identity_delete BEFORE DELETE ON personal_server
    WHEN EXISTS (SELECT 1 FROM account_profile_binding)
    BEGIN SELECT RAISE(ABORT, 'Account profile identity must be retained'); END;
    CREATE TRIGGER account_profile_device_update BEFORE UPDATE OF device_id ON device
    WHEN EXISTS (SELECT 1 FROM account_profile_binding) AND NEW.device_id IS NOT OLD.device_id
    BEGIN SELECT RAISE(ABORT, 'Account profile Device cannot be replaced'); END;
    CREATE TRIGGER account_profile_device_insert BEFORE INSERT ON device
    WHEN EXISTS (SELECT 1 FROM account_profile_binding)
    BEGIN SELECT RAISE(ABORT, 'Account profile Device already exists'); END;
    CREATE TRIGGER account_profile_device_delete BEFORE DELETE ON device
    WHEN EXISTS (SELECT 1 FROM account_profile_binding)
    BEGIN SELECT RAISE(ABORT, 'Account profile Device must be retained'); END;
    CREATE TRIGGER account_profile_keys_insert BEFORE INSERT ON device_key_pair
    WHEN EXISTS (SELECT 1 FROM account_profile_binding) AND
        (EXISTS (SELECT 1 FROM device_key_pair) OR NOT EXISTS (
            SELECT 1 FROM personal_server WHERE substr(private_material,2,32)=NEW.signing
                AND substr(private_material,34,32)=NEW.kem))
    BEGIN SELECT RAISE(ABORT, 'Account profile keys already exist'); END;
    CREATE TRIGGER account_profile_keys_update BEFORE UPDATE ON device_key_pair
    WHEN EXISTS (SELECT 1 FROM account_profile_binding) AND
        (NEW.signing IS NOT OLD.signing OR NEW.kem IS NOT OLD.kem)
    BEGIN SELECT RAISE(ABORT, 'Account profile keys cannot be replaced'); END;
    CREATE TRIGGER account_profile_keys_delete BEFORE DELETE ON device_key_pair
    WHEN EXISTS (SELECT 1 FROM account_profile_binding)
    BEGIN SELECT RAISE(ABORT, 'Account profile keys must be retained'); END;
    DROP TRIGGER personal_registration_retained;
    CREATE TRIGGER personal_registration_retained BEFORE DELETE ON personal_registration
    WHEN OLD.phase != 0 AND NOT (OLD.phase=2 AND EXISTS (
        SELECT 1 FROM account_profiles WHERE ready=1 AND payload=OLD.payload
            AND signature=OLD.account_signature AND confirmation=OLD.confirmation))
    BEGIN SELECT RAISE(ABORT, 'Registration requires confirmed independent installation'); END;
    "#,
    // 15: admit provenance fits its published bound; retain every immutable catalog binding.
    r#"
    DROP TRIGGER account_catalog_local;
    DROP TRIGGER account_catalog_immutable;
    DROP TRIGGER account_catalog_retained;
    DROP TRIGGER account_binding_empty;
    DROP TRIGGER account_binding_immutable;
    DROP TRIGGER account_binding_retained;
    DROP TRIGGER profile_selection_monotonic;
    DROP TRIGGER profile_selection_insert;
    DROP TRIGGER profile_selection_retained;
    DROP TRIGGER account_profile_identity_insert;
    DROP TRIGGER account_profile_identity_update;
    DROP TRIGGER account_profile_identity_delete;
    DROP TRIGGER account_profile_device_update;
    DROP TRIGGER account_profile_device_insert;
    DROP TRIGGER account_profile_device_delete;
    DROP TRIGGER account_profile_keys_insert;
    DROP TRIGGER account_profile_keys_update;
    DROP TRIGGER account_profile_keys_delete;
    DROP TRIGGER personal_registration_retained;
    CREATE TABLE profile_catalog_v14 AS SELECT * FROM account_profiles;
    CREATE TABLE profile_binding_v14 AS SELECT * FROM account_profile_binding;
    CREATE TABLE profile_selection_v14 AS SELECT * FROM profile_selection;
    DROP TABLE profile_selection;
    DROP TABLE account_profiles;
    DROP TABLE account_profile_binding;

    CREATE TABLE account_profiles (
        profile_id BLOB PRIMARY KEY CHECK (length(profile_id)=16),
        origin TEXT NOT NULL CHECK (length(origin) BETWEEN 1 AND 2048),
        account_id BLOB NOT NULL CHECK (length(account_id)=16),
        vault_id BLOB NOT NULL CHECK (length(vault_id)=16),
        device_id BLOB NOT NULL CHECK (length(device_id)=16),
        operation_id BLOB NOT NULL UNIQUE CHECK (length(operation_id)=16),
        payload BLOB NOT NULL CHECK (length(payload) BETWEEN 1 AND 4325376),
        signature BLOB NOT NULL CHECK (length(signature)=64),
        confirmation BLOB NOT NULL CHECK (length(confirmation) BETWEEN 1 AND 1024),
        ready INTEGER NOT NULL DEFAULT 0 CHECK (ready IN (0,1)),
        UNIQUE(origin,account_id)
    ) STRICT, WITHOUT ROWID;
    CREATE TABLE profile_selection (
        singleton INTEGER PRIMARY KEY CHECK (singleton=1),
        generation INTEGER NOT NULL DEFAULT 0 CHECK (generation>=0),
        profile_id BLOB REFERENCES account_profiles(profile_id)
    ) STRICT;
    CREATE TABLE account_profile_binding (
        singleton INTEGER PRIMARY KEY CHECK (singleton=1),
        profile_id BLOB NOT NULL CHECK (length(profile_id)=16),
        origin TEXT NOT NULL CHECK (length(origin) BETWEEN 1 AND 2048),
        account_id BLOB NOT NULL CHECK (length(account_id)=16),
        vault_id BLOB NOT NULL CHECK (length(vault_id)=16),
        device_id BLOB NOT NULL CHECK (length(device_id)=16),
        operation_id BLOB NOT NULL CHECK (length(operation_id)=16),
        payload BLOB NOT NULL CHECK (length(payload) BETWEEN 1 AND 4325376),
        signature BLOB NOT NULL CHECK (length(signature)=64),
        confirmation BLOB NOT NULL CHECK (length(confirmation) BETWEEN 1 AND 1024)
    ) STRICT;

    INSERT INTO account_profiles SELECT * FROM profile_catalog_v14;
    INSERT INTO account_profile_binding SELECT * FROM profile_binding_v14;
    INSERT INTO profile_selection SELECT * FROM profile_selection_v14;
    DROP TABLE profile_catalog_v14;
    DROP TABLE profile_binding_v14;
    DROP TABLE profile_selection_v14;
    CREATE TRIGGER account_catalog_local BEFORE INSERT ON account_profiles
    WHEN EXISTS (SELECT 1 FROM account_profile_binding) OR EXISTS (SELECT 1 FROM personal_server)
        OR NEW.ready!=0 OR (SELECT count(*) FROM account_profiles)>=128
        OR EXISTS (SELECT 1 FROM account_profiles WHERE profile_id=NEW.profile_id
            OR operation_id=NEW.operation_id OR (origin=NEW.origin AND account_id=NEW.account_id))
    BEGIN SELECT RAISE(ABORT, 'Account catalogs belong to Local'); END;
    CREATE TRIGGER account_catalog_immutable BEFORE UPDATE ON account_profiles
    WHEN NEW.profile_id IS NOT OLD.profile_id OR NEW.origin IS NOT OLD.origin
        OR NEW.account_id IS NOT OLD.account_id OR NEW.vault_id IS NOT OLD.vault_id
        OR NEW.device_id IS NOT OLD.device_id OR NEW.operation_id IS NOT OLD.operation_id
        OR NEW.payload IS NOT OLD.payload OR NEW.signature IS NOT OLD.signature
        OR NEW.confirmation IS NOT OLD.confirmation OR NEW.ready < OLD.ready
    BEGIN SELECT RAISE(ABORT, 'Account catalog identity is immutable'); END;
    CREATE TRIGGER account_catalog_retained BEFORE DELETE ON account_profiles
    BEGIN SELECT RAISE(ABORT, 'Account profiles must be retained'); END;
    CREATE TRIGGER account_binding_empty BEFORE INSERT ON account_profile_binding
    WHEN EXISTS (SELECT 1 FROM account_profile_binding) OR EXISTS (SELECT 1 FROM account_profiles)
        OR EXISTS (SELECT 1 FROM objects) OR EXISTS (SELECT 1 FROM personal_server)
        OR EXISTS (SELECT 1 FROM device_key_pair) OR EXISTS (SELECT 1 FROM personal_registration)
        OR EXISTS (SELECT 1 FROM personal_pairing) OR EXISTS (SELECT 1 FROM personal_pairing_device)
        OR EXISTS (SELECT 1 FROM personal_pairing_attempts)
        OR NOT EXISTS (SELECT 1 FROM device WHERE device_id=NEW.device_id AND clock=0)
    BEGIN SELECT RAISE(ABORT, 'Account identity requires its own empty store'); END;
    CREATE TRIGGER account_binding_immutable BEFORE UPDATE ON account_profile_binding
    BEGIN SELECT RAISE(ABORT, 'Account profile binding is immutable'); END;
    CREATE TRIGGER account_binding_retained BEFORE DELETE ON account_profile_binding
    BEGIN SELECT RAISE(ABORT, 'Account profile binding must be retained'); END;
    CREATE TRIGGER profile_selection_monotonic BEFORE UPDATE ON profile_selection
    WHEN NEW.generation != OLD.generation+1
    BEGIN SELECT RAISE(ABORT, 'Profile owner generation must advance'); END;
    CREATE TRIGGER profile_selection_insert BEFORE INSERT ON profile_selection
    WHEN EXISTS (SELECT 1 FROM profile_selection)
    BEGIN SELECT RAISE(ABORT, 'Profile owner generation cannot be replaced'); END;
    CREATE TRIGGER profile_selection_retained BEFORE DELETE ON profile_selection
    BEGIN SELECT RAISE(ABORT, 'Profile owner generation must be retained'); END;
    CREATE TRIGGER account_profile_identity_insert BEFORE INSERT ON personal_server
    WHEN EXISTS (SELECT 1 FROM account_profiles) OR (EXISTS (SELECT 1 FROM account_profile_binding) AND
        (EXISTS (SELECT 1 FROM personal_server) OR NOT EXISTS (
            SELECT 1 FROM account_profile_binding WHERE origin=NEW.origin
                AND account_id=NEW.account_id AND vault_id=NEW.personal_vault_id)))
    BEGIN SELECT RAISE(ABORT, 'Account identity does not match its store'); END;
    CREATE TRIGGER account_profile_identity_update BEFORE UPDATE ON personal_server
    WHEN EXISTS (SELECT 1 FROM account_profile_binding) AND
        (NEW.origin IS NOT OLD.origin OR NEW.account_id IS NOT OLD.account_id
            OR NEW.personal_vault_id IS NOT OLD.personal_vault_id
            OR NEW.private_material IS NOT OLD.private_material)
    BEGIN SELECT RAISE(ABORT, 'Account profile identity cannot be replaced'); END;
    CREATE TRIGGER account_profile_identity_delete BEFORE DELETE ON personal_server
    WHEN EXISTS (SELECT 1 FROM account_profile_binding)
    BEGIN SELECT RAISE(ABORT, 'Account profile identity must be retained'); END;
    CREATE TRIGGER account_profile_device_update BEFORE UPDATE OF device_id ON device
    WHEN EXISTS (SELECT 1 FROM account_profile_binding) AND NEW.device_id IS NOT OLD.device_id
    BEGIN SELECT RAISE(ABORT, 'Account profile Device cannot be replaced'); END;
    CREATE TRIGGER account_profile_device_insert BEFORE INSERT ON device
    WHEN EXISTS (SELECT 1 FROM account_profile_binding)
    BEGIN SELECT RAISE(ABORT, 'Account profile Device already exists'); END;
    CREATE TRIGGER account_profile_device_delete BEFORE DELETE ON device
    WHEN EXISTS (SELECT 1 FROM account_profile_binding)
    BEGIN SELECT RAISE(ABORT, 'Account profile Device must be retained'); END;
    CREATE TRIGGER account_profile_keys_insert BEFORE INSERT ON device_key_pair
    WHEN EXISTS (SELECT 1 FROM account_profile_binding) AND
        (EXISTS (SELECT 1 FROM device_key_pair) OR NOT EXISTS (
            SELECT 1 FROM personal_server WHERE substr(private_material,2,32)=NEW.signing
                AND substr(private_material,34,32)=NEW.kem))
    BEGIN SELECT RAISE(ABORT, 'Account profile keys already exist'); END;
    CREATE TRIGGER account_profile_keys_update BEFORE UPDATE ON device_key_pair
    WHEN EXISTS (SELECT 1 FROM account_profile_binding) AND
        (NEW.signing IS NOT OLD.signing OR NEW.kem IS NOT OLD.kem)
    BEGIN SELECT RAISE(ABORT, 'Account profile keys cannot be replaced'); END;
    CREATE TRIGGER account_profile_keys_delete BEFORE DELETE ON device_key_pair
    WHEN EXISTS (SELECT 1 FROM account_profile_binding)
    BEGIN SELECT RAISE(ABORT, 'Account profile keys must be retained'); END;
    CREATE TRIGGER personal_registration_retained BEFORE DELETE ON personal_registration
    WHEN OLD.phase != 0 AND NOT (OLD.phase=2 AND EXISTS (
        SELECT 1 FROM account_profiles WHERE ready=1 AND payload=OLD.payload
            AND signature=OLD.account_signature AND confirmation=OLD.confirmation))
    BEGIN SELECT RAISE(ABORT, 'Registration requires confirmed independent installation'); END;
    "#,
    // 16: password login retains exact independent admission identity and terminal outcome.
    r#"
    CREATE TABLE personal_password_login (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
        payload BLOB NOT NULL CHECK(length(payload) BETWEEN 1 AND 4325376),
        account_signature BLOB NOT NULL CHECK(length(account_signature)=64),
        private_material BLOB NOT NULL CHECK(length(private_material)=193),
        snapshot BLOB NOT NULL CHECK(length(snapshot) BETWEEN 1 AND 9437184),
        token BLOB NOT NULL CHECK(length(token)=32),
        expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>0),
        restart_required INTEGER NOT NULL DEFAULT 0 CHECK(restart_required IN(0,1)),
        phase INTEGER NOT NULL DEFAULT 0 CHECK(phase IN(0,1,2)),
        confirmation BLOB CHECK(confirmation IS NULL OR length(confirmation) BETWEEN 1 AND 1024),
        dispatch_generation INTEGER NOT NULL DEFAULT 0 CHECK(dispatch_generation>=0),
        unchanged_generation INTEGER NOT NULL DEFAULT 0 CHECK(unchanged_generation>=0 AND unchanged_generation<=dispatch_generation),
        retry_not_before_ms INTEGER NOT NULL DEFAULT 0 CHECK(retry_not_before_ms>=0),
        CHECK((phase=2)=(confirmation IS NOT NULL)),
        CHECK((phase=0)=(dispatch_generation=0))
    ) STRICT;
    CREATE TRIGGER password_login_insert BEFORE INSERT ON personal_password_login
    WHEN EXISTS(SELECT 1 FROM personal_password_login) OR EXISTS(SELECT 1 FROM personal_registration)
        OR EXISTS(SELECT 1 FROM personal_server) OR EXISTS(SELECT 1 FROM personal_admission)
        OR EXISTS(SELECT 1 FROM device_key_pair) OR EXISTS(SELECT 1 FROM account_profile_binding)
        OR EXISTS(SELECT 1 FROM personal_pairing) OR EXISTS(SELECT 1 FROM personal_pairing_device)
        OR EXISTS(SELECT 1 FROM personal_pairing_attempts)
        OR NEW.phase!=0 OR NEW.dispatch_generation!=0 OR NEW.unchanged_generation!=0
    BEGIN SELECT RAISE(ABORT,'Password login requires the original Local namespace'); END;
    CREATE TRIGGER password_login_immutable BEFORE UPDATE ON personal_password_login
    WHEN NEW.payload IS NOT OLD.payload OR NEW.account_signature IS NOT OLD.account_signature
        OR NEW.private_material IS NOT OLD.private_material OR NEW.snapshot IS NOT OLD.snapshot
        OR NEW.token IS NOT OLD.token OR NEW.expires_at_ms IS NOT OLD.expires_at_ms
        OR NEW.restart_required<OLD.restart_required
        OR (NEW.restart_required!=OLD.restart_required AND (NEW.phase!=1 OR NEW.unchanged_generation!=NEW.dispatch_generation))
        OR NEW.phase<OLD.phase OR NEW.phase>OLD.phase+1
        OR (OLD.confirmation IS NOT NULL AND NEW.confirmation IS NOT OLD.confirmation)
        OR NEW.dispatch_generation<OLD.dispatch_generation
        OR NEW.dispatch_generation-OLD.dispatch_generation>1
        OR NEW.unchanged_generation<OLD.unchanged_generation
        OR (NEW.dispatch_generation!=OLD.dispatch_generation AND
            (NEW.phase!=1 OR OLD.phase=2 OR (OLD.phase=1 AND OLD.dispatch_generation!=OLD.unchanged_generation)))
        OR (NEW.unchanged_generation!=OLD.unchanged_generation AND
            (NEW.phase!=1 OR NEW.dispatch_generation!=OLD.dispatch_generation OR NEW.unchanged_generation!=NEW.dispatch_generation))
        OR (NEW.retry_not_before_ms!=OLD.retry_not_before_ms AND NEW.unchanged_generation=OLD.unchanged_generation)
    BEGIN SELECT RAISE(ABORT,'Password admission outcome cannot be replaced'); END;
    CREATE TRIGGER password_login_retained BEFORE DELETE ON personal_password_login
    WHEN NOT(OLD.phase=0 OR (OLD.phase=1 AND OLD.dispatch_generation=OLD.unchanged_generation)
        OR (OLD.phase=2 AND EXISTS(SELECT 1 FROM account_profiles WHERE ready=1
            AND payload=OLD.payload AND signature=OLD.account_signature AND confirmation=OLD.confirmation)))
    BEGIN SELECT RAISE(ABORT,'Unknown device admission must retain its identity'); END;
    CREATE TRIGGER password_login_blocks_binding BEFORE INSERT ON account_profile_binding
    WHEN EXISTS(SELECT 1 FROM personal_password_login)
    BEGIN SELECT RAISE(ABORT,'Password admission requires a separate Account store'); END;
    CREATE TRIGGER password_login_blocks_registration BEFORE INSERT ON personal_registration
    WHEN EXISTS(SELECT 1 FROM personal_password_login)
    BEGIN SELECT RAISE(ABORT,'Password admission is pending'); END;
    CREATE TRIGGER password_login_blocks_identity BEFORE INSERT ON personal_server
    WHEN EXISTS(SELECT 1 FROM personal_password_login)
    BEGIN SELECT RAISE(ABORT,'Password admission is not current authority'); END;
    CREATE TRIGGER password_login_blocks_keys BEFORE INSERT ON device_key_pair
    WHEN EXISTS(SELECT 1 FROM personal_password_login)
    BEGIN SELECT RAISE(ABORT,'Password admission owns only its pending keys'); END;
    CREATE TABLE password_login_bootstrap(
        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
        snapshot BLOB NOT NULL CHECK(length(snapshot) BETWEEN 1 AND 9437184)
    ) STRICT;
    CREATE TRIGGER login_bootstrap_insert BEFORE INSERT ON password_login_bootstrap
    WHEN EXISTS(SELECT 1 FROM password_login_bootstrap) OR NOT EXISTS(SELECT 1 FROM account_profile_binding)
    BEGIN SELECT RAISE(ABORT,'Login bootstrap belongs to its independent Account store'); END;
    CREATE TRIGGER login_bootstrap_immutable BEFORE UPDATE ON password_login_bootstrap
    BEGIN SELECT RAISE(ABORT,'Original login bootstrap is immutable'); END;
    CREATE TRIGGER login_bootstrap_retained BEFORE DELETE ON password_login_bootstrap
    BEGIN SELECT RAISE(ABORT,'Original login bootstrap must be retained'); END;
    "#,
    // 17: retain one explicit team creation until its original outcome is resolved.
    r#"
    CREATE TABLE team_creation (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1),
        origin TEXT NOT NULL,
        account_id BLOB NOT NULL CHECK(length(account_id)=16),
        operation_id BLOB NOT NULL CHECK(length(operation_id)=16),
        payload BLOB NOT NULL CHECK(length(payload) BETWEEN 1 AND 1024),
        phase INTEGER NOT NULL CHECK(phase IN(0,1,2)),
        first_attempt_ms INTEGER CHECK(first_attempt_ms IS NULL OR first_attempt_ms>0),
        response BLOB CHECK(response IS NULL OR length(response) BETWEEN 1 AND 4096),
        CHECK((phase=2)=(response IS NOT NULL)),
        CHECK(phase=0 OR first_attempt_ms IS NOT NULL)
    ) STRICT;
    "#,
];
