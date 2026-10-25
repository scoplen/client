// SPDX-License-Identifier: Apache-2.0
//! Two real consumer processes share only their owned encrypted store and native key slot.

use std::{
    fs::{File, OpenOptions},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;
use zeroize::Zeroize as _;

use super::*;
use crate::{
    local_data::{LocalData, Status},
    local_key::Protection,
    personal_server::retained::RetainedAccount,
};

const TEST: &str = "personal_server::live_server::process_restart::live_personal_process_restart";
const RUN_ENV: &str = "SCOPLEN_PERSONAL_RESTART_RUN";
const PHASE_ENV: &str = "SCOPLEN_PERSONAL_RESTART_PHASE";
const MAX_WAIT: u64 = 15 * 60;
const PHASE_LIMIT: Duration = Duration::from_secs(120);
const DEVICE_NAME: &str = "Process restart integration device";
const INITIAL_NAME: &str = "Host before process exit";
const EDITED_NAME: &str = "Host edited before process exit";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Run {
    #[serde(with = "receipt_uuid")]
    owner: Uuid,
    root: PathBuf,
    data: PathBuf,
    executable: PathBuf,
    origin: String,
    started_at: u64,
    deadline: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Enrolled {
    #[serde(with = "receipt_uuid")]
    owner: Uuid,
    process: u32,
    #[serde(with = "receipt_uuid")]
    account: Uuid,
    #[serde(with = "receipt_uuid")]
    vault: Uuid,
    #[serde(with = "receipt_uuid")]
    device: Uuid,
    identity: [u8; 32],
    access: [u8; 32],
    access_expires_at: u64,
    refresh_expires_at: u64,
    generation: i64,
    scope: String,
    #[serde(with = "receipt_uuid")]
    host: Uuid,
    host_digest: [u8; 32],
    #[serde(with = "receipt_uuid")]
    local_only: Uuid,
    local_only_digest: [u8; 32],
    cursor: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Resumed {
    #[serde(with = "receipt_uuid")]
    owner: Uuid,
    process: u32,
    generation: i64,
    refresh_expires_at: u64,
    cursor: String,
}

mod receipt_uuid {
    use super::*;

    pub(super) fn serialize<S: serde::Serializer>(
        id: &Uuid,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_str(id)
    }

    pub(super) fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Uuid, D::Error> {
        String::deserialize(deserializer)?.parse().map_err(serde::de::Error::custom)
    }
}

fn read_json<T: DeserializeOwned>(path: &Path) -> T {
    serde_json::from_slice(&Zeroizing::new(bounded_file(path, 8_192)))
        .expect("valid bounded private process receipt")
}

fn private_file(path: &Path) -> File {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path).expect("create unique private process artifact")
}

fn write_json(path: &Path, value: &impl Serialize) {
    let mut file = private_file(path);
    serde_json::to_writer(&mut file, value).expect("write bounded process receipt");
    file.sync_all().expect("persist process receipt before normal exit");
}

fn deployment() -> Deployment {
    let descriptor = std::env::var_os("SCOPLEN_LIVE_PERSONAL_DEPLOYMENT")
        .expect("set SCOPLEN_LIVE_PERSONAL_DEPLOYMENT to a fresh private deployment descriptor");
    let value: Deployment = read_json(Path::new(&descriptor));
    assert!(value.disposable, "the process check consumes a disposable invitation once");
    assert!(
        value
            .origin
            .strip_prefix("https://localhost:")
            .and_then(|port| port.parse::<u16>().ok())
            .is_some_and(|port| port != 0),
        "the process check requires a loopback HTTPS deployment"
    );
    value
}

impl Run {
    fn verify(&self) {
        assert!(!self.owner.is_nil());
        assert_eq!(self.root.canonicalize().expect("owned root exists"), self.root);
        assert_eq!(self.data, self.root.join("data"));
        assert_eq!(self.data.canonicalize().expect("owned data directory exists"), self.data);
        assert!(!std::fs::symlink_metadata(&self.data).expect("owned data metadata").is_symlink());
        assert_eq!(bounded_file(&self.root.join("owner"), 36), self.owner.to_string().as_bytes());
        assert_eq!(
            std::env::current_exe().expect("consumer executable").canonicalize().unwrap(),
            self.executable
        );
        assert!(self.started_at <= now().unwrap() && now().unwrap() < self.deadline);
        assert_eq!(self.deadline.checked_sub(self.started_at), Some(MAX_WAIT + 240));
    }
}

struct OwnedRun {
    directory: Option<tempfile::TempDir>,
    run: Run,
    cleanup_attempted: bool,
    consumer_live: Arc<AtomicBool>,
}

impl OwnedRun {
    fn create(mut deployment: Deployment) -> Self {
        deployment.invitation_url.zeroize();
        let mut builder = tempfile::Builder::new();
        builder.prefix("scoplen-personal-restart-");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            builder.permissions(std::fs::Permissions::from_mode(0o700));
        }
        #[cfg(target_os = "windows")]
        let parent = PathBuf::from(
            std::env::var_os("LOCALAPPDATA").expect("private native application-data directory"),
        );
        #[cfg(target_os = "macos")]
        let parent = std::env::temp_dir();
        let directory = builder.tempdir_in(parent).expect("private owned process-test directory");
        let root = directory.path().canonicalize().expect("canonical owned root");
        std::fs::create_dir(root.join("data")).expect("create owned native data directory");
        let started_at = now().unwrap();
        let run = Run {
            owner: scoplen_model::new_uuid_v7().expect("test ownership id"),
            data: root.join("data").canonicalize().expect("canonical owned data directory"),
            root,
            executable: std::env::current_exe().unwrap().canonicalize().unwrap(),
            origin: deployment.origin,
            started_at,
            deadline: started_at + MAX_WAIT + 240,
        };
        let mut marker = private_file(&run.root.join("owner"));
        marker.write_all(run.owner.to_string().as_bytes()).unwrap();
        marker.sync_all().unwrap();
        private_file(&run.root.join("server-ca.pem"))
            .write_all(&bounded_file(&deployment.ca_certificate, 65_536))
            .expect("retain only the disposable server CA");
        write_json(&run.root.join("run.json"), &run);
        run.verify();
        // Register exact-slot cleanup before either child can create a native key.
        Self {
            directory: Some(directory),
            run,
            cleanup_attempted: false,
            consumer_live: Arc::new(AtomicBool::new(false)),
        }
    }

    fn cleanup(&mut self) -> Result<(), &'static str> {
        assert!(!self.cleanup_attempted, "owned native cleanup must not be retried");
        self.cleanup_attempted = true;
        if self.directory.is_none() {
            return Ok(());
        }
        if self.consumer_live.load(Ordering::Acquire) {
            return Err("consumer exit is unconfirmed; owned slot and artifacts retained");
        }
        if self.run.data != self.run.root.join("data")
            || self.run.data.canonicalize().ok().as_ref() != Some(&self.run.data)
            || std::fs::read(self.run.root.join("owner")).ok().as_deref()
                != Some(self.run.owner.to_string().as_bytes())
        {
            return Err("owned native slot binding changed; private artifacts retained");
        }
        let keystore = scoplen_client_platform::keystore::local_key_store(&self.run.data)
            .ok_or("real native key provider unavailable")?;
        keystore.delete().map_err(|_| "owned native key deletion failed")?;
        if keystore.load().map_err(|_| "owned native key deletion check failed")?.is_some() {
            return Err("owned native key remains readable");
        }
        Ok(())
    }

    fn finish(mut self) {
        self.cleanup().expect("remove only the exited consumers' owned native slot");
        self.directory.take().unwrap().close().expect("remove successful private test artifacts");
    }
}

impl Drop for OwnedRun {
    fn drop(&mut self) {
        if self.directory.is_some() {
            let cleanup_failed = self.cleanup_attempted || self.cleanup().is_err();
            if (cleanup_failed || std::thread::panicking())
                && let Some(directory) = self.directory.take()
            {
                let _ = directory.keep();
                eprintln!("Process check failed; private artifacts retained without retrying.");
            }
        }
    }
}

struct Consumer {
    process: Child,
    live: Arc<AtomicBool>,
}

impl Consumer {
    fn start(owned: &OwnedRun, phase: &str) -> Self {
        let run = &owned.run;
        run.verify();
        assert!(!owned.consumer_live.load(Ordering::Acquire));
        let log = private_file(&run.root.join(format!("{phase}.log")));
        let process = Command::new(&run.executable)
            .args([TEST, "--exact", "--nocapture", "--test-threads=1"])
            .env(RUN_ENV, run.root.join("run.json"))
            .env(PHASE_ENV, phase)
            .stdin(Stdio::null())
            .stdout(log.try_clone().expect("private child stdout"))
            .stderr(log)
            .spawn()
            .expect("start one real consumer process with the inherited native user context");
        owned.consumer_live.store(true, Ordering::Release);
        Self { process, live: owned.consumer_live.clone() }
    }

    async fn wait(mut self, deadline: u64) -> u32 {
        let process = self.process.id();
        let started = Instant::now();
        loop {
            if let Some(status) = self.process.try_wait().expect("read consumer exit") {
                self.live.store(false, Ordering::Release);
                assert!(status.success(), "consumer failed; no operation was retried");
                return process;
            }
            assert!(
                started.elapsed() < PHASE_LIMIT && now().unwrap() < deadline,
                "consumer exceeded its bounded phase; no operation was retried"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

impl Drop for Consumer {
    fn drop(&mut self) {
        // Also reap a timed-out child before the older owned-slot guard is dropped.
        if self.live.load(Ordering::Acquire) {
            let exited = self.process.try_wait().ok().flatten().is_some()
                || if self.process.kill().is_ok() {
                    self.process.wait().is_ok()
                } else {
                    self.process.try_wait().ok().flatten().is_some()
                };
            if exited {
                self.live.store(false, Ordering::Release);
            }
        }
    }
}

fn wait_seconds(run: &Run, receipt: &Enrolled, current: u64) -> Option<u64> {
    if receipt.owner != run.owner
        || receipt.process == 0
        || receipt.process == std::process::id()
        || receipt.generation < 1
        || receipt.access_expires_at <= run.started_at
        || receipt.access_expires_at > run.started_at.checked_add(MAX_WAIT)?
        || receipt.refresh_expires_at <= receipt.access_expires_at
        || receipt.refresh_expires_at <= current
        || current >= run.deadline
    {
        return None;
    }
    Some(receipt.access_expires_at.saturating_sub(60).saturating_sub(current))
}

fn identity_digest(store: &Store) -> [u8; 32] {
    let identity = record(store).expect("retained native identity");
    let retained = RetainedAccount::load(store, &identity)
        .expect("retained secrets still match the signed public identity");
    let mut digest = Sha256::new();
    digest.update(retained.signing_public);
    digest.update(retained.kem_public);
    digest.update(retained.certificate.encode().expect("signed device certificate"));
    digest.update(retained.anchor);
    digest.finalize().into()
}

fn object_digest(store: &Store, object: Uuid) -> [u8; 32] {
    Sha256::digest(store.get(object).unwrap().expect("retained host").encode().unwrap()).into()
}

fn access_digest(store: &Store) -> [u8; 32] {
    let access = store.personal_access_token(now().unwrap()).unwrap().expect("live access");
    Sha256::digest(access.as_bytes()).into()
}

fn open(run: &Run) -> LocalData {
    let data =
        LocalData::start(&run.data, scoplen_client_platform::keystore::local_key_store(&run.data))
            .expect("open the owned encrypted store using the actual platform provider");
    assert_eq!(data.status(), Status::Open { protection: Protection::Keystore });
    data
}

fn manager(run: &Run) -> PersonalServer {
    PersonalServer {
        operation: Mutex::new(()),
        transport: Ok(trusted_transport(&bounded_file(&run.root.join("server-ca.pem"), 65_536))),
        pairing: Default::default(),
    }
}

fn host(store: &Store, name: &str) -> scoplen_model::Object {
    store
        .write(LocalWrite {
            id: None,
            object_type: ObjectType::HOST,
            fields: vec![
                (FieldPath::Field(1), Value::Text(name.into())),
                (FieldPath::Field(2), Value::Text("host.example.com".into())),
            ],
        })
        .expect("write an ordinary local host through the production store")
}

async fn enroll(run: &Run) {
    let mut deployment = deployment();
    assert_eq!(deployment.origin, run.origin);
    assert!(
        !run.data.join(crate::local_key::STORE_FILE).exists(),
        "first process needs a fresh store"
    );
    let local = open(run);
    let store = local.store().expect("real provider opened the encrypted store");
    let object = host(&store, INITIAL_NAME);
    let unshared = host(&store, "Local-only restart host");
    let manager = manager(run);
    let invitation = Zeroizing::new(std::mem::take(&mut deployment.invitation_url));
    manager.prepare(store.clone(), invitation, DEVICE_NAME.into()).await.expect("prepare identity");
    manager.save_recovery_key(store.clone(), run.root.join("recovery.txt")).await.unwrap();
    manager.confirm_recovery_key(store.clone()).await.unwrap();
    assert_eq!(
        manager.submit(store.clone()).await.unwrap().phase,
        PersonalServerPhase::Authenticated
    );
    manager.bootstrap_sync(store.clone()).await.expect("verify real signed Personal keys");
    let account = manager.query_account(store.clone()).await.expect("retain signed account view");
    assert_eq!(account.devices.len(), 1);
    assert_eq!(account.devices[0].id, store.device_id().to_string());
    let settings = PersonalInventorySettings::default();
    let before = settings.status(&store).unwrap();
    assert_eq!(before.pending, 0, "setup never silently adopts existing hosts");
    assert!(before.objects.iter().all(|object| !object.personal));
    let review = settings.preview(&store, vec![object.id.to_string()]).unwrap();
    assert!(review.missing.is_empty() && review.token.is_some());
    let synced = settings.synchronize(&manager, store.clone(), review.token).await.unwrap();
    assert_eq!(synced.uploaded, 1);
    assert!(synced.downloaded >= 1 && !synced.more);
    let saved = settings.status(&store).unwrap();
    assert_eq!(saved.pending, 0);
    assert_eq!(saved.applied_cursor, saved.acknowledged_cursor);
    assert_ne!(saved.applied_cursor, "0");
    store
        .write(LocalWrite {
            id: Some(object.id),
            object_type: ObjectType::HOST,
            fields: vec![(FieldPath::Field(1), Value::Text(EDITED_NAME.into()))],
        })
        .expect("leave one real adopted edit in the durable offline outbox");
    let queued = settings.status(&store).unwrap();
    assert_eq!(queued.pending, 1);
    assert_eq!(queued.applied_cursor, saved.applied_cursor);
    assert_eq!(queued.acknowledged_cursor, saved.acknowledged_cursor);
    let identity = record(&store).unwrap();
    assert!(identity.refresh_available && identity.refresh_retry_at.is_none());
    let receipt = Enrolled {
        owner: run.owner,
        process: std::process::id(),
        account: identity.account_id,
        vault: identity.personal_vault_id,
        device: store.device_id(),
        identity: identity_digest(&store),
        access: access_digest(&store),
        access_expires_at: identity.access_expires_at.unwrap(),
        refresh_expires_at: identity.refresh_expires_at.unwrap(),
        generation: identity.auth_generation,
        scope: identity.auth_scope.unwrap(),
        host: object.id,
        host_digest: object_digest(&store, object.id),
        local_only: unshared.id,
        local_only_digest: object_digest(&store, unshared.id),
        cursor: queued.applied_cursor,
    };
    assert!(receipt.access_expires_at > now().unwrap() + 60);
    write_json(&run.root.join("enrolled.json"), &receipt);
    // Returning drops every Store, LocalData and transport before this OS process exits.
}

async fn resume(run: &Run) {
    let before: Enrolled = read_json(&run.root.join("enrolled.json"));
    assert_eq!(wait_seconds(run, &before, now().unwrap()), Some(0));
    assert_ne!(before.process, std::process::id());
    let local = open(run);
    let store = local.store().expect("fresh native provider recovered the existing database key");
    let manager = manager(run);
    let identity = record(&store).unwrap();
    assert_eq!(identity.account_id, before.account);
    assert_eq!(identity.personal_vault_id, before.vault);
    assert_eq!(store.device_id(), before.device);
    assert_eq!(identity_digest(&store), before.identity);
    assert_eq!(identity.auth_generation, before.generation);
    assert_eq!(identity.access_expires_at, Some(before.access_expires_at));
    assert_eq!(identity.refresh_expires_at, Some(before.refresh_expires_at));
    assert!(identity.refresh_available && identity.refresh_retry_at.is_none());
    assert!(manager.load_sync_bootstrap(&store).unwrap().is_some());
    assert_eq!(
        manager.account_snapshot(&store).unwrap().unwrap().account_id,
        before.account.to_string()
    );
    let settings = PersonalInventorySettings::default();
    let queued = settings.status(&store).unwrap();
    assert_eq!(queued.pending, 1);
    assert_eq!(queued.applied_cursor, before.cursor);
    assert_eq!(queued.acknowledged_cursor, before.cursor);
    assert_eq!(object_digest(&store, before.host), before.host_digest);
    assert_eq!(object_digest(&store, before.local_only), before.local_only_digest);

    // This is the first network operation of the new consumer. It must use the
    // persisted refresh directly, with no fresh challenge or invitation replay.
    let account =
        manager.query_account(store.clone()).await.expect("refresh after real process exit");
    assert_eq!(account.account_id, before.account.to_string());
    assert_eq!(account.devices.len(), 1);
    assert_eq!(account.devices[0].id, before.device.to_string());
    assert_eq!(account.devices[0].name, DEVICE_NAME);
    assert!(account.devices[0].current);
    let rotated = record(&store).unwrap();
    assert_eq!(identity_digest(&store), before.identity);
    assert!(rotated.auth_generation > before.generation);
    assert!(rotated.refresh_available && rotated.refresh_retry_at.is_none());
    assert_eq!(rotated.auth_scope.as_deref(), Some(before.scope.as_str()));
    assert!(rotated.access_expires_at.unwrap() > now().unwrap() + 60);
    assert!(rotated.refresh_expires_at.unwrap() <= before.refresh_expires_at);
    assert!(rotated.refresh_expires_at.unwrap() > now().unwrap());
    assert_ne!(access_digest(&store), before.access);
    let expected = store.get(before.host).unwrap().unwrap();
    let synced = settings.synchronize(&manager, store.clone(), None).await.unwrap();
    assert_eq!(synced.uploaded, 1);
    assert!(synced.downloaded >= 1 && !synced.more);
    assert_eq!(store.get(before.host).unwrap(), Some(expected));
    let saved = settings.status(&store).unwrap();
    assert_eq!(saved.pending, 0);
    assert_eq!(saved.applied_cursor, saved.acknowledged_cursor);
    assert!(saved.applied_cursor.parse::<u64>().unwrap() > before.cursor.parse::<u64>().unwrap());
    assert_eq!(object_digest(&store, before.local_only), before.local_only_digest);
    assert!(
        !saved
            .objects
            .iter()
            .find(|object| object.id == before.local_only.to_string())
            .unwrap()
            .personal
    );
    let history =
        settings.query_history(&manager, store.clone(), before.host.to_string()).await.unwrap();
    assert_eq!(
        history.versions.len(),
        2,
        "real remote history contains exactly both signed versions"
    );
    assert_eq!(history.versions[0].object.name.as_deref(), Some(INITIAL_NAME));
    assert_eq!(history.versions[1].object.name.as_deref(), Some(EDITED_NAME));
    assert_eq!(history.versions[1].sequence, saved.applied_cursor);
    write_json(
        &run.root.join("resumed.json"),
        &Resumed {
            owner: run.owner,
            process: std::process::id(),
            generation: rotated.auth_generation,
            refresh_expires_at: rotated.refresh_expires_at.unwrap(),
            cursor: saved.applied_cursor,
        },
    );
}

#[tokio::test]
async fn live_personal_process_restart() {
    if let Some(path) = std::env::var_os(RUN_ENV) {
        let run: Run = read_json(Path::new(&path));
        assert_eq!(Path::new(&path).canonicalize().unwrap(), run.root.join("run.json"));
        run.verify();
        match std::env::var(PHASE_ENV).as_deref() {
            Ok("enroll") => enroll(&run).await,
            Ok("resume") => resume(&run).await,
            _ => panic!("unknown consumer phase; no operation was sent"),
        }
        return;
    }
    assert!(std::env::var_os(PHASE_ENV).is_none(), "phase requires an owned controller receipt");
    let owned = OwnedRun::create(deployment());
    let run = &owned.run;
    let first = Consumer::start(&owned, "enroll").wait(run.deadline).await;
    let enrolled: Enrolled = read_json(&run.root.join("enrolled.json"));
    assert_eq!(enrolled.process, first);
    let started = Instant::now();
    loop {
        let remaining = wait_seconds(run, &enrolled, now().unwrap())
            .expect("receipt must bound a genuine live access lifetime");
        if remaining == 0 {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(MAX_WAIT),
            "real access wait exceeded its bound"
        );
        tokio::time::sleep(Duration::from_secs(remaining.min(1))).await;
    }
    let second = Consumer::start(&owned, "resume").wait(run.deadline).await;
    let resumed: Resumed = read_json(&run.root.join("resumed.json"));
    assert_eq!(resumed.owner, run.owner);
    assert_eq!(resumed.process, second);
    assert_ne!(first, second);
    assert!(resumed.generation > enrolled.generation);
    assert!(resumed.refresh_expires_at <= enrolled.refresh_expires_at);
    assert!(resumed.cursor.parse::<u64>().unwrap() > enrolled.cursor.parse::<u64>().unwrap());
    owned.finish();
}

#[test]
fn restart_receipt_rejects_wrong_owner_overlong_expiry_and_expired_family() {
    let owner = Uuid::from_u128(1);
    let run = Run {
        owner,
        root: PathBuf::new(),
        data: PathBuf::new(),
        executable: PathBuf::new(),
        origin: "https://localhost:443".into(),
        started_at: 1_000,
        deadline: 1_000 + MAX_WAIT + 240,
    };
    let receipt = Enrolled {
        owner,
        process: std::process::id().wrapping_add(1).max(1),
        account: Uuid::from_u128(2),
        vault: Uuid::from_u128(3),
        device: Uuid::from_u128(4),
        identity: [0; 32],
        access: [0; 32],
        access_expires_at: 1_600,
        refresh_expires_at: 5_000,
        generation: 2,
        scope: "sync".into(),
        host: Uuid::from_u128(5),
        host_digest: [0; 32],
        local_only: Uuid::from_u128(6),
        local_only_digest: [0; 32],
        cursor: "1".into(),
    };
    let mut receipt: Enrolled =
        serde_json::from_slice(&serde_json::to_vec(&receipt).unwrap()).unwrap();
    assert_eq!(wait_seconds(&run, &receipt, 1_001), Some(539));
    assert_eq!(wait_seconds(&run, &receipt, 1_540), Some(0));
    receipt.owner = Uuid::nil();
    assert_eq!(wait_seconds(&run, &receipt, 1_001), None);
    receipt.owner = owner;
    receipt.access_expires_at = run.started_at + MAX_WAIT + 1;
    assert_eq!(wait_seconds(&run, &receipt, 1_001), None);
    receipt.access_expires_at = 1_600;
    assert_eq!(wait_seconds(&run, &receipt, run.deadline), None);
    receipt.refresh_expires_at = 1_800;
    assert_eq!(wait_seconds(&run, &receipt, 1_800), None);
    receipt.refresh_expires_at = 5_000;
    receipt.process = std::process::id();
    assert_eq!(wait_seconds(&run, &receipt, 1_540), None);
}
