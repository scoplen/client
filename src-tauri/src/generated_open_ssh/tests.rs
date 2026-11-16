// SPDX-License-Identifier: Apache-2.0

use super::*;
use scoplen_client_core::{
    inventory::{HostDetails, NewHost, SignIn},
    repository::{Host, HostChange, Repository},
};

fn fixture() -> (tempfile::TempDir, Arc<Store>) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("space \u{914d}\u{7f6e}");
    fs::create_dir(&path).unwrap();
    let store = Arc::new(
        Store::open(&path.join("inventory.db"), &scoplen_crypto::LocalDatabaseKey::new([73; 32]))
            .unwrap(),
    );
    (directory, store)
}

fn password(store: &Arc<Store>, name: &str) -> HostDetails {
    Inventory::new(store.clone())
        .add_host(NewHost {
            name: Some(name.into()),
            address: "fixture.example".into(),
            port: Some(2200),
            username: "deploy".into(),
            sign_in: SignIn::Password { password: "generated-native-fixture".into() },
        })
        .unwrap()
}

fn generate(state: &GeneratedOpenSshState, store: &Arc<Store>) -> OpenSshGeneratedResult {
    let preview = state.preview(store, "opening".into(), vec![]).unwrap();
    state.generate(store, "opening", &preview.id).unwrap()
}

#[test]
fn publication_retains_complete_generations_and_clear_only_removes_owned_scope_files() {
    let (_directory, store) = fixture();
    let state = GeneratedOpenSshState::default();
    let host = password(&store, "Production");
    let status = state.status(&store).unwrap();
    assert!(!status.active);
    assert!(status.include_line.contains("space \u{914d}\u{7f6e}"));
    let source = store.data_dir().join("unrelated-source");
    fs::write(&source, "preserve source").unwrap();
    let first = generate(&state, &store);
    assert!(first.status.active);
    assert_eq!(first.hosts, 1);
    let scope = Scope::new(&store).unwrap();
    let original = scope.target().unwrap();
    let old_generation = fs::read_dir(&scope.generations).unwrap().next().unwrap().unwrap().path();
    let old_config = fs::read(old_generation.join("config")).unwrap();
    Repository::<Host>::new(&store)
        .update(
            uuid::Uuid::parse_str(&host.summary.id).unwrap(),
            HostChange {
                port: scoplen_client_core::repository::Edit::Set(2222),
                ..Default::default()
            },
        )
        .unwrap();
    generate(&state, &store);
    assert_ne!(scope.target().unwrap(), original);
    assert_eq!(fs::read_dir(&scope.generations).unwrap().count(), 2);
    assert_eq!(fs::read(old_generation.join("config")).unwrap(), old_config);
    assert!(old_generation.join("known_hosts").is_file());
    let unknown = scope.generations.join(uuid::Uuid::now_v7().to_string());
    fs::create_dir(&unknown).unwrap();
    fs::write(unknown.join("keep"), "not marked").unwrap();
    let other_scope = scope.base.join("other-scope");
    fs::create_dir(&other_scope).unwrap();
    fs::write(other_scope.join("keep"), "preserve scope").unwrap();
    let cleared = state.clear(&store).unwrap();
    assert!(!cleared.active);
    assert_eq!(fs::read(&scope.active).unwrap(), HEADER.as_bytes());
    assert_eq!(fs::read_dir(&scope.generations).unwrap().count(), 1);
    assert!(unknown.join("keep").is_file());
    assert!(other_scope.join("keep").is_file());
    assert_eq!(fs::read_to_string(&source).unwrap(), "preserve source");
}

#[test]
fn path_is_stable_after_reopen_but_reviews_require_the_original_opening_and_store() {
    let (_directory, store) = fixture();
    let state = GeneratedOpenSshState::default();
    password(&store, "Stable");
    let original = generate(&state, &store).status;
    let preview = state.preview(&store, "opening".into(), vec![]).unwrap();
    assert_eq!(state.generate(&store, "reopened", &preview.id), Err(Error::ContextChanged));
    let preview = state.preview(&store, "opening".into(), vec![]).unwrap();
    let reopened = Arc::new(
        Store::open(
            &store.data_dir().join("inventory.db"),
            &scoplen_crypto::LocalDatabaseKey::new([73; 32]),
        )
        .unwrap(),
    );
    assert_eq!(state.generate(&reopened, "opening", &preview.id), Err(Error::ContextChanged));
    assert_eq!(state.status(&reopened).unwrap(), original);
    let (_other_directory, other) = fixture();
    assert_ne!(state.status(&other).unwrap().include_path, original.include_path);
}

#[test]
fn target_inventory_and_abandoned_reviews_never_replace_the_active_generation() {
    let (_directory, store) = fixture();
    let state = GeneratedOpenSshState::default();
    let host = password(&store, "Reviewed");
    generate(&state, &store);
    let scope = Scope::new(&store).unwrap();
    let active = fs::read(&scope.active).unwrap();
    let preview = state.preview(&store, "opening".into(), vec![]).unwrap();
    Repository::<Host>::new(&store)
        .update(
            uuid::Uuid::parse_str(&host.summary.id).unwrap(),
            HostChange { address: Some("changed.example".into()), ..Default::default() },
        )
        .unwrap();
    assert_eq!(state.generate(&store, "opening", &preview.id), Err(Error::InventoryChanged));
    assert_eq!(fs::read(&scope.active).unwrap(), active);
    let preview = state.preview(&store, "opening".into(), vec![]).unwrap();
    fs::write(&scope.active, HEADER).unwrap();
    assert_eq!(state.generate(&store, "opening", &preview.id), Err(Error::TargetChanged));
    assert_eq!(fs::read(&scope.active).unwrap(), HEADER.as_bytes());
    let preview = state.preview(&store, "opening".into(), vec![]).unwrap();
    state.discard();
    assert_eq!(state.generate(&store, "opening", &preview.id), Err(Error::PreviewExpired));
    assert_eq!(fs::read_dir(&scope.generations).unwrap().count(), 1);
}

#[test]
fn prepublication_target_failure_preserves_wrapper_and_sidecars_and_removes_staging() {
    let (_directory, store) = fixture();
    let state = GeneratedOpenSshState::default();
    password(&store, "BeforeFailure");
    generate(&state, &store);
    let scope = Scope::new(&store).unwrap();
    let before = fs::read(&scope.active).unwrap();
    let expected = Some(HEADER.as_bytes().to_vec());
    assert_eq!(scope.publish(&expected, HEADER.as_bytes()), Err(Error::TargetChanged));
    assert_eq!(fs::read(&scope.active).unwrap(), before);
    assert_eq!(fs::read_dir(&scope.directory).unwrap().count(), 2);
    let generation = fs::read_dir(&scope.generations).unwrap().next().unwrap().unwrap().path();
    assert!(generation.join("config").is_file());
    assert!(generation.join("known_hosts").is_file());
}

#[test]
fn empty_and_last_login_generation_replace_stale_entries_before_clear() {
    let (_directory, store) = fixture();
    let state = GeneratedOpenSshState::default();
    assert_eq!(generate(&state, &store).hosts, 0);
    let host = password(&store, "Last");
    assert_eq!(generate(&state, &store).hosts, 1);
    store.delete(uuid::Uuid::parse_str(&host.logins[0].id).unwrap()).unwrap();
    assert_eq!(generate(&state, &store).hosts, 0);
    let scope = Scope::new(&store).unwrap();
    let wrapper = fs::read_to_string(&scope.active).unwrap();
    let generation = wrapper
        .strip_prefix(HEADER)
        .unwrap()
        .strip_prefix("# Generation ")
        .unwrap()
        .split_once('\n')
        .unwrap()
        .0;
    assert!(
        !fs::read_to_string(scope.generations.join(generation).join("config"))
            .unwrap()
            .contains("\nHost ")
    );
    assert_eq!(fs::read_dir(&scope.generations).unwrap().count(), 3);
    assert!(!state.clear(&store).unwrap().active);
    assert_eq!(fs::read_dir(&scope.generations).unwrap().count(), 0);
}

#[test]
fn clear_publishes_empty_wrapper_even_when_owned_generation_cleanup_fails() {
    let (_directory, store) = fixture();
    let state = GeneratedOpenSshState::default();
    password(&store, "Cleanup");
    generate(&state, &store);
    let scope = Scope::new(&store).unwrap();
    let generation = fs::read_dir(&scope.generations).unwrap().next().unwrap().unwrap().path();
    let marker = generation.join(".scoplen-generation");
    // A failed ownership-marker read is conservatively retained after empty publication.
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        let _locked = fs::OpenOptions::new().read(true).share_mode(0).open(marker).unwrap();
        assert!(matches!(state.clear(&store), Err(Error::ClearFailed { .. })));
        assert_eq!(fs::read(&scope.active).unwrap(), HEADER.as_bytes());
        assert!(generation.join("config").exists());
    }
    #[cfg(not(windows))]
    {
        fs::write(marker, "unknown marker").unwrap();
        assert!(!state.clear(&store).unwrap().active);
        assert!(generation.join("config").exists());
    }
}
