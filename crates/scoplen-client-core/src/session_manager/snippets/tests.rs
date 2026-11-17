// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::personal_server::{TeamAssetsPhase, tests::fixture_profile};
use crate::repository::{Repository, Snippet, SnippetChange, Variable, VariableKind};
use crate::snippets::Snippets;
use crate::store::team_assets::TeamAssetPublication;
use scoplen_crypto::LocalDatabaseKey;
use scoplen_model::Object;

fn local(dir: &tempfile::TempDir, name: &str) -> Arc<Store> {
    Arc::new(Store::open(&dir.path().join(name), &LocalDatabaseKey::new([7; 32])).unwrap())
}

fn source(store: &Store) -> TeamSshSource {
    let identity = fixture_profile(store, "https://sync.example", true).record;
    store
        .save_personal_tokens(b"synthetic-access", b"synthetic-refresh", u64::MAX, u64::MAX)
        .unwrap();
    TeamSshSource {
        origin: identity.origin,
        account_id: identity.account_id.to_string(),
        organization_id: Uuid::now_v7().to_string(),
        device_id: store.device_id().to_string(),
    }
}

fn definition(store: &Store, secret: bool) -> Object {
    let variables = if secret {
        BTreeMap::from([(
            "token".into(),
            Some(Variable {
                kind: VariableKind::Secret,
                default: Some("synthetic-redacted-default".into()),
                choices: vec!["synthetic-redacted-choice".into()],
            }),
        )])
    } else {
        BTreeMap::from([
            (
                "label".into(),
                Some(Variable {
                    kind: VariableKind::Text,
                    default: Some("ready".into()),
                    choices: vec![],
                }),
            ),
            (
                "count".into(),
                Some(Variable {
                    kind: VariableKind::Integer,
                    default: Some("-7".into()),
                    choices: vec![],
                }),
            ),
            (
                "mode".into(),
                Some(Variable {
                    kind: VariableKind::Choice,
                    default: Some("status".into()),
                    choices: vec!["status".into(), "detail".into()],
                }),
            ),
        ])
    };
    let saved = Repository::<Snippet>::new(store)
        .create(SnippetChange {
            name: Some("Shared inspection".into()),
            template: Some(
                if secret { "echo unused" } else { "printf '%s' '{{label}}/{{count}}/{{mode}}'" }
                    .into(),
            ),
            variables,
            ..Default::default()
        })
        .unwrap();
    store.get(saved.meta.id).unwrap().unwrap()
}

fn publish(
    store: &Store,
    source: &TeamSshSource,
    objects: &[Object],
    ack: bool,
) -> TeamAssetPublication {
    let identity = store.personal_record().unwrap().unwrap();
    let organization = Uuid::parse_str(&source.organization_id).unwrap();
    let publication = TeamAssetPublication {
        organization,
        generation: store.begin_team_asset_pull(&identity, organization).unwrap(),
        vault: Uuid::now_v7(),
        revision: u64::MAX,
        cursor: 50,
    };
    store.publish_team_assets(&identity, &publication, objects).unwrap();
    if ack {
        store.acknowledge_team_assets(&identity, organization, publication.generation).unwrap();
    }
    publication
}

fn ready(
    manager: &SessionManager,
    name: &str,
    source: Option<TeamSshSource>,
) -> (SnippetTerminal, mpsc::Receiver<TransportCommand>) {
    manager.reserve(name, true).unwrap();
    let id = Uuid::now_v7();
    let (sender, commands) = mpsc::channel(COMMAND_QUEUE);
    let (files, _file_requests) = mpsc::channel(FILE_QUEUE);
    manager.sessions.lock().unwrap().get_mut(name).unwrap().active = Some(ActiveAttempt {
        id,
        control: PreparationControl::default(),
        sender,
        files,
        file: None,
        ready: true,
        context: Some(PreparationContext {
            terminal_profile: None,
            source,
            profile_id: Uuid::now_v7().to_string(),
            host_id: Uuid::now_v7().to_string(),
            login: "ops".into(),
            host: "Owned host".into(),
            username: "ops".into(),
            address: "127.0.0.1".into(),
            port: 22,
            position: 1,
            total: 1,
            target: true,
        }),
    });
    (SnippetTerminal { session_id: name.into(), transport_id: id.to_string() }, commands)
}

#[test]
fn public_team_snippet_facade_uses_exact_namespace_and_literal_preparer_without_signer_side_effects()
 {
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir, "account.db");
    let source = source(&store);
    let personal = definition(&store, false);
    let original = personal.encode().unwrap();
    publish(&store, &source, std::slice::from_ref(&personal), true);
    let manager = SessionManager::default();
    let (origin, mut commands) = ready(&manager, "origin", Some(source.clone()));
    let library = manager.team_snippets(&store, &origin).unwrap();
    assert_eq!(library.snippets.len(), 1);
    assert_eq!(library.snippets[0].template, "printf '%s' '{{label}}/{{count}}/{{mode}}'");
    assert_eq!(library.fence.as_ref().unwrap().revision, "18446744073709551615");
    Snippets::new(store.clone()).delete(&personal.id.to_string()).unwrap();
    let preview = manager
        .prepare_team_snippet(
            &store,
            origin.clone(),
            library.fence.clone().unwrap(),
            &personal.id.to_string(),
            BTreeMap::from([("label".into(), "{{literal}}; echo value".into())]),
            vec![origin.clone()],
        )
        .unwrap();
    assert_eq!(preview.snippet.command, "printf '%s' '{{literal}}; echo value/-7/status'");
    assert_eq!(
        manager.send_team_snippet(&store, &preview, 0).unwrap(),
        TeamSnippetSendOutcome::Sent
    );
    let TransportCommand::Input(bytes) = commands.try_recv().unwrap() else {
        panic!("input expected")
    };
    assert_eq!(bytes, b"printf '%s' '{{literal}}; echo value/-7/status'\r");
    assert!(commands.try_recv().is_err());
    assert!(store.team_ssh_signer(&source.owner(&store).unwrap()).unwrap().is_none());
    let retained = store
        .team_assets_record(
            &store.personal_record().unwrap().unwrap(),
            Uuid::parse_str(&source.organization_id).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(retained.objects[0].encode().unwrap(), original);
    assert_eq!(
        manager
            .prepare_team_snippet(
                &store,
                origin.clone(),
                library.fence.unwrap(),
                &personal.id.to_string(),
                BTreeMap::from([("count".into(), "01".into())]),
                vec![origin]
            )
            .unwrap_err(),
        SnippetIssue::InvalidValue { name: "count".into() }
    );
}

#[test]
fn team_snippet_ready_ack_and_replacement_fences_never_fall_back_to_retained_or_personal_data() {
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir, "account.db");
    let source = source(&store);
    let object = definition(&local(&dir, "author.db"), false);
    let manager = SessionManager::default();
    let (origin, mut commands) = ready(&manager, "origin", Some(source.clone()));
    assert_eq!(manager.team_snippets(&store, &origin).unwrap().phase, TeamAssetsPhase::NotLoaded);
    let publication = publish(&store, &source, std::slice::from_ref(&object), false);
    let unconfirmed = manager.team_snippets(&store, &origin).unwrap();
    assert_eq!(unconfirmed.phase, TeamAssetsPhase::Ready);
    assert!(unconfirmed.fence.is_none() && unconfirmed.snippets.is_empty());
    let identity = store.personal_record().unwrap().unwrap();
    store
        .acknowledge_team_assets(&identity, publication.organization, publication.generation)
        .unwrap();
    let fence = manager.team_snippets(&store, &origin).unwrap().fence.unwrap();
    let prepared = manager
        .prepare_team_snippet(
            &store,
            origin.clone(),
            fence.clone(),
            &object.id.to_string(),
            BTreeMap::new(),
            vec![origin.clone()],
        )
        .unwrap();
    let generation = store.begin_team_asset_pull(&identity, publication.organization).unwrap();
    assert_eq!(manager.team_snippets(&store, &origin).unwrap().phase, TeamAssetsPhase::Updating);
    assert_eq!(
        manager.send_team_snippet(&store, &prepared, 0).unwrap(),
        TeamSnippetSendOutcome::Invalidated
    );
    store
        .finish_team_asset_pull(&identity, publication.organization, generation, 4, false)
        .unwrap();
    assert!(manager.team_snippets(&store, &origin).unwrap().snippets.is_empty());
    publish(&store, &source, &[object], true);
    assert!(
        manager
            .prepare_team_snippet(
                &store,
                origin.clone(),
                fence,
                &prepared.snippet.snippet_id,
                BTreeMap::new(),
                vec![origin.clone()]
            )
            .is_err()
    );
    assert_eq!(
        manager.send_team_snippet(&store, &prepared, 0).unwrap(),
        TeamSnippetSendOutcome::Invalidated
    );
    publish(&store, &source, &[], true);
    assert!(manager.team_snippets(&store, &origin).unwrap().snippets.is_empty());
    assert!(commands.try_recv().is_err());
}

#[test]
fn team_snippet_admission_rechecks_actual_source_and_never_redirects_original_transports() {
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir, "account.db");
    let source = source(&store);
    let object = definition(&local(&dir, "author.db"), false);
    publish(&store, &source, std::slice::from_ref(&object), true);
    let manager = SessionManager::default();
    let (origin, _origin_input) = ready(&manager, "origin", Some(source.clone()));
    let (sibling, mut sibling_input) = ready(&manager, "sibling", Some(source.clone()));
    let (personal, _personal_input) = ready(&manager, "personal", None);
    let fence = manager.team_snippets(&store, &origin).unwrap().fence.unwrap();
    let prepare = |targets| {
        manager.prepare_team_snippet(
            &store,
            origin.clone(),
            fence.clone(),
            &object.id.to_string(),
            BTreeMap::new(),
            targets,
        )
    };
    assert!(manager.team_snippets(&store, &personal).is_err());
    assert!(prepare(vec![personal]).is_err());
    assert!(prepare(vec![]).is_err());
    assert!(prepare(vec![sibling.clone(), sibling.clone()]).is_err());
    for (index, foreign) in [
        TeamSshSource { origin: "https://foreign.example".into(), ..source.clone() },
        TeamSshSource { account_id: Uuid::now_v7().to_string(), ..source.clone() },
        TeamSshSource { device_id: Uuid::now_v7().to_string(), ..source.clone() },
        TeamSshSource { organization_id: Uuid::now_v7().to_string(), ..source.clone() },
    ]
    .into_iter()
    .enumerate()
    {
        let (target, _input) = ready(&manager, &format!("foreign-{index}"), Some(foreign));
        assert!(prepare(vec![target]).is_err());
    }
    let prepared = prepare(vec![sibling.clone()]).unwrap();
    manager
        .sessions
        .lock()
        .unwrap()
        .get_mut("sibling")
        .unwrap()
        .active
        .as_mut()
        .unwrap()
        .context
        .as_mut()
        .unwrap()
        .source =
        Some(TeamSshSource { organization_id: Uuid::now_v7().to_string(), ..source.clone() });
    assert_eq!(
        manager.send_team_snippet(&store, &prepared, 0).unwrap(),
        TeamSnippetSendOutcome::NotSent
    );
    manager
        .sessions
        .lock()
        .unwrap()
        .get_mut("sibling")
        .unwrap()
        .active
        .as_mut()
        .unwrap()
        .context
        .as_mut()
        .unwrap()
        .source = Some(source.clone());
    manager.sessions.lock().unwrap().get_mut("sibling").unwrap().active.as_mut().unwrap().id =
        Uuid::now_v7();
    assert_eq!(
        manager.send_team_snippet(&store, &prepared, 0).unwrap(),
        TeamSnippetSendOutcome::NotSent
    );
    assert!(sibling_input.try_recv().is_err());
    manager
        .sessions
        .lock()
        .unwrap()
        .get_mut("origin")
        .unwrap()
        .active
        .as_mut()
        .unwrap()
        .context
        .as_mut()
        .unwrap()
        .source = Some(TeamSshSource { organization_id: Uuid::now_v7().to_string(), ..source });
    assert_eq!(
        manager.send_team_snippet(&store, &prepared, 0).unwrap(),
        TeamSnippetSendOutcome::Invalidated
    );
    manager.close("origin").unwrap();
    assert_eq!(
        manager.send_team_snippet(&store, &prepared, 0).unwrap(),
        TeamSnippetSendOutcome::Invalidated
    );
}

#[test]
fn team_empty_text_expansion_preserves_the_existing_single_enter_profile() {
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir, "account.db");
    let source = source(&store);
    let author = local(&dir, "author.db");
    let saved = Repository::<Snippet>::new(&author)
        .create(SnippetChange {
            name: Some("Empty text".into()),
            template: Some("{{text}}".into()),
            variables: BTreeMap::from([(
                "text".into(),
                Some(Variable {
                    kind: VariableKind::Text,
                    default: Some(String::new()),
                    choices: vec![],
                }),
            )]),
            ..Default::default()
        })
        .unwrap();
    publish(&store, &source, &[author.get(saved.meta.id).unwrap().unwrap()], true);
    let manager = SessionManager::default();
    let (origin, mut commands) = ready(&manager, "origin", Some(source));
    let fence = manager.team_snippets(&store, &origin).unwrap().fence.unwrap();
    let prepared = manager
        .prepare_team_snippet(
            &store,
            origin.clone(),
            fence,
            &saved.meta.id.to_string(),
            BTreeMap::new(),
            vec![origin],
        )
        .unwrap();
    assert!(prepared.snippet.command.is_empty());
    assert_eq!(
        manager.send_team_snippet(&store, &prepared, 0).unwrap(),
        TeamSnippetSendOutcome::Sent
    );
    let TransportCommand::Input(bytes) = commands.try_recv().unwrap() else {
        panic!("input expected")
    };
    assert_eq!(bytes, b"\r");
}

#[test]
fn team_secret_metadata_is_redacted_and_whole_definition_preparation_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let store = local(&dir, "account.db");
    let source = source(&store);
    let object = definition(&local(&dir, "author.db"), true);
    let original = object.encode().unwrap();
    publish(&store, &source, std::slice::from_ref(&object), true);
    let manager = SessionManager::default();
    let (origin, mut commands) = ready(&manager, "origin", Some(source.clone()));
    let library = manager.team_snippets(&store, &origin).unwrap();
    assert!(library.snippets[0].read_only);
    assert_eq!(library.snippets[0].issue, Some(SnippetIssue::SecretUnsupported));
    let projection = serde_json::to_string(&library).unwrap();
    assert!(!projection.contains("synthetic-redacted"));
    assert!(!format!("{library:?}").contains("synthetic-redacted"));
    assert_eq!(
        manager
            .prepare_team_snippet(
                &store,
                origin.clone(),
                library.fence.unwrap(),
                &object.id.to_string(),
                BTreeMap::new(),
                vec![origin]
            )
            .unwrap_err(),
        SnippetIssue::SecretUnsupported
    );
    assert!(commands.try_recv().is_err());
    assert!(store.list(scoplen_model::ObjectType::SNIPPET).unwrap().is_empty());
    assert_eq!(
        store
            .team_assets_record(
                &store.personal_record().unwrap().unwrap(),
                Uuid::parse_str(&source.organization_id).unwrap()
            )
            .unwrap()
            .unwrap()
            .objects[0]
            .encode()
            .unwrap(),
        original
    );
}
