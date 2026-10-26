// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::repository::{Change, Host, HostChange};
use crate::store::LocalWrite;
use scoplen_crypto::LocalDatabaseKey;
use scoplen_model::{FieldPath, MapKey};

fn store() -> (tempfile::TempDir, Arc<Store>, Snippets) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        Store::open(&dir.path().join("snippets.db"), &LocalDatabaseKey::new([3; 32])).unwrap(),
    );
    let snippets = Snippets::new(store.clone());
    (dir, store, snippets)
}

fn variable(name: &str, kind: SnippetVariableKind, default: Option<&str>) -> SnippetVariableInput {
    SnippetVariableInput {
        name: name.into(),
        kind,
        default: default.map(str::to_owned),
        choices: Vec::new(),
    }
}

fn input(template: &str, variables: Vec<SnippetVariableInput>) -> SnippetInput {
    SnippetInput {
        name: "Inspect service".into(),
        template: template.into(),
        variables,
        tags: vec!["operations".into()],
        folder: Some("Services".into()),
    }
}

#[test]
fn public_facade_round_trips_edits_reopen_and_delete_without_losing_unknown_fields() {
    let (dir, store, snippets) = store();
    assert!(snippets.list().unwrap().is_empty());
    let created = snippets
        .create(input(
            "tail -n {{lines}}",
            vec![variable("lines", SnippetVariableKind::Integer, Some("100"))],
        ))
        .unwrap();
    let id = Uuid::parse_str(&created.id).unwrap();
    store
        .write(LocalWrite {
            id: Some(id),
            object_type: ObjectType::SNIPPET,
            fields: vec![(FieldPath::Field(99), Value::Text("future field".into()))],
        })
        .unwrap();
    let mut update = input(
        "echo '{{label}}'",
        vec![variable("label", SnippetVariableKind::Text, Some("ready"))],
    );
    update.name = "Current label".into();
    update.tags = vec!["status".into()];
    update.folder = None;
    let edited = snippets.update(&created.id, update).unwrap();
    assert_eq!(edited.name, "Current label");
    assert_eq!(edited.tags, ["status"]);
    assert_eq!(edited.folder, None);
    assert_eq!(edited.variables.len(), 1);
    assert_eq!(edited.variables[0].name, "label");
    let object = store.get(id).unwrap().unwrap();
    assert_eq!(object.set_field(99).unwrap().value, Value::Text("future field".into()));
    let removed = FieldPath::map_entry(3, MapKey::Text("lines".into())).unwrap();
    assert_eq!(object.fields[&removed].value, Value::Null);
    drop(snippets);
    drop(store);
    let reopened = Snippets::new(Arc::new(
        Store::open(&dir.path().join("snippets.db"), &LocalDatabaseKey::new([3; 32])).unwrap(),
    ));
    assert_eq!(reopened.list().unwrap(), [edited]);
    assert_eq!(reopened.prepare(&created.id, BTreeMap::new()).unwrap().command, "echo 'ready'");
    reopened.delete(&created.id).unwrap();
    assert!(reopened.list().unwrap().is_empty());
    assert_eq!(reopened.prepare(&created.id, BTreeMap::new()), Err(SnippetIssue::NotFound));
}

#[test]
fn values_are_inserted_once_literally_and_repeated_placeholders_prompt_once() {
    let (_dir, _store, snippets) = store();
    let created = snippets
        .create(input(
            "printf '%s:%s' '{{label}}' '{{label}}'",
            vec![variable("label", SnippetVariableKind::Text, None)],
        ))
        .unwrap();
    let punctuation = "' ; $HOME && {{other}} \\";
    let command = snippets
        .prepare(&created.id, BTreeMap::from([("label".into(), punctuation.into())]))
        .unwrap();
    assert_eq!(command.command, format!("printf '%s:%s' '{punctuation}' '{punctuation}'"));
    assert_eq!(command.snippet_id, created.id);
    assert!(!command.command.ends_with('\r'));
    assert_eq!(
        snippets.prepare(&created.id, BTreeMap::new()),
        Err(SnippetIssue::MissingValue { name: "label".into() })
    );
    assert_eq!(
        snippets.prepare(&created.id, BTreeMap::from([("other".into(), "value".into())])),
        Err(SnippetIssue::UnknownValue { name: "other".into() })
    );
    assert_eq!(
        snippets
            .prepare(&created.id, BTreeMap::from([("label".into(), "".into())]))
            .unwrap()
            .command,
        "printf '%s:%s' '' ''"
    );
}

#[test]
fn docker_go_actions_escaped_identifiers_and_unmatched_braces_remain_literal() {
    let (_dir, _store, snippets) = store();
    let created = snippets
        .create(input(
            "docker inspect --format '{{.State.Status}} {{json .Config}} {{{{json}}}}' {{container}} {one} {{unfinished",
            vec![variable("container", SnippetVariableKind::Text, Some("api"))],
        ))
        .unwrap();
    assert_eq!(
        snippets.prepare(&created.id, BTreeMap::new()).unwrap().command,
        "docker inspect --format '{{.State.Status}} {{json .Config}} {{json}}' api {one} {{unfinished"
    );
    let quoted_action =
        snippets.create(input("printf '{{printf \"{{literal}}\"}}'", Vec::new())).unwrap();
    assert_eq!(
        snippets.prepare(&quoted_action.id, BTreeMap::new()).unwrap().command,
        "printf '{{printf \"{{literal}}\"}}'"
    );
}

#[test]
fn definitions_refuse_unknown_unused_duplicate_and_invalid_variable_names() {
    let (_dir, _store, snippets) = store();
    assert_eq!(
        snippets.create(input("echo {{missing}}", Vec::new())),
        Err(SnippetIssue::UnknownPlaceholder { name: "missing".into() })
    );
    assert_eq!(
        snippets.create(input(
            "echo {{{{unused}}}}",
            vec![variable("unused", SnippetVariableKind::Text, None)]
        )),
        Err(SnippetIssue::UnusedVariable { name: "unused".into() })
    );
    let duplicate = variable("label", SnippetVariableKind::Text, None);
    assert_eq!(
        snippets.create(input("echo {{label}}", vec![duplicate.clone(), duplicate])),
        Err(SnippetIssue::DuplicateVariable)
    );
    for name in ["", "9name", "a-b", "é", "a b"] {
        assert_eq!(
            snippets
                .create(input("echo value", vec![variable(name, SnippetVariableKind::Text, None)])),
            Err(SnippetIssue::InvalidVariableName)
        );
    }
}

#[test]
fn integer_values_and_defaults_are_canonical_signed_i64() {
    let (_dir, store, snippets) = store();
    for value in ["0", "-1", "9223372036854775807", "-9223372036854775808"] {
        let created = snippets
            .create(input(
                "echo {{number}}",
                vec![variable("number", SnippetVariableKind::Integer, Some(value))],
            ))
            .unwrap();
        assert_eq!(
            snippets.prepare(&created.id, BTreeMap::new()).unwrap().command,
            format!("echo {value}")
        );
        let record = Repository::<Snippet>::new(&store)
            .get(Uuid::parse_str(&created.id).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(record.variables["number"].default.as_deref(), Some(value));
    }
    let created = snippets
        .create(input(
            "echo {{number}}",
            vec![variable("number", SnippetVariableKind::Integer, None)],
        ))
        .unwrap();
    for value in [
        "",
        "+1",
        "01",
        "-01",
        "-0",
        " 1",
        "1 ",
        "1.0",
        "1e2",
        "9223372036854775808",
        "-9223372036854775809",
    ] {
        assert_eq!(
            snippets.prepare(&created.id, BTreeMap::from([("number".into(), value.into())])),
            Err(SnippetIssue::InvalidValue { name: "number".into() })
        );
        assert_eq!(
            snippets.create(input(
                "echo {{number}}",
                vec![variable("number", SnippetVariableKind::Integer, Some(value))]
            )),
            Err(SnippetIssue::InvalidDefault { name: "number".into() })
        );
    }
}

#[test]
fn choices_are_exact_unique_nonempty_lists_with_optional_empty_members() {
    let (_dir, _store, snippets) = store();
    let mut choice = variable("mode", SnippetVariableKind::Choice, Some(""));
    choice.choices = vec!["".into(), "Blue".into()];
    let created = snippets.create(input("echo '{{mode}}'", vec![choice.clone()])).unwrap();
    assert_eq!(snippets.prepare(&created.id, BTreeMap::new()).unwrap().command, "echo ''");
    assert_eq!(
        snippets
            .prepare(&created.id, BTreeMap::from([("mode".into(), "Blue".into())]))
            .unwrap()
            .command,
        "echo 'Blue'"
    );
    for value in ["blue", " Blue", "Blue "] {
        assert_eq!(
            snippets.prepare(&created.id, BTreeMap::from([("mode".into(), value.into())])),
            Err(SnippetIssue::InvalidValue { name: "mode".into() })
        );
    }
    choice.default = Some("blue".into());
    assert_eq!(
        snippets.create(input("echo {{mode}}", vec![choice.clone()])),
        Err(SnippetIssue::InvalidDefault { name: "mode".into() })
    );
    choice.default = None;
    for choices in [vec![], vec!["same".into(), "same".into()], vec!["tab\t".into()]] {
        choice.choices = choices;
        assert_eq!(
            snippets.create(input("echo {{mode}}", vec![choice.clone()])),
            Err(SnippetIssue::InvalidChoices { name: "mode".into() })
        );
    }
    choice.kind = SnippetVariableKind::Text;
    choice.choices = vec!["extra".into()];
    assert_eq!(
        snippets.create(input("echo {{mode}}", vec![choice])),
        Err(SnippetIssue::InvalidChoices { name: "mode".into() })
    );
}

#[test]
fn one_line_profile_refuses_controls_in_templates_defaults_and_inputs() {
    let (_dir, _store, snippets) = store();
    let created = snippets
        .create(input("echo '{{value}}'", vec![variable("value", SnippetVariableKind::Text, None)]))
        .unwrap();
    for byte in (0u8..=31).chain([127]) {
        let value = format!("before{}after", char::from(byte));
        assert_eq!(
            snippets.prepare(&created.id, BTreeMap::from([("value".into(), value.clone())])),
            Err(SnippetIssue::InvalidValue { name: "value".into() })
        );
        assert_eq!(snippets.create(input(&value, Vec::new())), Err(SnippetIssue::InvalidTemplate));
        assert_eq!(
            snippets.create(input(
                "echo {{value}}",
                vec![variable("value", SnippetVariableKind::Text, Some(&value))]
            )),
            Err(SnippetIssue::InvalidDefault { name: "value".into() })
        );
    }
}

#[test]
fn complete_utf8_command_reserves_exactly_one_byte_for_enter() {
    let (_dir, _store, snippets) = store();
    let created = snippets
        .create(input("{{value}}", vec![variable("value", SnippetVariableKind::Text, None)]))
        .unwrap();
    let exact = "界".repeat((MAX_SSH_INPUT - 1) / 3);
    assert_eq!(exact.len(), MAX_SSH_INPUT - 1);
    assert_eq!(
        snippets
            .prepare(&created.id, BTreeMap::from([("value".into(), exact.clone())]))
            .unwrap()
            .command,
        exact
    );
    assert_eq!(
        snippets.prepare(&created.id, BTreeMap::from([("value".into(), format!("{exact}x"))])),
        Err(SnippetIssue::CommandTooLarge)
    );
    let repeated = snippets
        .create(input(
            "{{value}}{{value}}{{value}}{{value}}",
            vec![variable("value", SnippetVariableKind::Text, None)],
        ))
        .unwrap();
    assert_eq!(
        snippets.prepare(
            &repeated.id,
            BTreeMap::from([("value".into(), "x".repeat(MAX_SSH_INPUT / 4))])
        ),
        Err(SnippetIssue::CommandTooLarge)
    );
}

#[test]
fn secret_definitions_are_redacted_read_only_and_unchanged_even_when_unused() {
    let (_dir, store, snippets) = store();
    let sentinel = "synthetic-secret-default-for-redaction";
    let secret = Variable {
        kind: VariableKind::Secret,
        default: Some(sentinel.into()),
        choices: vec!["synthetic-secret-choice".into()],
    };
    let change = SnippetChange {
        name: Some("Retained secret".into()),
        template: Some("echo ordinary".into()),
        variables: BTreeMap::from([("token".into(), Some(secret.clone()))]),
        ..Default::default()
    };
    assert!(!format!("{change:?}").contains(sentinel));
    assert!(!format!("{secret:?}").contains("synthetic-secret-choice"));
    let record = Repository::<Snippet>::new(&store).create(change).unwrap();
    assert!(!format!("{record:?}").contains(sentinel));
    let original = store.get(record.meta.id).unwrap().unwrap().encode().unwrap();
    let view = snippets.list().unwrap().remove(0);
    assert!(view.read_only);
    assert_eq!(view.issue, Some(SnippetIssue::SecretUnsupported));
    assert!(view.variables[0].has_default);
    assert_eq!(view.variables[0].default, None);
    assert!(view.variables[0].choices.is_empty());
    assert!(!format!("{view:?}").contains(sentinel));
    assert!(!serde_json::to_string(&view).unwrap().contains(sentinel));
    assert_eq!(snippets.prepare(&view.id, BTreeMap::new()), Err(SnippetIssue::SecretUnsupported));
    assert_eq!(
        snippets.update(&view.id, input("echo replacement", Vec::new())),
        Err(SnippetIssue::ReadOnly)
    );
    assert_eq!(snippets.delete(&view.id), Err(SnippetIssue::ReadOnly));
    assert_eq!(store.get(record.meta.id).unwrap().unwrap().encode().unwrap(), original);
    let submitted = variable("token", SnippetVariableKind::Secret, Some(sentinel));
    assert!(!format!("{submitted:?}").contains(sentinel));
    assert_eq!(
        snippets.create(input("echo {{token}}", vec![submitted])),
        Err(SnippetIssue::SecretUnsupported)
    );
}

#[test]
fn unsupported_synchronized_defaults_remain_visible_without_becoming_executable() {
    let (_dir, store, snippets) = store();
    let fields = SnippetChange {
        name: Some("Future default".into()),
        template: Some("echo {{value}}".into()),
        variables: BTreeMap::from([(
            "value".into(),
            Some(Variable { kind: VariableKind::Text, default: None, choices: Vec::new() }),
        )]),
        ..Default::default()
    }
    .into_writes()
    .unwrap();
    let mut fields = fields;
    fields.iter_mut().find(|(path, _)| matches!(path, FieldPath::MapEntry { .. })).unwrap().1 =
        Value::Map(vec![(Value::UInt(1), Value::UInt(1)), (Value::UInt(2), Value::Bool(true))]);
    let object =
        store.write(LocalWrite { id: None, object_type: ObjectType::SNIPPET, fields }).unwrap();
    let original = object.encode().unwrap();
    let view = snippets.list().unwrap().remove(0);
    assert_eq!(view.name, "Future default");
    assert_eq!(view.issue, Some(SnippetIssue::InvalidDefinition));
    assert!(view.read_only);
    assert_eq!(snippets.prepare(&view.id, BTreeMap::new()), Err(SnippetIssue::InvalidDefinition));
    assert_eq!(
        snippets.update(&view.id, input("echo replacement", Vec::new())),
        Err(SnippetIssue::ReadOnly)
    );
    assert_eq!(store.get(object.id).unwrap().unwrap().encode().unwrap(), original);
}

#[test]
fn unsupported_but_readable_objects_can_be_repaired_without_silent_rewriting() {
    let (_dir, store, snippets) = store();
    let object = Repository::<Snippet>::new(&store)
        .create(SnippetChange {
            name: Some("Imported count".into()),
            template: Some("echo {{number}}".into()),
            variables: BTreeMap::from([(
                "number".into(),
                Some(Variable {
                    kind: VariableKind::Integer,
                    default: Some(u64::MAX.to_string()),
                    choices: Vec::new(),
                }),
            )]),
            ..Default::default()
        })
        .unwrap();
    let original = store.get(object.meta.id).unwrap().unwrap().encode().unwrap();
    let view = snippets.list().unwrap().remove(0);
    assert!(!view.read_only);
    assert_eq!(view.issue, Some(SnippetIssue::InvalidDefault { name: "number".into() }));
    assert_eq!(
        snippets.prepare(&view.id, BTreeMap::new()),
        Err(SnippetIssue::InvalidDefault { name: "number".into() })
    );
    assert_eq!(store.get(object.meta.id).unwrap().unwrap().encode().unwrap(), original);
    let repaired = snippets
        .update(
            &view.id,
            input(
                "echo {{number}}",
                vec![variable("number", SnippetVariableKind::Integer, Some("1"))],
            ),
        )
        .unwrap();
    assert_eq!(repaired.issue, None);
}

#[test]
fn identifiers_and_foreign_objects_cannot_select_a_different_record() {
    let (_dir, store, snippets) = store();
    for id in [
        "not-an-id".into(),
        Uuid::nil().to_string(),
        Uuid::now_v7().to_string().to_ascii_uppercase(),
    ] {
        assert_eq!(snippets.prepare(&id, BTreeMap::new()), Err(SnippetIssue::InvalidId));
    }
    let host = Repository::<Host>::new(&store)
        .create(HostChange {
            name: Some("ordinary host".into()),
            address: Some("host.example".into()),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(snippets.delete(&host.meta.id.to_string()), Err(SnippetIssue::NotFound));
    assert!(store.get(host.meta.id).unwrap().is_some());
    assert_eq!(
        snippets.prepare(&Uuid::now_v7().to_string(), BTreeMap::new()),
        Err(SnippetIssue::NotFound)
    );
}
