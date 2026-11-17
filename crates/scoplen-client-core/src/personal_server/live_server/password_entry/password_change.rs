// SPDX-License-Identifier: Apache-2.0
//! Existing native Device credential replacement against a disposable strict HTTPS service.

use super::*;
use crate::personal_server::{PasswordChangeError, PasswordChangePhase};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangeDeployment {
    disposable: bool,
    origin: String,
    operator_lifecycle_verified: bool,
    ca_certificate: PathBuf,
}

#[tokio::test]
async fn live_existing_device_password_change() {
    let artifact = std::env::var_os("SCOPLEN_LIVE_PASSWORD_CHANGE_DEPLOYMENT")
        .expect("provide the private disposable password-change HTTPS descriptor");
    let artifact = Path::new(&artifact);
    assert!(artifact.is_absolute());
    let deployment: ChangeDeployment = serde_json::from_slice(&bounded_file(artifact, 8192))
        .expect("strict password-change descriptor");
    assert!(
        deployment.disposable
            && deployment.operator_lifecycle_verified
            && deployment.ca_certificate.is_absolute()
    );
    assert!(
        deployment
            .origin
            .strip_prefix("https://localhost:")
            .and_then(|port| port.parse::<u16>().ok())
            .is_some_and(|port| port != 0)
    );
    let ca = bounded_file(&deployment.ca_certificate, 65_536);
    let directory = OwnedDirectory::new();
    let first = Device::new(&directory.path().join("first"));
    let second = Device::new(&directory.path().join("second"));
    let first_manager = manager(&ca);
    let second_manager = manager(&ca);
    let suffix = scoplen_model::new_uuid_v7().unwrap();
    let username = format!("change-{}", suffix.simple());
    let old = SecretVec::new(format!("Original disposable Account {suffix}").into_bytes());
    let new = SecretVec::new(format!("Replacement disposable Account {suffix}").into_bytes());
    let third_password = SecretVec::new(format!("Final disposable Account {suffix}").into_bytes());
    let original = register(
        &first,
        &first_manager,
        &deployment.origin,
        &username,
        old.clone(),
        &directory.path().join("recovery.txt"),
    )
    .await;
    let second_lease =
        sign_in(&second, &second_manager, &deployment.origin, &username, old.clone()).await;
    let store = first.store(&original);
    let second_store = second.store(&second_lease);
    let shared = host(&store, "Personal Host created before password replacement");
    let settings = PersonalInventorySettings::default();
    let preview = settings.preview(&store, vec![shared.id.to_string()]).unwrap();
    assert!(preview.missing.is_empty() && preview.token.is_some());
    let uploaded = settings
        .synchronize(&first_manager, store.clone(), preview.token)
        .await
        .expect("publish the original Device's encrypted Personal Host before password change");
    assert_eq!(uploaded.uploaded, 1);
    settings
        .synchronize(&second_manager, second_store.clone(), None)
        .await
        .expect("second Device decrypts the Personal Host before password change");
    assert_eq!(second_store.get(shared.id).unwrap(), Some(shared.clone()));
    let identity = store.personal_record().unwrap().unwrap();
    let provenance = store.account_profile_binding().unwrap().unwrap();
    let ready = first_manager
        .begin_password_change(
            &first.profiles,
            &original,
            old.clone(),
            new.clone(),
            &RegistrationCancellation::default(),
        )
        .await
        .expect("prepare original Device password replacement");
    assert_eq!(ready.phase, PasswordChangePhase::Ready);
    assert_eq!(
        first_manager
            .exchange_password_change(
                &first.profiles,
                &original,
                ready.operation_id,
                RegistrationAction::Submit,
                &RegistrationCancellation::default()
            )
            .await
            .expect("commit replacement over strict HTTPS")
            .phase,
        PasswordChangePhase::Committed
    );
    assert_eq!(store.credential_generation_floor().unwrap(), Some(2));
    assert_eq!(
        store.personal_record().unwrap().unwrap().private_material,
        identity.private_material
    );
    assert_eq!(store.personal_record().unwrap().unwrap().auth_generation, identity.auth_generation);
    let unchanged = store.account_profile_binding().unwrap().unwrap();
    assert_eq!(provenance.payload, unchanged.payload);
    assert_eq!(provenance.signature, unchanged.signature);
    assert_eq!(provenance.confirmation, unchanged.confirmation);
    first_manager
        .query_account(store.clone())
        .await
        .expect("original native Device session remains usable");
    second_manager
        .query_account(second_store.clone())
        .await
        .expect("other native Device session remains usable");
    let edited = second_store
        .write(LocalWrite {
            id: Some(shared.id),
            object_type: ObjectType::HOST,
            fields: vec![(
                FieldPath::Field(1),
                Value::Text("Host edited after first password change".into()),
            )],
        })
        .unwrap();
    settings
        .synchronize(&second_manager, second_store.clone(), None)
        .await
        .expect("second Device uploads its Personal Host edit after password change");
    settings
        .synchronize(&first_manager, store.clone(), None)
        .await
        .expect("original Device decrypts the same Host after password change");
    assert_eq!(store.get(shared.id).unwrap(), Some(edited));
    store.clear_personal_tokens().unwrap();
    let generation = store.personal_record().unwrap().unwrap().auth_generation;
    assert_eq!(
        first_manager
            .exchange_password_change(
                &first.profiles,
                &original,
                ready.operation_id,
                RegistrationAction::Confirm,
                &RegistrationCancellation::default()
            )
            .await
            .expect("confirm historical receipt without a native access session")
            .phase,
        PasswordChangePhase::Committed
    );
    assert!(store.personal_access_token(0).unwrap().is_none());
    assert_eq!(store.personal_record().unwrap().unwrap().auth_generation, generation);
    first_manager.discard_password_change(&first.profiles, &original, ready.operation_id).unwrap();
    assert_eq!(
        first_manager
            .begin_password_change(
                &first.profiles,
                &original,
                old,
                new.clone(),
                &RegistrationCancellation::default()
            )
            .await,
        Err(PasswordChangeError::AuthenticationDenied)
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    let next = first_manager
        .begin_password_change(
            &first.profiles,
            &original,
            new.clone(),
            third_password.clone(),
            &RegistrationCancellation::default(),
        )
        .await
        .expect("new password opens unchanged ARK and roots");
    first_manager
        .exchange_password_change(
            &first.profiles,
            &original,
            next.operation_id,
            RegistrationAction::Submit,
            &RegistrationCancellation::default(),
        )
        .await
        .expect("commit checked successor generation");
    assert_eq!(store.credential_generation_floor().unwrap(), Some(3));
    assert!(store.personal_access_token(0).unwrap().is_none());
    first_manager
        .authenticate(store.clone())
        .await
        .expect("original Device can authenticate with unchanged identity");
    second_manager
        .query_account(second_store.clone())
        .await
        .expect("second Device remains authorized after two replacements");
    let final_host = store
        .write(LocalWrite {
            id: Some(shared.id),
            object_type: ObjectType::HOST,
            fields: vec![(
                FieldPath::Field(1),
                Value::Text("Host edited after second password change".into()),
            )],
        })
        .unwrap();
    settings
        .synchronize(&first_manager, store.clone(), None)
        .await
        .expect("original Device uploads its Personal Host edit after two password changes");
    settings
        .synchronize(&second_manager, second_store.clone(), None)
        .await
        .expect("second Device decrypts the same Host after two password changes");
    assert_eq!(second_store.get(shared.id).unwrap(), Some(final_host.clone()));
    let third = Device::new(&directory.path().join("third"));
    let third_manager = manager(&ca);
    let third_lease =
        sign_in(&third, &third_manager, &deployment.origin, &username, third_password).await;
    assert_eq!(third_lease.account().unwrap().account_id, original.account().unwrap().account_id);
    assert_eq!(
        third_lease.account().unwrap().personal_vault_id,
        original.account().unwrap().personal_vault_id
    );
    assert_ne!(third_lease.account().unwrap().device_id, original.account().unwrap().device_id);
    let third_store = third.store(&third_lease);
    settings
        .synchronize(&third_manager, third_store.clone(), None)
        .await
        .expect("final-password admitted Device downloads and decrypts the same Personal Host");
    assert_eq!(third_store.get(shared.id).unwrap(), Some(final_host));
    let current = third_store.personal_record().unwrap().unwrap();
    let old_keys = identity::Secrets::parse(&identity.private_material).unwrap();
    let new_keys = identity::Secrets::parse(&current.private_material).unwrap();
    assert_eq!(SymmetricKey::from_slice(old_keys.ark()), SymmetricKey::from_slice(new_keys.ark()));
    assert_eq!(
        SymmetricKey::from_slice(old_keys.account_signing()),
        SymmetricKey::from_slice(new_keys.account_signing())
    );
    assert_eq!(
        SymmetricKey::from_slice(old_keys.account_kem()),
        SymmetricKey::from_slice(new_keys.account_kem())
    );
    drop((
        third_store,
        store,
        second_store,
        third_lease,
        original,
        second_lease,
        third,
        first,
        second,
    ));
    directory.close();
}
