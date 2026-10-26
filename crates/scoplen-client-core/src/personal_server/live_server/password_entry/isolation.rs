// SPDX-License-Identifier: Apache-2.0
//! Independent Accounts on one deployment keep Personal discovery, keys and objects separate.

use scoplen_api::ProblemDetails;
use scoplen_crypto::{DpopProof, DpopTarget, DpopToken};

use super::*;

async fn unavailable_keys(
    manager: &PersonalServer,
    store: &Arc<Store>,
    vault_id: uuid::Uuid,
) -> ProblemDetails {
    let retained = record(store).expect("current authenticated Account identity");
    let access = store
        .personal_access_token(now().expect("current time"))
        .expect("load current real token")
        .expect("usable real token");
    let token = std::str::from_utf8(access.as_bytes()).expect("real access token encoding");
    let secrets =
        identity::Secrets::parse(&retained.private_material).expect("retained Device keys");
    let signing = P256SigningKey::from_bytes(secrets.signing()).expect("retained signing key");
    let path = format!("/sync/v1/vaults/{vault_id}/keys");
    let target = DpopTarget::new("GET", &retained.origin, &path).expect("exact protected target");
    let proof = DpopProof::sign(
        &signing,
        &signing.public_key_sec1(),
        &target,
        DpopToken::Protected(token),
        now().expect("fresh proof time"),
        None,
    )
    .expect("fresh real Device proof");
    let response = manager
        .transport
        .as_ref()
        .expect("trusted HTTPS transport")
        .protected(&retained.origin, &path, None, token, &proof, 16_384)
        .await
        .expect("foreign/absent vault request through real HTTPS");
    assert_eq!(response.status, 404);
    assert!(response.problem_cbor);
    let problem =
        ProblemDetails::from_cbor(response.body.as_bytes()).expect("strict shared CBOR problem");
    assert_eq!(problem.status, 404);
    assert_eq!(problem.code.as_str(), "sync.object_not_found");
    assert!(!problem.changed && !problem.retryable);
    problem
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn verify(
    deployment: &PasswordDeployment,
    directory: &Path,
    ca: &[u8],
    first_manager: &PersonalServer,
    first_store: &Arc<Store>,
    first_host: &scoplen_model::Object,
    created_teams: &[TeamSummary],
) -> scoplen_model::Object {
    let other = Device::new(&directory.join("other-account"));
    let other_manager = manager(ca);
    let suffix = scoplen_model::new_uuid_v7().expect("independent Account name");
    let lease = register(
        &other,
        &other_manager,
        &deployment.origin,
        &format!("other-{}", suffix.simple()),
        SecretVec::new(format!("Disposable other Account {suffix}").into_bytes()),
        &directory.join("other-recovery.txt"),
    )
    .await;
    let other_profile = lease.account().expect("independent Account metadata");
    let first_identity = record(first_store).expect("original Account identity");
    assert_ne!(other_profile.account_id, first_identity.account_id);
    assert_ne!(other_profile.personal_vault_id, first_identity.personal_vault_id);
    let other_store = other.store(&lease);
    teams::verify_isolation(
        first_manager,
        first_store,
        &other_manager,
        &other_store,
        created_teams,
    )
    .await;
    let settings = PersonalInventorySettings::default();
    settings
        .synchronize(&other_manager, other_store.clone(), None)
        .await
        .expect("the other Account synchronizes only its empty Personal vault");
    assert!(other_store.list(ObjectType::HOST).expect("independent empty inventory").is_empty());
    let bootstrap = other_manager
        .load_sync_bootstrap(&other_store)
        .expect("locally verified other Account bootstrap")
        .expect("retained bootstrap");
    assert_eq!(bootstrap.session().vaults.len(), 1);
    assert_eq!(bootstrap.session().vaults[0].id, other_profile.personal_vault_id);

    for (manager, store, foreign_vault) in [
        (&other_manager, &other_store, first_identity.personal_vault_id),
        (first_manager, first_store, other_profile.personal_vault_id),
    ] {
        let absent = unavailable_keys(
            manager,
            store,
            scoplen_model::new_uuid_v7().expect("absent vault id"),
        )
        .await;
        let foreign = unavailable_keys(manager, store, foreign_vault).await;
        assert_eq!(foreign.problem_type, absent.problem_type);
        assert_eq!(foreign.title, absent.title);
        assert_eq!(foreign.detail, absent.detail);
    }

    let other_host = host(&other_store, "Private Host of the other Account");
    let review = settings.preview(&other_store, vec![other_host.id.to_string()]).expect("review");
    assert!(review.missing.is_empty() && review.token.is_some());
    let uploaded = settings
        .synchronize(&other_manager, other_store.clone(), review.token)
        .await
        .expect("publish only the other Account's reviewed Host");
    assert_eq!(uploaded.uploaded, 1);
    settings
        .synchronize(first_manager, first_store.clone(), None)
        .await
        .expect("original Account still synchronizes normally");
    assert_eq!(
        other_store.list(ObjectType::HOST).expect("other inventory"),
        vec![other_host.clone()]
    );
    assert!(other_store.get(first_host.id).expect("no original Account Host").is_none());
    assert_eq!(
        first_store.get(first_host.id).expect("original Host retained"),
        Some(first_host.clone())
    );
    assert!(first_store.get(other_host.id).expect("no other Account Host").is_none());
    let progress = settings.status(&other_store).expect("other Account durable progress");
    assert_eq!(progress.pending, 0);
    assert_eq!(progress.applied_cursor, progress.acknowledged_cursor);
    other_host
}
