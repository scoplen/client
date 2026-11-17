// SPDX-License-Identifier: Apache-2.0
//! Independent real denial, exact access application, approval history and ordinary SSH/SFTP.

use std::io::Write as _;
use tokio::sync::mpsc;

use crate::{
    connection::{
        SessionTarget,
        preparation::{PreparationEvent, PreparationResponse},
    },
    personal_server::{
        TeamAccessRequestDraft, TeamAccessRequests, TeamAuthoringCollection as Collection,
        TeamAuthoringData as Data, TeamCreationPhase, TeamSshPolicyDenial, TeamSshSource,
    },
    session_manager::{SessionEvent, SessionManager},
};

use super::{
    team_ssh::{SshFixture, terminal_and_files},
    *,
};

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExpectedOutcome {
    SshSftp,
    IssuanceDenied,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestTeamDeployment {
    disposable: bool,
    origin: String,
    ca_certificate: PathBuf,
    organization_id: String,
    host_id: String,
    profile_id: String,
    owner_username: String,
    owner_password_file: PathBuf,
    member_username: String,
    member_password_file: PathBuf,
    expected_outcome: ExpectedOutcome,
    #[serde(deserialize_with = "required_cutoff")]
    certificate_not_after: Option<u64>,
    #[serde(deserialize_with = "required_request")]
    request_id: Option<String>,
    request_duration_seconds: u32,
    request_reason: String,
}

fn required_cutoff<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u64>, D::Error> {
    let value = Option::<u64>::deserialize(deserializer)?;
    if value.is_some_and(|value| value > 253_402_300_799) {
        return Err(serde::de::Error::custom("invalid certificate cutoff"));
    }
    Ok(value)
}

fn required_request<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    let value = Option::<String>::deserialize(deserializer)?;
    if let Some(value) = &value {
        let id = uuid::Uuid::parse_str(value)
            .map_err(|_| serde::de::Error::custom("invalid request id"))?;
        scoplen_model::validate_uuid_v7(id)
            .map_err(|_| serde::de::Error::custom("invalid request id"))?;
        if id.to_string() != *value {
            return Err(serde::de::Error::custom("noncanonical request id"));
        }
    }
    Ok(value)
}

struct RequestInput<'a> {
    duration_seconds: u32,
    reason: &'a str,
}

async fn denied_terminal(
    personal: &PersonalServer,
    store: Arc<Store>,
    target: &SessionTarget,
    expected: &TeamSshPolicyDenial,
    application: Option<RequestInput<'_>>,
) -> Option<String> {
    let sessions = SessionManager::default();
    let requests = TeamAccessRequests::default();
    let id = "request-policy-denial";
    sessions.reserve(id, true).unwrap();
    let (failure_tx, mut failure_rx) = mpsc::unbounded_channel();
    let terminal = sessions.run_target(
        id,
        target,
        personal,
        None,
        true,
        store.clone(),
        |event| {
            match event {
                SessionEvent::Preparation { transport_id, event } => {
                    if let PreparationEvent::Trust { prompt_id, .. } = *event {
                        sessions.respond(
                            id,
                            &transport_id,
                            &prompt_id,
                            PreparationResponse::AcceptHostKey,
                        )?;
                    }
                }
                SessionEvent::Failed { team_ssh_policy_denial, .. } => {
                    failure_tx
                        .send(team_ssh_policy_denial)
                        .map_err(|_| "denial receiver closed")?;
                }
                SessionEvent::Ready { .. } => {
                    return Err("request fixture unexpectedly authorized a connection".into());
                }
                _ => {}
            }
            Ok(())
        },
        |_, _| Err("denied fixture received terminal output".into()),
        |_, _| {},
    );
    let exercise = async {
        let denial = failure_rx
            .recv()
            .await
            .expect("actual completed ordinary terminal refusal")
            .expect("authenticated certificate-policy refusal");
        assert_eq!(&denial, expected);
        let request = if let Some(application) = application {
            let checked = requests
                .check(
                    personal,
                    &sessions,
                    store.clone(),
                    id,
                    TeamAccessRequestDraft {
                        duration_seconds: application.duration_seconds,
                        reason: application.reason.into(),
                    },
                )
                .await
                .expect("check eligibility for the actual denied terminal target");
            assert!(checked.allowed);
            assert_eq!(checked.source, expected.source);
            assert_eq!(checked.fields.host_id, expected.host_id);
            assert_eq!(checked.fields.remote_user, expected.remote_user);
            assert_eq!(checked.fields.duration_seconds, application.duration_seconds);
            assert_eq!(checked.fields.reason, application.reason);
            assert!(
                requests.pending(&store, &expected.source.organization_id).unwrap().is_none(),
                "checking must create no application"
            );
            let prepared = requests
                .prepare_create(personal, &store, checked.check_id.as_deref().unwrap())
                .unwrap();
            assert_eq!(prepared.phase, TeamCreationPhase::Prepared);
            let confirmed = requests
                .submit(
                    personal,
                    store.clone(),
                    &expected.source.organization_id,
                    &prepared.operation_id,
                )
                .await
                .expect("explicitly submit the checked exact application");
            assert_eq!(confirmed.phase, TeamCreationPhase::Confirmed);
            let resource = confirmed.result.as_ref().unwrap();
            assert_eq!(resource.status, "pending");
            assert_eq!(resource.fields, checked.fields);
            assert_eq!(resource.requester_account_id, expected.source.account_id);
            let reviewed = requests
                .review(
                    personal,
                    store.clone(),
                    &expected.source.organization_id,
                    &prepared.request_id,
                )
                .await
                .unwrap();
            assert_eq!(reviewed.resource.id, prepared.request_id);
            assert_eq!(reviewed.resource.status, "pending");
            assert!(
                reviewed.resource.can_cancel
                    && !reviewed.resource.can_decide
                    && !reviewed.resource.can_connect
            );
            assert!(requests.connection_targets(personal, &store, &reviewed.intent_id).is_err());
            Some(prepared.request_id)
        } else {
            None
        };
        sessions.close(id).unwrap();
        request
    };
    let (terminal, request) =
        tokio::time::timeout(Duration::from_secs(120), async { tokio::join!(terminal, exercise) })
            .await
            .expect("bounded real denied-terminal/application journey");
    terminal.expect("close the denied ordinary terminal");
    request
}

async fn consume(
    deployment: &RequestTeamDeployment,
    ssh: SshFixture,
    directory: &Path,
) -> (&'static str, serde_json::Value) {
    ssh.verify().await;
    let ca = bounded_file(&deployment.ca_certificate, 65_536);
    let owner_device = Device::new(&directory.join("owner"));
    let member_device = Device::new(&directory.join("member"));
    let owner = manager(&ca);
    let member = manager(&ca);
    let owner_lease = sign_in(
        &owner_device,
        &owner,
        &deployment.origin,
        &deployment.owner_username,
        SecretVec::new(bounded_file(&deployment.owner_password_file, 4096)),
    )
    .await;
    let member_lease = sign_in(
        &member_device,
        &member,
        &deployment.origin,
        &deployment.member_username,
        SecretVec::new(bounded_file(&deployment.member_password_file, 4096)),
    )
    .await;
    let owner_store = owner_device.store(&owner_lease);
    let member_store = member_device.store(&member_lease);
    assert_ne!(record(&owner_store).unwrap().account_id, record(&member_store).unwrap().account_id);
    let host = owner
        .team_authoring_resource(
            owner_store.clone(),
            &deployment.organization_id,
            Collection::Host,
            &deployment.host_id,
        )
        .await
        .unwrap();
    let Data::Host(host) = host.data else { panic!("expected existing prepared Host") };
    assert_eq!(host.address, "127.0.0.1");
    assert_eq!(host.port, Some(ssh.port));
    let profile = owner
        .team_authoring_resource(
            owner_store.clone(),
            &deployment.organization_id,
            Collection::Login,
            &deployment.profile_id,
        )
        .await
        .unwrap();
    let Data::Login(profile) = profile.data else { panic!("expected existing prepared Login") };
    assert_eq!(profile.host, deployment.host_id);
    assert_eq!(profile.username, "smoke");
    member.refresh_team_assets(member_store.clone(), &deployment.organization_id).await.unwrap();
    let source = TeamSshSource {
        origin: deployment.origin.clone(),
        account_id: record(&member_store).unwrap().account_id.to_string(),
        organization_id: deployment.organization_id.clone(),
        device_id: member_store.device_id().to_string(),
    };
    let trust = member
        .team_user_ca(member_store.clone(), &source)
        .await
        .unwrap()
        .expect("existing prepared user CA");
    let setup = trust
        .setups
        .iter()
        .find(|setup| setup.profile_id == deployment.profile_id)
        .expect("the prepared Login has an authenticated CA setup");
    assert_eq!(setup.host_id, deployment.host_id);
    assert_eq!(setup.remote_user, profile.username);
    ssh.install(&trust.public_key, &setup.principal).await;
    let ordinary = SessionTarget::Organization {
        source: source.clone(),
        profile_id: deployment.profile_id.clone(),
    };
    let denial = TeamSshPolicyDenial {
        source: source.clone(),
        host_id: deployment.host_id.clone(),
        remote_user: profile.username.clone(),
    };
    match (&deployment.request_id, deployment.expected_outcome) {
        (None, ExpectedOutcome::IssuanceDenied) => {
            let request = denied_terminal(
                &member,
                member_store,
                &ordinary,
                &denial,
                Some(RequestInput {
                    duration_seconds: deployment.request_duration_seconds,
                    reason: &deployment.request_reason,
                }),
            )
            .await
            .unwrap();
            (
                "before",
                serde_json::json!({"request_id": request, "host_id": deployment.host_id,
                "remote_user": profile.username, "duration_seconds": deployment.request_duration_seconds, "status":"pending"}),
            )
        }
        (Some(request), outcome) => {
            let requests = TeamAccessRequests::default();
            let reviewed = requests
                .review(&member, member_store.clone(), &deployment.organization_id, request)
                .await
                .expect("read the independently approved original application");
            let resource = &reviewed.resource;
            assert_eq!(resource.id, *request);
            assert_eq!(resource.source, source);
            assert_eq!(resource.requester_account_id, source.account_id);
            assert_eq!(resource.fields.host_id, deployment.host_id);
            assert_eq!(resource.fields.remote_user, profile.username);
            assert_eq!(resource.fields.duration_seconds, deployment.request_duration_seconds);
            assert_eq!(resource.fields.reason, deployment.request_reason);
            assert_eq!(resource.status, "approved");
            assert!(!resource.can_cancel && !resource.can_decide);
            assert_ne!(resource.decision.as_ref().unwrap().actor_account_id, source.account_id);
            match outcome {
                ExpectedOutcome::SshSftp => {
                    let matching = requests
                        .connection_targets(&member, &member_store, &reviewed.intent_id)
                        .unwrap();
                    let selected = matching
                        .into_iter()
                        .find(|login| login.target.profile_id() == deployment.profile_id)
                        .expect(
                            "currently visible ordinary Login matches the original exact target",
                        );
                    assert!(
                        matches!(&selected.target, SessionTarget::OrganizationAccessRequest { host_id, remote_user, .. }
                        if host_id == &deployment.host_id && remote_user == &profile.username)
                    );
                    terminal_and_files(&member, member_store.clone(), &selected.target, directory)
                        .await;
                    let certificate = member
                        .team_ssh_certificate(
                            member_store,
                            &source,
                            deployment.host_id.parse().unwrap(),
                            &profile.username,
                        )
                        .await
                        .expect(
                            "inspect the certificate obtained by the explicit ordinary terminal",
                        );
                    assert!(certificate.cached);
                    assert!(
                        certificate.certificate.certificate().valid_before()
                            <= deployment.certificate_not_after.unwrap()
                    );
                    (
                        "active",
                        serde_json::json!({"request_id":request,"status":"approved","ssh_sftp":true}),
                    )
                }
                ExpectedOutcome::IssuanceDenied => {
                    assert!(member.team_ssh_operations(&member_store, &source).unwrap().is_empty());
                    assert!(
                        denied_terminal(&member, member_store, &ordinary, &denial, None)
                            .await
                            .is_none()
                    );
                    (
                        "withdrawn",
                        serde_json::json!({"request_id":request,"status":"approved","issuance_denied":true}),
                    )
                }
            }
        }
        _ => panic!("invalid independent request handoff phase"),
    }
}

#[tokio::test]
async fn live_host_access_request_ordinary_ssh_and_binary_sftp() {
    let artifact = std::env::var_os("SCOPLEN_LIVE_HOST_ACCESS_REQUEST_DEPLOYMENT")
        .expect("provide the private access-request handoff");
    let artifact = Path::new(&artifact);
    assert!(artifact.is_absolute());
    let deployment: RequestTeamDeployment =
        serde_json::from_slice(&bounded_file(artifact, 8192)).unwrap();
    assert!(deployment.disposable);
    assert!(
        deployment.ca_certificate.is_absolute()
            && deployment.owner_password_file.is_absolute()
            && deployment.member_password_file.is_absolute()
    );
    assert!(
        deployment
            .origin
            .strip_prefix("https://localhost:")
            .and_then(|port| port.parse::<u16>().ok())
            .is_some_and(|port| port != 0)
    );
    assert!((1..=86_400).contains(&deployment.request_duration_seconds));
    scoplen_api::access_request::AccessRequestFields {
        host: deployment.host_id.parse().unwrap(),
        remote_user: "smoke".into(),
        duration_seconds: deployment.request_duration_seconds,
        reason: deployment.request_reason.clone(),
    }
    .validate()
    .unwrap();
    assert_eq!(
        deployment.certificate_not_after.is_some(),
        matches!(deployment.expected_outcome, ExpectedOutcome::SshSftp)
    );
    let ssh_path = std::env::var_os("SCOPLEN_LIVE_TEAM_SSH_FIXTURE")
        .expect("provide the owned OpenSSH fixture descriptor");
    let ssh: SshFixture =
        serde_json::from_slice(&bounded_file(Path::new(&ssh_path), 8192)).unwrap();
    let directory = OwnedDirectory::new();
    let (phase, completion) = consume(&deployment, ssh, directory.path()).await;
    directory.close();
    let completion_path =
        artifact.parent().unwrap().join(format!("request-client-{phase}.complete"));
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(completion_path)
        .expect("create only the previously absent successful phase evidence");
    let mut bytes = serde_json::to_vec(&completion).unwrap();
    bytes.push(b'\n');
    output.write_all(&bytes).unwrap();
    output.sync_all().unwrap();
}

#[test]
fn request_handoff_requires_canonical_explicit_request_and_exact_bounded_input() {
    let original = serde_json::json!({"disposable":true,"origin":"https://localhost:8443",
        "ca_certificate":"/fixture/ca.pem","organization_id":"01900000-0000-7000-8000-000000000001",
        "host_id":"01900000-0000-7000-8000-000000000002","profile_id":"01900000-0000-7000-8000-000000000003",
        "owner_username":"fixture-owner","owner_password_file":"/fixture/owner-password",
        "member_username":"fixture-member","member_password_file":"/fixture/member-password",
        "expected_outcome":"issuance_denied","certificate_not_after":null,"request_id":null,
        "request_duration_seconds":600,"request_reason":"Exact fixture request"});
    assert!(serde_json::from_value::<RequestTeamDeployment>(original.clone()).is_ok());
    for field in
        ["request_id", "certificate_not_after", "request_duration_seconds", "request_reason"]
    {
        let mut absent = original.clone();
        absent.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<RequestTeamDeployment>(absent).is_err());
    }
    for invalid in [
        serde_json::json!("not-an-id"),
        serde_json::json!(17),
        serde_json::json!("01900000-0000-7000-8000-00000000000A"),
    ] {
        let mut altered = original.clone();
        altered["request_id"] = invalid;
        assert!(serde_json::from_value::<RequestTeamDeployment>(altered).is_err());
    }
    let mut extended = original;
    extended["extra"] = serde_json::json!(true);
    assert!(serde_json::from_value::<RequestTeamDeployment>(extended).is_err());
}
