// SPDX-License-Identifier: Apache-2.0
//! Actual SSH trust acceptance crosses the production encrypted Personal sync path.

use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::connection::preparation::{
    PreparationControl, PreparationEvent, PreparationResponse, prepare_connection,
};
use crate::connection::{HostKeyPresentation, HostKeyStatus, HostKeyTrustSource, assess_host_key};
use crate::inventory::{Inventory, NewHost, SignIn};
use crate::repository::{AccessProfile, Repository, TrustRecord};

pub(super) struct Receipt {
    host: uuid::Uuid,
    key: HostKeyPresentation,
    source: HostKeyTrustSource,
    objects: Vec<scoplen_model::Object>,
}

pub(super) async fn verify(devices: [(&PersonalServer, &Arc<Store>); 3]) -> Receipt {
    let ssh = crate::connection::test_peer::Peer::start().await;
    let (manager, source) = devices[0];
    let details = Inventory::new(source.clone())
        .add_host(NewHost {
            name: Some("Personal trust propagation SSH peer".into()),
            address: "127.0.0.1".into(),
            port: Some(ssh.port),
            username: "trust-fixture".into(),
            sign_in: SignIn::Password { password: "disposable-trust-password".into() },
        })
        .unwrap();
    let host = uuid::Uuid::parse_str(&details.summary.id).unwrap();
    let profile = uuid::Uuid::parse_str(&details.logins[0].id).unwrap();
    let control = PreparationControl::default();
    let confirmations = AtomicUsize::new(0);
    let connection = prepare_connection(source, profile, &control, |event| {
        if let PreparationEvent::Trust { prompt_id, .. } = event {
            assert_eq!(ssh.authentications.load(Ordering::SeqCst), 0);
            confirmations.fetch_add(1, Ordering::SeqCst);
            control.respond(&prompt_id, PreparationResponse::AcceptHostKey)?;
        }
        Ok(())
    })
    .await
    .expect("confirm the actual SSH key before original-device authentication");
    connection.close().await.unwrap();
    assert_eq!(confirmations.load(Ordering::SeqCst), 1);
    let record = Repository::<TrustRecord>::new(source)
        .list()
        .unwrap()
        .into_iter()
        .find(|record| record.host == Some(host))
        .expect("production confirmation persists provenance");
    assert_eq!(record.accepted_by_device, Some(source.device_id()));
    assert_eq!(record.accepted_by_account, Some(record_account(source)));
    let credential =
        Repository::<AccessProfile>::new(source).get(profile).unwrap().unwrap().credential.unwrap();
    let ids = [host, profile, credential, record.meta.id];
    let settings = PersonalInventorySettings::default();
    for (_, store) in devices.iter().skip(1) {
        assert!(store.get(host).unwrap().is_none());
        assert!(store.get(record.meta.id).unwrap().is_none());
    }
    let preview = settings.preview(source, ids.iter().map(|id| id.to_string()).collect()).unwrap();
    assert!(preview.missing.is_empty());
    let result = settings
        .synchronize(manager, source.clone(), preview.token)
        .await
        .expect("explicitly adopt the host, Login, Credential and generated trust record");
    assert_eq!(result.uploaded, 4);
    let receipt = Receipt {
        host,
        key: ssh.key.clone(),
        source: assess_host_key(source, host, &ssh.key).unwrap().source.unwrap(),
        objects: ids.into_iter().map(|id| source.get(id).unwrap().unwrap()).collect(),
    };
    for (manager, store) in devices.iter().skip(1) {
        let result = settings
            .synchronize(manager, (*store).clone(), None)
            .await
            .expect("another real enrolled device verifies and decrypts the trust record");
        assert_eq!(result.uploaded, 0);
        assert_offline(store, &receipt);
        let connection =
            prepare_connection(store, profile, &PreparationControl::default(), |event| {
                assert!(
                    !matches!(event, PreparationEvent::Trust { .. }),
                    "verified same-user source is adopted without another trust prompt"
                );
                if let PreparationEvent::Verified { source: adopted, .. } = event {
                    assert_eq!(adopted.device_id, receipt.source.device_id);
                    assert_eq!(adopted.device_name, receipt.source.device_name);
                    assert_eq!(adopted.accepted_at, receipt.source.accepted_at);
                    assert!(!adopted.current);
                }
                Ok(())
            })
            .await
            .expect("replicated Personal trust authorizes an actual SSH password connection");
        connection.close().await.unwrap();
    }
    assert_eq!(ssh.authentications.load(Ordering::SeqCst), 3);
    receipt
}

fn record_account(store: &Store) -> uuid::Uuid {
    super::super::record(store).unwrap().account_id
}

pub(super) fn assert_offline(store: &Store, receipt: &Receipt) {
    for object in &receipt.objects {
        assert!(
            store.get(object.id).unwrap().as_ref() == Some(object),
            "encrypted reopen retains the exact synchronized inventory"
        );
    }
    let assessment = assess_host_key(store, receipt.host, &receipt.key).unwrap();
    assert_eq!(assessment.status, HostKeyStatus::Trusted);
    let source = assessment.source.unwrap();
    assert_eq!(source.device_id, receipt.source.device_id);
    assert_eq!(source.device_name, receipt.source.device_name);
    assert_eq!(source.accepted_at, receipt.source.accepted_at);
    assert!(!source.imported);
}
