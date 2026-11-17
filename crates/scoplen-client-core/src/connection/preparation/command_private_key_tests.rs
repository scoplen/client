// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::connection::test_peer::{Authentication, Peer};
use crate::repository::{Credential, CredentialChange};
use scoplen_crypto::LocalDatabaseKey;
use ssh_key::{Algorithm, Cipher, Kdf, PrivateKey};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::atomic::{AtomicUsize, Ordering},
};

pub(super) fn login(store: &Store, port: u16, directory: &Path, material: &[u8]) -> (Uuid, Uuid) {
    let key = directory.join("helper-key");
    let marker = directory.join("called");
    let script = directory.join(if cfg!(windows) { "helper.ps1" } else { "helper.sh" });
    std::fs::write(&key, material).unwrap();
    std::fs::write(&script, if cfg!(windows) {
        "[IO.File]::AppendAllText($args[1], '+'); $output = [Console]::OpenStandardOutput(); $bytes = [IO.File]::ReadAllBytes($args[0]); $output.Write($bytes, 0, $bytes.Length)"
    } else { "printf + >> \"$2\"; cat \"$1\"" }).unwrap();
    let path = if cfg!(windows) {
        format!(
            "powershell.exe -NoProfile -NonInteractive -File \"{}\" \"{}\" \"{}\"",
            script.display(),
            key.display(),
            marker.display()
        )
    } else {
        format!("/bin/sh \"{}\" \"{}\" \"{}\"", script.display(), key.display(), marker.display())
    };
    let (profile, credential) = super::command_password_tests::login(store, port, path, true);
    Repository::<Credential>::new(store)
        .update(
            credential,
            CredentialChange {
                provider: BTreeMap::from([("field".into(), Some("private_key".into()))]),
                ..Default::default()
            },
        )
        .unwrap();
    (profile, credential)
}

fn encrypted(key: &PrivateKey) -> PrivateKey {
    key.encrypt_with(
        Cipher::Aes256Ctr,
        Kdf::Bcrypt { salt: vec![7; 16], rounds: 1 },
        42,
        b"disposable-passphrase",
    )
    .unwrap()
}

#[tokio::test]
async fn fetched_key_retries_local_decryption_once_then_continues_existing_factors_or_cancels() {
    for cancel in [false, true] {
        let peer = Peer::with_authentication(Authentication::KeyThenInteractive).await;
        let directory = tempfile::tempdir().unwrap();
        let store =
            Store::open(&directory.path().join("local.db"), &LocalDatabaseKey::new([7; 32]))
                .unwrap();
        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .unwrap();
        let material = encrypted(&key).to_openssh(ssh_key::LineEnding::LF).unwrap();
        let (profile, credential) = login(&store, peer.port, directory.path(), material.as_bytes());
        let control = PreparationControl::default();
        let commands = AtomicUsize::new(0);
        let passphrases = AtomicUsize::new(0);
        let rounds = AtomicUsize::new(0);
        let events = Mutex::new(Vec::new());
        let result = prepare_connection(&store, profile, &control, |event| {
            events.lock().unwrap().push(format!("{event:?}"));
            match event {
                PreparationEvent::Trust { prompt_id, .. } => {
                    control.respond(&prompt_id, PreparationResponse::AcceptHostKey)?
                }
                PreparationEvent::CommandExecution { prompt_id, .. } => {
                    commands.fetch_add(1, Ordering::SeqCst);
                    control.respond(&prompt_id, PreparationResponse::AcceptCommand)?;
                }
                PreparationEvent::Passphrase { prompt_id, incorrect, .. } => {
                    assert_eq!(std::fs::read(directory.path().join("called")).unwrap(), b"+");
                    let attempt = passphrases.fetch_add(1, Ordering::SeqCst);
                    assert_eq!(incorrect, attempt != 0);
                    if cancel {
                        control.cancel();
                    } else {
                        control.respond(
                            &prompt_id,
                            PreparationResponse::Passphrase(SecretVec::new(if attempt == 0 {
                                b"wrong-passphrase".to_vec()
                            } else {
                                b"disposable-passphrase".to_vec()
                            })),
                        )?;
                    }
                }
                PreparationEvent::KeyboardInteractive { prompt_id, .. } => {
                    assert_eq!(passphrases.load(Ordering::SeqCst), 2);
                    let answers = match rounds.fetch_add(1, Ordering::SeqCst) {
                        0 => vec![b"visible".to_vec(), vec![]],
                        1 => vec![],
                        _ => vec![b"123456".to_vec()],
                    };
                    control
                        .respond(&prompt_id, PreparationResponse::keyboard_interactive(answers)?)?;
                }
                _ => {}
            }
            Ok(())
        })
        .await;
        if cancel {
            assert_eq!(result.err().unwrap().to_string(), "connection was cancelled");
            assert_eq!(peer.authentications.load(Ordering::SeqCst), 0);
            assert_eq!(passphrases.load(Ordering::SeqCst), 1);
        } else {
            result.unwrap().close().await.unwrap();
            assert_eq!(peer.authentications.load(Ordering::SeqCst), 1);
            assert_eq!(rounds.load(Ordering::SeqCst), 3);
        }
        assert_eq!(commands.load(Ordering::SeqCst), 1);
        assert_eq!(std::fs::read(directory.path().join("called")).unwrap(), b"+");
        assert!(crate::repository::credential_secret(&store, credential).unwrap().is_none());
        assert!(store.device_credential(credential).unwrap().is_none());
        let events = events.lock().unwrap().join("\n");
        assert!(!events.contains("OPENSSH PRIVATE KEY"));
        assert!(!events.contains(material.as_str()));
        assert!(!events.contains("disposable-passphrase"));
        assert!(!events.contains(&key.public_key().to_openssh().unwrap()));
    }
}

#[tokio::test]
async fn fetched_invalid_unsupported_and_over_budget_keys_fail_before_passphrase_or_signing() {
    let mut rng = ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng);
    let key = PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap();
    let public = ssh_key::public::SkEd25519::new(
        *key.public_key().key_data().ed25519().unwrap(),
        "ssh:fixture",
    );
    let sk = ssh_key::private::SkEd25519::new(public, 0, vec![7]).unwrap();
    let unsupported =
        PrivateKey::new(ssh_key::private::KeypairData::SkEd25519(sk), "fixture").unwrap();
    let mut raw = encrypted(&key).to_bytes().unwrap();
    let mut offset = b"openssh-key-v1\0".len();
    for _ in 0..2 {
        let length = u32::from_be_bytes(raw[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4 + length;
    }
    let salt_length = u32::from_be_bytes(raw[offset + 4..offset + 8].try_into().unwrap()) as usize;
    let rounds = offset + 8 + salt_length;
    raw[rounds..rounds + 4]
        .copy_from_slice(&(super::super::MAX_PRIVATE_KEY_BCRYPT_ROUNDS + 1).to_be_bytes());
    let excessive = PrivateKey::from_bytes(raw.as_slice()).unwrap();
    for (material, expected) in [
        (zeroize::Zeroizing::new("not a private key".into()), "private key is invalid"),
        (unsupported.to_openssh(ssh_key::LineEnding::LF).unwrap(), "algorithm is not supported"),
        (
            encrypted(&unsupported).to_openssh(ssh_key::LineEnding::LF).unwrap(),
            "algorithm is not supported",
        ),
        (
            excessive.to_openssh(ssh_key::LineEnding::LF).unwrap(),
            "unsupported passphrase work parameters",
        ),
    ] {
        let peer = Peer::with_authentication(Authentication::KeyThenInteractive).await;
        let directory = tempfile::tempdir().unwrap();
        let store =
            Store::open(&directory.path().join("local.db"), &LocalDatabaseKey::new([7; 32]))
                .unwrap();
        let (profile, _) = login(&store, peer.port, directory.path(), material.as_bytes());
        let control = PreparationControl::default();
        let result = prepare_connection(&store, profile, &control, |event| {
            match event {
                PreparationEvent::Trust { prompt_id, .. } => {
                    control.respond(&prompt_id, PreparationResponse::AcceptHostKey)?
                }
                PreparationEvent::CommandExecution { prompt_id, .. } => {
                    control.respond(&prompt_id, PreparationResponse::AcceptCommand)?
                }
                PreparationEvent::Passphrase { .. }
                | PreparationEvent::KeyboardInteractive { .. } => {
                    panic!("unusable key reached a secret prompt")
                }
                _ => {}
            }
            Ok(())
        })
        .await;
        assert!(result.err().unwrap().to_string().contains(expected));
        assert_eq!(peer.authentications.load(Ordering::SeqCst), 0);
        assert_eq!(std::fs::read(directory.path().join("called")).unwrap(), b"+");
    }
}
