// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{
    inventory::{HostDetails, Inventory, NewHost, OpenSshGeneratedError, SignIn},
    portable_archive::ArchiveDestination,
    repository::{AccessProfile, Repository},
};
use std::sync::Arc;

fn fixture() -> (tempfile::TempDir, Arc<Store>, Inventory) {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(
        Store::open(
            &directory.path().join("inventory.db"),
            &scoplen_crypto::LocalDatabaseKey::new([41; 32]),
        )
        .unwrap(),
    );
    let inventory = Inventory::new(store.clone());
    (directory, store, inventory)
}

fn password(inventory: &Inventory, name: &str) -> HostDetails {
    inventory
        .add_host(NewHost {
            name: Some(name.into()),
            address: "fixture.example".into(),
            port: Some(2200),
            username: "deploy".into(),
            sign_in: SignIn::Password { password: "generated-scope-fixture".into() },
        })
        .unwrap()
}

#[test]
fn scope_predicates_exclude_other_vaults_and_personal_omits_retained_local_inventory() {
    let (_directory, store, inventory) = fixture();
    password(&inventory, "Local");
    let personal = password(&inventory, "Personal");
    let foreign = password(&inventory, "LOCAL");
    let vault = Uuid::now_v7();
    let other = Uuid::now_v7();
    let move_host = |host: &HostDetails, vault: Uuid| {
        let login = Repository::<AccessProfile>::new(&store)
            .get(Uuid::parse_str(&host.logins[0].id).unwrap())
            .unwrap()
            .unwrap();
        for id in
            [Uuid::parse_str(&host.summary.id).unwrap(), login.meta.id, login.credential.unwrap()]
        {
            store
                .conn()
                .execute(
                    "UPDATE objects SET vault=?1 WHERE id=?2",
                    params![vault.as_bytes().as_slice(), id.as_bytes().as_slice()],
                )
                .unwrap();
        }
    };
    move_host(&personal, vault);
    move_host(&foreign, other);
    let local = inventory.preview_generated_open_ssh(vec![]).unwrap();
    assert_eq!(local.destination, ArchiveDestination::Local);
    assert_eq!(local.report.entries.len(), 1);
    assert_eq!(local.report.entries[0].host_name, "Local");
    assert_eq!(local.aliases[0].alias.as_deref(), Some("local"));
    let foreign_credential = Repository::<AccessProfile>::new(&store)
        .get(Uuid::parse_str(&foreign.logins[0].id).unwrap())
        .unwrap()
        .unwrap()
        .credential
        .unwrap();
    store.conn().execute(
        "INSERT INTO openssh_import_sources(source,source_key,source_file,object_id) VALUES('fixture','credential:foreign','ignored-source',?1)",
        params![foreign_credential.as_bytes().as_slice()],
    ).unwrap();
    assert_eq!(
        inventory.preview_generated_open_ssh(vec![]).unwrap().report.revision,
        local.report.revision
    );
    let account = Uuid::now_v7();
    {
        let conn = store.conn();
        conn.execute("INSERT INTO personal_server(singleton,origin,account_id,personal_vault_id,device_name,private_material,enrollment_attempted) VALUES(1,'https://example.test',?1,?2,'test',X'00',1)",params![account.as_bytes().as_slice(),vault.as_bytes().as_slice()]).unwrap();
        conn.execute("INSERT INTO personal_sync VALUES(1,1,X'01',X'01',X'01')", []).unwrap();
        conn.execute("INSERT INTO personal_admission SELECT 1,p.origin,p.account_id,p.personal_vault_id,d.device_id,X'01' FROM personal_server p,device d WHERE p.singleton=1 AND d.singleton=1", []).unwrap();
    }
    let personal = inventory.preview_generated_open_ssh(vec![]).unwrap();
    assert_eq!(
        personal.destination,
        ArchiveDestination::Personal { owner_id: account.to_string(), vault_id: vault.to_string() }
    );
    assert_eq!(personal.report.entries.len(), 1);
    assert_eq!(personal.report.entries[0].host_name, "Personal");
    assert_eq!(
        inventory.recheck_generated_open_ssh(&local),
        Err(OpenSshGeneratedError::ContextChanged)
    );
    store
        .conn()
        .execute("UPDATE personal_server SET auth_generation=auth_generation+1", [])
        .unwrap();
    assert_eq!(
        inventory.recheck_generated_open_ssh(&personal),
        Err(OpenSshGeneratedError::InventoryChanged)
    );
}
