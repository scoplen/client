// SPDX-License-Identifier: Apache-2.0

//! The Scoplen desktop application shell: window management and the typed
//! IPC surface between the frontend and `scoplen-client-core`
//! (`scoplen-docs/11-client-architecture.md` §1, §4).

pub mod commands;
pub mod events;
pub mod frames;
pub mod inventory;
pub mod local_data;
pub mod personal_inventory;
pub mod personal_pairing;
pub mod personal_server;
pub mod session_transfers;
mod smoke;
pub mod ssh;
mod window_state;

use tauri::Manager as _;
use tauri_specta::{Builder, Event as _, collect_commands, collect_events};

/// Path of the generated frontend bindings, relative to this crate.
pub const BINDINGS_PATH: &str = "../web/app/src/ipc/bindings.ts";

/// The typed command surface. The frontend bindings are generated from it, so
/// the frontend and the core cannot drift.
pub fn ipc() -> Builder<tauri::Wry> {
    Builder::<tauri::Wry>::new()
        .commands(collect_commands![
            commands::app_info,
            commands::shell_ready,
            ssh::session_respond,
            ssh::session_reserve_transport,
            ssh::session_connect,
            ssh::session_input,
            ssh::session_resize,
            ssh::session_list_files,
            session_transfers::session_transfer_queue,
            session_transfers::session_enqueue_upload,
            session_transfers::session_enqueue_download,
            session_transfers::session_cancel_transfer,
            session_transfers::session_acknowledge_transfer,
            ssh::session_create_remote_directory,
            ssh::session_rename_remote_entry,
            ssh::session_delete_remote_entry,
            ssh::session_cancel_file_operation,
            ssh::session_retry_transport,
            ssh::session_stop_reconnecting,
            ssh::session_fail_transport,
            ssh::session_close_transport,
            ssh::session_save_output,
            inventory::session_saved_output,
            inventory::inventory_areas,
            inventory::inventory_groups,
            inventory::inventory_hosts,
            inventory::inventory_recent_sessions,
            inventory::session_open,
            inventory::session_close,
            inventory::session_reconnect,
            inventory::session_forget,
            inventory::inventory_host,
            inventory::inventory_add_host,
            inventory::inventory_set_favorite,
            inventory::inventory_update_host,
            inventory::inventory_create_group,
            inventory::inventory_update_group,
            inventory::inventory_access_profiles,
            inventory::inventory_forwards,
            inventory::inventory_create_access_profile,
            inventory::inventory_update_access_profile,
            inventory::inventory_delete_access_profile,
            inventory::inventory_restore_orphaned_host,
            inventory::inventory_restore_orphaned_object,
            inventory::inventory_credentials,
            inventory::inventory_create_credential,
            inventory::inventory_update_credential,
            inventory::inventory_delete_credential,
            inventory::inventory_routes,
            inventory::inventory_create_route,
            inventory::inventory_update_route,
            inventory::inventory_delete_route,
            inventory::inventory_delete_host,
            inventory::inventory_undo_delete,
            inventory::inventory_preview_open_ssh_config,
            inventory::inventory_import_open_ssh_config,
            inventory::choose_open_ssh_config,
            inventory::choose_key_file,
            local_data::local_data_status,
            local_data::unlock_local_data,
            local_data::create_local_passphrase,
            local_data::set_local_passphrase,
            local_data::remove_local_passphrase,
            local_data::start_with_empty_local_data,
            personal_server::personal_server_status,
            personal_server::personal_account_snapshot,
            personal_server::query_personal_account,
            personal_server::prepare_personal_enrollment,
            personal_server::save_personal_recovery_key,
            personal_server::confirm_personal_recovery_key,
            personal_server::submit_personal_enrollment,
            personal_server::authenticate_personal_server,
            personal_server::update_personal_invitation,
            personal_server::personal_sync_key_status,
            personal_server::connect_personal_sync,
            personal_server::personal_sync_background_status,
            personal_pairing::personal_pairing_status,
            personal_pairing::create_personal_pairing,
            personal_pairing::join_personal_pairing,
            personal_pairing::join_personal_pairing_image,
            personal_pairing::prepare_personal_pairing_watch,
            personal_pairing::watch_personal_pairing,
            personal_pairing::stop_personal_pairing_watch,
            personal_pairing::confirm_personal_pairing,
            personal_pairing::recover_personal_pairing,
            personal_pairing::cancel_personal_pairing,
            personal_inventory::personal_inventory_status,
            personal_inventory::preview_personal_inventory,
            personal_inventory::synchronize_personal_inventory,
            personal_inventory::restore_personal_inventory,
            personal_inventory::restore_personal_inventory_recovery,
            personal_inventory::query_personal_inventory_history,
            personal_inventory::restore_personal_inventory_history,
        ])
        .events(collect_events![
            events::StoreChanged,
            events::SessionChanged,
            events::PersonalSyncChanged
        ])
}

/// Writes the TypeScript bindings for [`ipc`] to `path`.
pub fn write_bindings(path: &std::path::Path) -> Result<(), specta_typescript::Error> {
    let header = "// SPDX-License-Identifier: Apache-2.0\n// Generated from src-tauri by `pnpm bindings`. Do not edit.\n";
    ipc().export(specta_typescript::Typescript::default().header(header), path)?;

    // Specta emits spaces before the newline for some documented union members.
    // Normalize them here so the generated artifact remains diff-clean and the
    // committed file is byte-for-byte identical to `pnpm bindings` output.
    let generated = std::fs::read_to_string(path)?;
    let normalized = generated.lines().map(str::trim_end).collect::<Vec<_>>().join("\n");
    let normalized = if generated.ends_with('\n') { format!("{normalized}\n") } else { normalized };
    if normalized != generated {
        std::fs::write(path, normalized)?;
    }
    Ok(())
}

/// Starts the application.
pub fn run() {
    let ipc = ipc();
    let smoke = smoke::SmokeTest::from_env();
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(smoke)
        .invoke_handler(ipc.invoke_handler())
        .setup(move |app| {
            ipc.mount_events(app);
            app.state::<smoke::SmokeTest>().arm(app.handle().clone());
            let local = local_data::LocalDataState::start(app.handle());
            local.on_change({
                let handle = app.handle().clone();
                move |change| {
                    let _ = events::StoreChanged::from(change).emit(&handle);
                }
            });
            if let (Some(store), Some(window)) =
                (local.store(), window_state::main_window(app.handle()))
            {
                window_state::restore(&window, &store);
            }
            app.manage(local);
            app.manage(ssh::SessionManager::default());
            app.manage(inventory::InventoryState::default());
            app.manage(scoplen_client_core::personal_server::PersonalServer::default());
            let background = std::sync::Arc::new(scoplen_client_core::personal_server::PersonalSyncRuntime::default());
            background.set_store(app.state::<local_data::LocalDataState>().store());
            let owner = background.clone();
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                owner.run(&handle.state::<scoplen_client_core::personal_server::PersonalServer>()).await;
            });
            let mut status = background.subscribe();
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                while status.changed().await.is_ok() {
                    let current = *status.borrow_and_update();
                    let _ = events::PersonalSyncChanged { status: current }.emit(&handle);
                }
            });
            app.manage(background);
            app.manage(personal_pairing::PairingWatchState::default());
            app.manage(std::sync::Arc::new(
                scoplen_client_core::personal_inventory::PersonalInventorySettings::default(),
            ));
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                let app = window.app_handle();
                if let (Some(store), Some(main)) = (
                    app.state::<local_data::LocalDataState>().store(),
                    window_state::main_window(app),
                ) && main.label() == window.label()
                {
                    window_state::save(&main, &store);
                }
            }
        })
        .build(tauri::generate_context!())
        .expect("the application failed to start")
        .run(|app, event| {
            if let tauri::RunEvent::ExitRequested { api, code: None, .. } = &event
                && let Some(window) = window_state::main_window(app)
            {
                api.prevent_exit();
                // Route an ordinary application quit through the same final-checkpoint close.
                let _ = window.close();
                return;
            }
            if matches!(event, tauri::RunEvent::Exit | tauri::RunEvent::ExitRequested { .. }) {
                app.state::<std::sync::Arc<scoplen_client_core::personal_server::PersonalSyncRuntime>>().shutdown();
            }
        });
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    /// The committed bindings must be exactly what the command surface
    /// generates. Run `pnpm bindings` after changing a command.
    #[test]
    fn bindings_are_current() {
        let scratch = std::env::temp_dir().join(format!("spl-bindings-{}.ts", std::process::id()));
        super::write_bindings(&scratch).expect("bindings render");
        let generated = std::fs::read_to_string(&scratch).expect("generated bindings");
        let _ = std::fs::remove_file(&scratch);
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(super::BINDINGS_PATH);
        let committed = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(committed == generated, "{} is out of date; run `pnpm bindings`", path.display());
    }
}
