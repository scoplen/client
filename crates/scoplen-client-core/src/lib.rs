// SPDX-License-Identifier: Apache-2.0

//! Platform-independent logic of the Scoplen desktop client.
//!
//! Every client behavior is implemented here, below the user interface and
//! above the platform layer (`scoplen-docs/11-client-architecture.md` §1), so
//! that it is the same on every desktop platform and testable without a window.

pub mod connection;
pub mod forward_manager;
pub mod inventory;
pub mod local_data;
pub mod local_key;
pub mod locale;
pub mod personal_inventory;
pub mod personal_server;
pub mod profiles;
pub mod repository;
pub mod session_files;
pub mod session_lifecycle;
pub mod session_manager;
pub mod session_transfers;
pub mod store;
pub mod terminal_output;

#[cfg(test)]
mod testing;
