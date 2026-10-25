// SPDX-License-Identifier: Apache-2.0

//! Native paths enter only here; product IPC contains context/ticket identities and positions.

use scoplen_client_core::locale::Locale;
use scoplen_client_core::session_manager::{
    SessionManager,
    file_drop::{FileDrag, FileDragPhase, FileDropAccepted},
};
use scoplen_client_core::session_transfers::SessionTransferIssue;
use serde::Serialize;
use specta::Type;
use tauri::{DragDropEvent, Manager as _, WindowEvent};
use tauri_specta::Event as _;

/// Application-owned drag feedback; framework path-bearing drag events are never subscribed to.
#[derive(Clone, Debug, PartialEq, Serialize, Type, tauri_specta::Event)]
#[serde(rename_all = "camelCase")]
pub struct SessionFileDrag {
    /// Current Files view identity.
    pub context_id: String,
    /// Native transition.
    pub phase: FileDragPhase,
    /// One-use selection identity, present only on Drop.
    pub ticket_id: Option<String>,
    /// Bounded selection count (17 also represents an oversized selection).
    pub count: u32,
    /// Horizontal fraction of matching native webview bounds.
    pub x: Option<f64>,
    /// Vertical fraction of matching native webview bounds.
    pub y: Option<f64>,
}

impl From<FileDrag> for SessionFileDrag {
    fn from(event: FileDrag) -> Self {
        Self {
            context_id: event.context_id,
            phase: event.phase,
            ticket_id: event.ticket_id,
            count: event.count,
            x: event.x,
            y: event.y,
        }
    }
}

/// Arm an exact current Files destination for the invoking native window.
#[tauri::command]
#[specta::specta]
pub fn session_arm_file_drop(
    window: tauri::WebviewWindow,
    manager: tauri::State<'_, SessionManager>,
    session_id: String,
    transport_id: String,
    queue_id: String,
    directory_path: Vec<u8>,
    context_id: String,
) -> Result<(), SessionTransferIssue> {
    if geometry(&window).is_none() {
        return Err(SessionTransferIssue::InvalidSelection);
    }
    manager.arm_file_drop(
        window.label(),
        &context_id,
        &session_id,
        &transport_id,
        &queue_id,
        directory_path,
    )
}

/// Cleanup cannot revoke a newer Files context.
#[tauri::command]
#[specta::specta]
pub fn session_revoke_file_drop(
    window: tauri::WebviewWindow,
    manager: tauri::State<'_, SessionManager>,
    context_id: String,
) {
    manager.revoke_file_drop(window.label(), &context_id);
}

/// Only the opaque native ticket can choose sources and its frozen destination.
#[tauri::command]
#[specta::specta]
pub async fn session_consume_file_drop(
    window: tauri::WebviewWindow,
    app: tauri::AppHandle,
    manager: tauri::State<'_, SessionManager>,
    context_id: String,
    ticket_id: String,
    locale: Locale,
) -> Result<FileDropAccepted, SessionTransferIssue> {
    if geometry(&window).is_none() {
        manager.invalidate_file_drop(window.label());
        return Err(SessionTransferIssue::StaleItem);
    }
    manager
        .consume_file_drop(window.label(), &context_id, &ticket_id, move |review| {
            crate::session_transfers::confirm_replace(app.clone(), locale, review)
        })
        .await
}

/// Refuse a hit outside the current list without exposing the native selection.
#[tauri::command]
#[specta::specta]
pub fn session_cancel_file_drop(
    window: tauri::WebviewWindow,
    manager: tauri::State<'_, SessionManager>,
    context_id: String,
    ticket_id: String,
) {
    manager.cancel_file_drop(window.label(), &context_id, &ticket_id);
}

/// Translate native transitions to the application's path-free typed event surface.
pub(crate) fn on_window_event(window: &tauri::Window, event: &WindowEvent) {
    let Some(manager) = window.try_state::<SessionManager>() else { return };
    if matches!(
        event,
        WindowEvent::Resized(_)
            | WindowEvent::ScaleFactorChanged { .. }
            | WindowEvent::Destroyed
            | WindowEvent::CloseRequested { .. }
    ) {
        manager.invalidate_file_drop(window.label());
        return;
    }
    let WindowEvent::DragDrop(event) = event else { return };
    let Some(webview) = window.app_handle().get_webview_window(window.label()) else {
        manager.invalidate_file_drop(window.label());
        return;
    };
    let position = |point: &tauri::PhysicalPosition<f64>| {
        geometry(&webview).and_then(|bounds| bounds.normalize(point.x, point.y))
    };
    let event = match event {
        DragDropEvent::Enter { paths, position: point } => {
            manager.begin_file_drag(window.label(), paths.len(), position(point))
        }
        DragDropEvent::Over { position: point } => {
            manager.file_drag(window.label(), FileDragPhase::Over, position(point))
        }
        DragDropEvent::Drop { paths, position: point } => manager.capture_file_drop(
            tauri::async_runtime::handle().inner(),
            window.label(),
            paths.iter().take(17).cloned().collect(),
            position(point),
        ),
        // Native Drop is commonly followed immediately by Leave. It must not revoke the ticket.
        DragDropEvent::Leave => manager.file_drag(window.label(), FileDragPhase::Leave, None),
        _ => None,
    };
    if let Some(event) = event {
        let _ = SessionFileDrag::from(event)
            .emit_to(window.app_handle(), tauri::EventTarget::webview_window(window.label()));
    }
}

struct Bounds {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}

impl Bounds {
    fn normalize(&self, x: f64, y: f64) -> Option<(f64, f64)> {
        let point = ((x - self.x) / self.width, (y - self.y) / self.height);
        (point.0.is_finite()
            && point.1.is_finite()
            && (0.0..1.0).contains(&point.0)
            && (0.0..1.0).contains(&point.1))
        .then_some(point)
    }
}

fn geometry(window: &tauri::WebviewWindow) -> Option<Bounds> {
    if window.label() != "main" || window.as_ref().window().webviews().len() != 1 {
        return None;
    }
    let bounds = window.as_ref().bounds().ok()?;
    let inner = window.inner_size().ok()?;
    let scale = window.scale_factor().ok()?;
    if !scale.is_finite() || scale <= 0.0 {
        return None;
    }
    // Wry delivers macOS drag locations in points; Windows locations are physical pixels.
    #[cfg(target_os = "macos")]
    let (position, size, expected) = (
        bounds.position.to_logical::<f64>(scale),
        bounds.size.to_logical::<f64>(scale),
        inner.to_logical::<f64>(scale),
    );
    #[cfg(not(target_os = "macos"))]
    let (position, size, expected) = (
        bounds.position.to_physical::<f64>(scale),
        bounds.size.to_physical::<f64>(scale),
        inner.cast::<f64>(),
    );
    if !position.x.is_finite()
        || !position.y.is_finite()
        || !expected.width.is_finite()
        || !expected.height.is_finite()
        || !size.width.is_finite()
        || !size.height.is_finite()
        || size.width <= 0.0
        || size.height <= 0.0
        || position.x.abs() > 0.5
        || position.y.abs() > 0.5
        || (size.width - expected.width).abs() > 0.5
        || (size.height - expected.height).abs() > 0.5
    {
        return None;
    }
    Some(Bounds { x: position.x, y: position.y, width: size.width, height: size.height })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positions_use_matching_native_bounds_without_assuming_a_pixel_scale() {
        let points = Bounds { x: 0.0, y: 0.0, width: 1200.0, height: 800.0 };
        let physical = Bounds { x: 0.0, y: 0.0, width: 2400.0, height: 1600.0 };
        assert_eq!(points.normalize(900.0, 400.0), Some((0.75, 0.5)));
        assert_eq!(physical.normalize(1800.0, 800.0), Some((0.75, 0.5)));
        for (x, y) in
            [(f64::NAN, 0.0), (0.0, f64::INFINITY), (-1.0, 0.0), (1200.0, 0.0), (0.0, 800.0)]
        {
            assert_eq!(points.normalize(x, y), None);
        }
    }

    #[test]
    fn product_event_serializes_only_bounded_path_free_fields() {
        let event = SessionFileDrag {
            context_id: "context".into(),
            phase: FileDragPhase::Drop,
            ticket_id: Some("ticket".into()),
            count: 16,
            x: Some(0.5),
            y: Some(0.5),
        };
        let json = serde_json::to_value(event).unwrap();
        assert_eq!(json.as_object().unwrap().len(), 6);
        assert_eq!(json["phase"], "drop");
        assert_eq!(json["count"], 16);
    }
}
