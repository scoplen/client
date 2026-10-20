// SPDX-License-Identifier: Apache-2.0

//! Binary streams to the frontend.
//!
//! Terminal output, transfer data, and other byte streams travel over Tauri
//! channels as raw binary frames, never as JSON
//! (`scoplen-docs/11-client-architecture.md` §4). The frontend receives each
//! frame as an `ArrayBuffer` (`web/app/src/ipc/frames.ts`).

use scoplen_client_core::session_manager::SessionEvent;
use tauri::ipc::{Channel, InvokeResponseBody, IpcResponse};

/// A raw binary frame sent through a Tauri channel.
///
/// The custom Specta definition keeps the generated frontend contract as
/// `ArrayBuffer`, while the `IpcResponse` implementation preserves Tauri's
/// raw response body instead of serializing bytes as JSON.
#[derive(Debug)]
pub struct RawFrame(pub Vec<u8>);

impl specta::Type for RawFrame {
    fn definition(_types: &mut specta::Types) -> specta::datatype::DataType {
        specta_typescript::define("ArrayBuffer").into()
    }
}

impl IpcResponse for RawFrame {
    fn body(self) -> tauri::Result<InvokeResponseBody> {
        Ok(InvokeResponseBody::Raw(self.0))
    }
}

/// A channel that carries binary frames to the frontend.
pub struct FrameSender {
    channel: Channel<RawFrame>,
}

/// The frontend closed the channel or its window went away.
#[derive(Debug, thiserror::Error)]
#[error("the frame channel to the frontend is closed")]
pub struct ChannelClosed(#[source] tauri::Error);

impl FrameSender {
    /// Wraps a channel received as a command argument.
    pub fn new(channel: Channel<RawFrame>) -> FrameSender {
        FrameSender { channel }
    }

    /// Sends one frame. Frames arrive in the order they are sent, each intact.
    pub fn send(&self, frame: impl Into<Vec<u8>>) -> Result<(), ChannelClosed> {
        self.channel.send(RawFrame(frame.into())).map_err(ChannelClosed)
    }
}

/// Ordered terminal state or transport-tagged raw output on one IPC channel.
pub enum SessionMessage {
    /// Display-safe manager state, serialized as JSON.
    Event(SessionEvent),
    /// Raw output prefixed with its 16-byte transport UUID.
    Output(uuid::Uuid, Vec<u8>),
}

impl specta::Type for SessionMessage {
    fn definition(types: &mut specta::Types) -> specta::datatype::DataType {
        let _ = <SessionEvent as specta::Type>::definition(types);
        specta_typescript::define("SessionEvent | ArrayBuffer").into()
    }
}

impl IpcResponse for SessionMessage {
    fn body(self) -> tauri::Result<InvokeResponseBody> {
        match self {
            Self::Event(event) => Ok(InvokeResponseBody::Json(serde_json::to_string(&event)?)),
            Self::Output(transport, bytes) => {
                let mut frame = Vec::with_capacity(16 + bytes.len());
                frame.extend_from_slice(transport.as_bytes());
                frame.extend_from_slice(&bytes);
                Ok(InvokeResponseBody::Raw(frame))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FrameSender, RawFrame};
    use std::sync::{Arc, Mutex};
    use tauri::ipc::{Channel, InvokeResponseBody};

    #[test]
    fn frames_are_sent_raw_and_in_order() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let sink = received.clone();
        let channel: Channel<RawFrame> = Channel::new(move |body| {
            sink.lock().unwrap().push(body);
            Ok(())
        });
        let sender = FrameSender::new(channel);
        sender.send(b"\x1b[1mbold".to_vec()).unwrap();
        sender.send(vec![0u8, 255, 10]).unwrap();
        sender.send(Vec::new()).unwrap();

        let received = received.lock().unwrap();
        let frames: Vec<&[u8]> = received
            .iter()
            .map(|body| match body {
                InvokeResponseBody::Raw(bytes) => bytes.as_slice(),
                InvokeResponseBody::Json(json) => panic!("frame sent as JSON: {json}"),
            })
            .collect();
        assert_eq!(frames, [&b"\x1b[1mbold"[..], &[0, 255, 10][..], &[][..]]);
    }

    #[test]
    fn a_closed_channel_is_reported() {
        let channel = Channel::new(|_| Err(tauri::Error::FailedToReceiveMessage));
        let error = FrameSender::new(channel).send(vec![1]).unwrap_err();
        assert_eq!(error.to_string(), "the frame channel to the frontend is closed");
    }

    #[test]
    fn session_frames_keep_transport_identity_and_payload_as_binary() {
        let received = Arc::new(Mutex::new(Vec::new()));
        let sink = received.clone();
        let channel = Channel::new(move |body| {
            sink.lock().unwrap().push(body);
            Ok(())
        });
        let transport = uuid::Uuid::now_v7();
        channel.send(super::SessionMessage::Output(transport, vec![0, 255, 10])).unwrap();
        let received = received.lock().unwrap();
        let InvokeResponseBody::Raw(bytes) = &received[0] else { panic!("JSON terminal frame") };
        assert_eq!(&bytes[..16], transport.as_bytes());
        assert_eq!(&bytes[16..], &[0, 255, 10]);
    }

    #[test]
    fn state_and_output_share_one_ordered_channel_across_attempts() {
        use super::SessionMessage;
        use scoplen_client_core::session_manager::SessionEvent;
        let received = Arc::new(Mutex::new(Vec::new()));
        let sink = received.clone();
        let channel = Channel::new(move |body| {
            sink.lock().unwrap().push(body);
            Ok(())
        });
        for automatic in [false, true] {
            let transport = uuid::Uuid::now_v7();
            channel
                .send(SessionMessage::Event(SessionEvent::Starting {
                    transport_id: transport.to_string(),
                    automatic,
                }))
                .unwrap();
            channel.send(SessionMessage::Output(transport, vec![0, 255])).unwrap();
            channel
                .send(SessionMessage::Event(SessionEvent::Ready {
                    transport_id: transport.to_string(),
                }))
                .unwrap();
        }
        let received = received.lock().unwrap();
        for attempt in received.as_chunks::<3>().0 {
            let InvokeResponseBody::Json(start) = &attempt[0] else {
                panic!("starting must precede output")
            };
            let starting: serde_json::Value = serde_json::from_str(start).unwrap();
            assert_eq!(starting["kind"], "starting");
            let transport =
                uuid::Uuid::parse_str(starting["transportId"].as_str().unwrap()).unwrap();
            let InvokeResponseBody::Raw(output) = &attempt[1] else {
                panic!("output must stay binary")
            };
            assert_eq!(&output[..16], transport.as_bytes());
            let InvokeResponseBody::Json(ready) = &attempt[2] else {
                panic!("readiness must remain a state event")
            };
            assert_eq!(serde_json::from_str::<serde_json::Value>(ready).unwrap()["kind"], "ready");
        }
    }
}
