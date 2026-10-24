// SPDX-License-Identifier: Apache-2.0
//! RFC 8441 tunnel transport; WebSocket framing belongs to tungstenite.

use std::{
    future::Future as _,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

use bytes::{Buf as _, Bytes};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::protocol::{Role, WebSocketConfig},
};

use super::{LIMIT, PersonalServerError};

pub(super) type Socket = WebSocketStream<H2Stream>;

struct Driver(tokio::task::JoinHandle<()>);

impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) struct H2Stream {
    recv: h2::RecvStream,
    send: h2::SendStream<Bytes>,
    buffered: Bytes,
    _driver: Option<Driver>,
}

impl H2Stream {
    pub(crate) fn new(recv: h2::RecvStream, send: h2::SendStream<Bytes>) -> Self {
        Self { recv, send, buffered: Bytes::new(), _driver: None }
    }
}

fn io_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}

impl AsyncRead for H2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        while self.buffered.is_empty() {
            match ready!(self.recv.poll_data(cx)) {
                Some(Ok(bytes)) => self.buffered = bytes,
                Some(Err(error)) => return Poll::Ready(Err(io_error(error))),
                None => return Poll::Ready(Ok(())),
            }
        }
        let count = output.remaining().min(self.buffered.len());
        output.put_slice(&self.buffered[..count]);
        self.buffered.advance(count);
        self.recv.flow_control().release_capacity(count).map_err(io_error)?;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        self.send.reserve_capacity(input.len().min(LIMIT));
        let capacity = match ready!(self.send.poll_capacity(cx)) {
            Some(Ok(capacity)) if capacity > 0 => capacity,
            Some(Ok(_)) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Some(Err(error)) => return Poll::Ready(Err(io_error(error))),
            None => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        };
        let count = capacity.min(input.len()).min(LIMIT);
        self.send.send_data(Bytes::copy_from_slice(&input[..count]), false).map_err(io_error)?;
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.send.send_data(Bytes::new(), true).map_err(io_error)?;
        Poll::Ready(Ok(()))
    }
}

pub(super) async fn open(
    origin: &str,
    tls: Arc<rustls::ClientConfig>,
) -> Result<Socket, PersonalServerError> {
    scoplen_crypto::validate_server_origin(origin)
        .map_err(|_| PersonalServerError::InvalidResponse)?;
    let uri: http::Uri = origin.parse().map_err(|_| PersonalServerError::InvalidResponse)?;
    let host = uri.host().ok_or(PersonalServerError::InvalidResponse)?;
    let name = rustls::pki_types::ServerName::try_from(host.trim_matches(['[', ']']).to_owned())
        .map_err(|_| PersonalServerError::InvalidResponse)?;
    let tcp = tokio::net::TcpStream::connect((
        host.trim_matches(['[', ']']),
        uri.port_u16().unwrap_or(443),
    ))
    .await
    .map_err(|_| PersonalServerError::Network)?;
    let tls = tokio_rustls::TlsConnector::from(tls)
        .connect(name, tcp)
        .await
        .map_err(|_| PersonalServerError::Network)?;
    if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
        return Err(PersonalServerError::InvalidResponse);
    }
    let (mut client, mut connection) = h2::client::Builder::new()
        .initial_window_size(LIMIT as u32)
        .initial_connection_window_size((2 * LIMIT) as u32)
        .max_header_list_size(LIMIT as u32)
        .handshake::<_, Bytes>(tls)
        .await
        .map_err(|_| PersonalServerError::Network)?;
    // Drive the first peer SETTINGS before using the negotiated extension.
    std::future::poll_fn(|cx| {
        if Pin::new(&mut connection).poll(cx).is_ready() {
            return Poll::Ready(Err(PersonalServerError::Network));
        }
        if client.is_extended_connect_protocol_enabled() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    })
    .await?;
    client = client.ready().await.map_err(|_| PersonalServerError::Network)?;
    let mut request = http::Request::builder()
        .method(http::Method::CONNECT)
        .version(http::Version::HTTP_2)
        .uri(format!("{origin}/sync/v1/notify"))
        .header("sec-websocket-version", "13")
        .body(())
        .map_err(|_| PersonalServerError::InvalidResponse)?;
    request.extensions_mut().insert(h2::ext::Protocol::from_static("websocket"));
    let (response, send) =
        client.send_request(request, false).map_err(|_| PersonalServerError::Network)?;
    let driver = Driver(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let response = response.await.map_err(|_| PersonalServerError::Network)?;
    if response.status() != http::StatusCode::OK
        || response.headers().contains_key("sec-websocket-extensions")
        || response.headers().contains_key("sec-websocket-protocol")
        || response.headers().contains_key("set-cookie")
    {
        return Err(PersonalServerError::InvalidResponse);
    }
    let mut stream = H2Stream::new(response.into_body(), send);
    stream._driver = Some(driver);
    Ok(WebSocketStream::from_raw_socket(stream, Role::Client, Some(config())).await)
}

pub(super) fn config() -> WebSocketConfig {
    WebSocketConfig::default()
        .read_buffer_size(4096)
        .write_buffer_size(0)
        .max_write_buffer_size(2 * LIMIT)
        .max_message_size(Some(LIMIT))
        .max_frame_size(Some(LIMIT))
}
