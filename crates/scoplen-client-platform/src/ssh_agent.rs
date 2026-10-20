// SPDX-License-Identifier: Apache-2.0

//! System SSH agent transports. Protocol framing and identity selection belong
//! to the shared SSH crate; this module only moves bounded local bytes.

use std::{
    io::{self, Read, Write},
    sync::mpsc,
    time::Instant,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc as async_mpsc,
    task::AbortHandle,
};

const MAX_IO: usize = 262_148;

enum Operation {
    Read(usize),
    Write(Vec<u8>),
    Flush,
}

enum Response {
    Bytes(Vec<u8>),
    Written(usize),
    Flushed,
}

struct Request {
    operation: Operation,
    response: mpsc::SyncSender<io::Result<Response>>,
}

/// Blocking byte interface for a synchronous SSH-agent signer running outside
/// the async executor. All I/O shares one absolute deadline, including partial
/// reads. Dropping it aborts and closes the underlying async local transport.
pub struct AgentStream {
    sender: async_mpsc::Sender<Request>,
    task: AbortHandle,
    deadline: Instant,
}

impl AgentStream {
    fn from_io<S>(mut stream: S, deadline: Instant) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (sender, mut receiver) = async_mpsc::channel::<Request>(1);
        let task = tokio::spawn(async move {
            while let Some(request) = receiver.recv().await {
                let result = tokio::time::timeout_at(deadline.into(), async {
                    match request.operation {
                        Operation::Read(size) => {
                            let mut bytes = vec![0; size];
                            let size = stream.read(&mut bytes).await?;
                            bytes.truncate(size);
                            Ok(Response::Bytes(bytes))
                        }
                        Operation::Write(bytes) => {
                            stream.write(&bytes).await.map(Response::Written)
                        }
                        Operation::Flush => stream.flush().await.map(|()| Response::Flushed),
                    }
                })
                .await
                .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()));
                let failed = result.is_err();
                if request.response.send(result).is_err() || failed {
                    break;
                }
            }
        });
        Self { sender, task: task.abort_handle(), deadline }
    }

    /// A cancellation handle that closes pending agent I/O without native FFI.
    #[must_use]
    pub fn abort_handle(&self) -> AbortHandle {
        self.task.clone()
    }

    fn exchange(&mut self, operation: Operation) -> io::Result<Response> {
        let remaining =
            self.deadline.checked_duration_since(Instant::now()).ok_or(io::ErrorKind::TimedOut)?;
        let (response, receiver) = mpsc::sync_channel(1);
        self.sender
            .try_send(Request { operation, response })
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
        receiver.recv_timeout(remaining).map_err(|error| {
            self.task.abort();
            io::Error::from(match error {
                mpsc::RecvTimeoutError::Timeout => io::ErrorKind::TimedOut,
                mpsc::RecvTimeoutError::Disconnected => io::ErrorKind::BrokenPipe,
            })
        })?
    }
}

impl Drop for AgentStream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Read for AgentStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        match self.exchange(Operation::Read(buffer.len().min(MAX_IO)))? {
            Response::Bytes(bytes) => {
                buffer[..bytes.len()].copy_from_slice(&bytes);
                Ok(bytes.len())
            }
            _ => Err(io::ErrorKind::InvalidData.into()),
        }
    }
}

impl Write for AgentStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        match self.exchange(Operation::Write(bytes[..bytes.len().min(MAX_IO)].to_vec()))? {
            Response::Written(size) => Ok(size),
            _ => Err(io::ErrorKind::InvalidData.into()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.exchange(Operation::Flush)? {
            Response::Flushed => Ok(()),
            _ => Err(io::ErrorKind::InvalidData.into()),
        }
    }
}

/// Open this user's system agent with one deadline covering connection and all
/// later I/O. Unix uses `SSH_AUTH_SOCK`; Windows uses a local named pipe from
/// that variable, or the standard OpenSSH pipe when the variable is absent.
pub async fn connect_system_agent(deadline: Instant) -> io::Result<AgentStream> {
    #[cfg(unix)]
    {
        let path = std::env::var_os("SSH_AUTH_SOCK").ok_or(io::ErrorKind::NotFound)?;
        let stream =
            tokio::time::timeout_at(deadline.into(), tokio::net::UnixStream::connect(path))
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        Ok(AgentStream::from_io(stream, deadline))
    }
    #[cfg(windows)]
    {
        let path = std::env::var_os("SSH_AUTH_SOCK")
            .unwrap_or_else(|| r"\\.\pipe\openssh-ssh-agent".into());
        if !path.to_string_lossy().starts_with(r"\\.\pipe\") {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let stream = tokio::net::windows::named_pipe::ClientOptions::new().open(path)?;
        Ok(AgentStream::from_io(stream, deadline))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = deadline;
        Err(io::ErrorKind::Unsupported.into())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn fragmented_reads_share_one_deadline() {
        let (client, mut peer) = tokio::io::duplex(16);
        let mut stream = AgentStream::from_io(client, Instant::now() + Duration::from_millis(80));
        let read = tokio::task::spawn_blocking(move || {
            let mut bytes = [0; 4];
            stream.read_exact(&mut bytes).unwrap_err().kind()
        });
        let drip = tokio::spawn(async move {
            while peer.write_all(b"x").await.is_ok() {
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        });
        assert_eq!(read.await.unwrap(), io::ErrorKind::TimedOut);
        drip.abort();
    }

    #[tokio::test]
    async fn abort_releases_pending_blocking_io_and_closes_peer() {
        let (client, mut peer) = tokio::io::duplex(16);
        let mut stream = AgentStream::from_io(client, Instant::now() + Duration::from_secs(10));
        let abort = stream.abort_handle();
        let read = tokio::task::spawn_blocking(move || stream.read(&mut [0; 1]));
        tokio::task::yield_now().await;
        abort.abort();
        assert_eq!(read.await.unwrap().unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn moves_local_bytes_without_protocol_interpretation() {
        let (client, mut peer) = tokio::io::duplex(16);
        let mut stream = AgentStream::from_io(client, Instant::now() + Duration::from_secs(1));
        let exchange = tokio::task::spawn_blocking(move || {
            stream.write_all(b"request").unwrap();
            stream.flush().unwrap();
            let mut response = [0; 8];
            stream.read_exact(&mut response).unwrap();
            response
        });
        let mut request = [0; 7];
        peer.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"request");
        peer.write_all(b"response").await.unwrap();
        assert_eq!(&exchange.await.unwrap(), b"response");
    }
}
