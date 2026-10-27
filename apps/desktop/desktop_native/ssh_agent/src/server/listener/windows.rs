//! Windows named pipe listener for the SSH agent server

use std::{mem, os::windows::io::AsRawHandle};

use anyhow::{anyhow, Result};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tracing::{info, warn};
use windows::Win32::{Foundation::HANDLE, System::Pipes::GetNamedPipeClientProcessId};

use super::Listener;
use crate::server::{connection::Connection, peer_info::PeerInfo};

/// The fixed named pipe path that OpenSSH clients expect on Windows
const PIPE_NAME: &str = r"\\.\pipe\openssh-ssh-agent";

/// Windows named pipe listener for the SSH agent server
pub(crate) struct WindowsListener {
    inner: NamedPipeServer,
    /// The name this listener binds, kept so `accept` can create the next instance.
    name: String,
}

impl WindowsListener {
    /// Creates a new [`WindowsListener`], binding to the OpenSSH named pipe path.
    ///
    /// The first pipe instance is created synchronously, so the name is registered before this
    /// returns.
    ///
    /// # Errors
    ///
    /// Returns an error if the named pipe cannot be created.
    pub(crate) fn new() -> Result<Self> {
        Self::with_name(PIPE_NAME)
    }

    /// Like [`Self::new`], but binds to `name`. Tests use it so each test owns its own pipe.
    pub(crate) fn with_name(name: &str) -> Result<Self> {
        let server = ServerOptions::new()
            .create(name)
            .map_err(|e| anyhow!("Unable to create named pipe {name}: {e}"))?;

        info!(pipe_name = name, "Named pipe listener ready");

        Ok(Self {
            inner: server,
            name: name.to_string(),
        })
    }
}

#[async_trait::async_trait]
impl Listener for WindowsListener {
    type Stream = NamedPipeServer;

    async fn accept(&mut self) -> Result<Connection<Self::Stream>> {
        self.inner.connect().await?;

        // Create the next server instance before handing off the current one, so the
        // pipe name remains available for subsequent clients without a gap.
        let next = ServerOptions::new()
            .create(self.name.as_str())
            .map_err(|e| anyhow!("Failed to create next pipe instance after accept: {e}"))?;

        let stream = mem::replace(&mut self.inner, next);
        let peer_info = get_peer_info(&stream);

        Ok(Connection { stream, peer_info })
    }
}

// Gathers peer process info from a connected named pipe server handle.
//
// TODO: PM-30755 Add test coverage for peer info gathering once the connection handler
// is implemented and `PeerInfo` is observable via the SSH protocol exchange.
fn get_peer_info(server: &NamedPipeServer) -> Option<PeerInfo> {
    let mut pid: u32 = 0;
    let handle = HANDLE(server.as_raw_handle().cast());

    // SAFETY: `handle` is valid for the lifetime of this call (server is still alive),
    // and `pid` is a local stack variable that Windows writes the client PID into.
    if let Err(error) = unsafe { GetNamedPipeClientProcessId(handle, &raw mut pid) } {
        warn!(%error, "Failed to get named pipe client process id");
        return None;
    }

    PeerInfo::from_pid(pid)
}

#[cfg(test)]
mod tests {
    use tokio::net::windows::named_pipe::ClientOptions;

    use super::*;

    /// A pipe name that cannot collide with a real agent already running on this machine.
    ///
    /// These tests used the fixed `PIPE_NAME`, which a running Bitwarden also binds: the tests then
    /// blocked on that instance (hanging for minutes) or connected to it instead of their own pipe.
    fn test_pipe_name() -> String {
        format!(r"\\.\pipe\bw-ssh-agent-unit-{}", std::process::id())
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn test_new_creates_pipe() {
        WindowsListener::with_name(&test_pipe_name()).unwrap();
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn test_get_peer_info_connected_client_returns_some() {
        let pipe = test_pipe_name();
        let server = ServerOptions::new().create(&pipe).unwrap();
        // Keep the client alive so the connection stays open for the duration of the check
        let _client = ClientOptions::new().open(&pipe).unwrap();
        server.connect().await.unwrap();

        let peer_info = get_peer_info(&server);

        assert!(peer_info.is_some());
    }
}
