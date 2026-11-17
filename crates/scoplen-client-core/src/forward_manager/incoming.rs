// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::connection::agent_forwarding::{AgentForwardingService, ForwardedAgent};
use scoplen_ssh::{ForwardedChannel, ForwardedChannelKind, ForwardedChannelReceiver};

/// The original bounded incoming queue has exactly one owner per terminal transport.
pub(crate) struct IncomingForwardingService {
    pub(crate) state: Arc<IncomingForwardingState>,
    stop: watch::Sender<bool>,
    driver: Option<tokio::task::JoinHandle<()>>,
}

#[derive(Default)]
pub(crate) struct IncomingForwardingState {
    endpoints: Mutex<BTreeMap<(String, u16), Arc<remote::AttachedRemote>>>,
}

impl IncomingForwardingState {
    pub(super) fn reserve(
        &self,
        run: Arc<Run>,
    ) -> Result<Arc<remote::AttachedRemote>, ForwardIssue> {
        let (address, port) = run.configuration.bind();
        let mut endpoints = self.endpoints.lock().map_err(|_| ForwardIssue::Unavailable)?;
        let entry = endpoints.entry((address.to_owned(), port));
        let std::collections::btree_map::Entry::Vacant(entry) = entry else {
            return Err(ForwardIssue::ListenFailed);
        };
        let endpoint = Arc::new(remote::AttachedRemote::new(run));
        entry.insert(endpoint.clone());
        Ok(endpoint)
    }

    fn accept(&self, channel: ForwardedChannel) -> Option<ForwardedChannel> {
        let ForwardedChannelKind::Tcp { connected_address, connected_port, .. } = channel.kind()
        else {
            return Some(channel);
        };
        let Ok(port) = u16::try_from(*connected_port) else { return Some(channel) };
        let endpoint = self
            .endpoints
            .lock()
            .ok()
            .and_then(|endpoints| endpoints.get(&(connected_address.clone(), port)).cloned());
        if let Some(endpoint) = endpoint { endpoint.accept(channel) } else { Some(channel) }
    }

    fn stop(&self) {
        if let Ok(endpoints) = self.endpoints.lock() {
            for endpoint in endpoints.values() {
                endpoint.stop();
            }
        }
    }
}

impl IncomingForwardingService {
    pub(crate) fn start(
        selected: Option<ForwardedAgent>,
        control: PreparationControl,
        mut incoming: ForwardedChannelReceiver,
    ) -> Self {
        let state = Arc::new(IncomingForwardingState::default());
        let endpoints = state.clone();
        let (stop, mut stopped) = watch::channel(false);
        let mut agent =
            selected.map(|selected| AgentForwardingService::new(selected, control.clone()));
        let driver = tokio::spawn(async move {
            let mut rejected = JoinSet::new();
            loop {
                let channel = tokio::select! { biased;
                    _ = stopped.wait_for(|stopped| *stopped) => break,
                    _ = control.cancelled() => break,
                    channel = incoming.recv() => channel,
                };
                let Some(channel) = channel else { break };
                let rejected_channel = if matches!(channel.kind(), ForwardedChannelKind::Agent) {
                    if let Some(agent) = &mut agent { agent.accept(channel) } else { Some(channel) }
                } else {
                    endpoints.accept(channel)
                };
                while rejected.try_join_next().is_some() {}
                if let Some(channel) = rejected_channel {
                    // Retaining the channel retains its existing shared capacity permit.
                    rejected.spawn(async move {
                        let _ = remote::close_peer(channel.into_channel()).await;
                    });
                }
            }
            endpoints.stop();
            if let Some(agent) = &mut agent {
                agent.settle().await;
            }
            while rejected.join_next().await.is_some() {}
        });
        Self { state, stop, driver: Some(driver) }
    }

    pub(crate) async fn settle(&mut self) {
        self.state.stop();
        self.stop.send_replace(true);
        if let Some(driver) = self.driver.take() {
            let _ = driver.await;
        }
    }
}

impl Drop for IncomingForwardingService {
    fn drop(&mut self) {
        self.state.stop();
        self.stop.send_replace(true);
        if let Some(driver) = self.driver.take() {
            driver.abort();
        }
    }
}
