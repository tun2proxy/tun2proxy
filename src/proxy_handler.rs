use crate::{
    directions::{IncomingDataEvent, OutgoingDataEvent, OutgoingDirection},
    session_info::SessionInfo,
};
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::Mutex;

#[async_trait::async_trait]
pub(crate) trait ProxyHandler: Send + Sync {
    fn get_server_addr(&self) -> SocketAddr;
    fn get_session_info(&self) -> SessionInfo;
    fn get_domain_name(&self) -> Option<String>;
    /// Adds incoming bytes and advances the protocol state machine.
    async fn push_data(&mut self, event: IncomingDataEvent<'_>) -> std::io::Result<()>;
    /// Advances the protocol state machine using data already buffered by the handler.
    ///
    /// This is separate from `push_data` so callers do not need to rely on empty input
    /// events to trigger state progression. Implementations must make any buffered
    /// server input available through `ToClient` and buffered client input through
    /// `ToServer` when the connection is established.
    async fn process_pending(&mut self) -> std::io::Result<()>;
    fn consume_data(&mut self, dir: OutgoingDirection, size: usize);
    fn peek_data(&mut self, dir: OutgoingDirection) -> OutgoingDataEvent<'_>;
    fn connection_established(&self) -> bool;
    #[allow(dead_code)]
    fn data_len(&self, dir: OutgoingDirection) -> usize;
    #[allow(dead_code)]
    fn reset_connection(&self) -> bool;
    fn get_udp_associate(&self) -> Option<SocketAddr>;
}

#[async_trait::async_trait]
pub(crate) trait ProxyHandlerManager: Send + Sync {
    async fn new_proxy_handler(
        &self,
        info: SessionInfo,
        domain_name: Option<String>,
        udp_associate: bool,
    ) -> std::io::Result<Arc<Mutex<dyn ProxyHandler>>>;
}
