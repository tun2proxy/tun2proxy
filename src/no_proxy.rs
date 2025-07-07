use crate::{
    directions::{IncomingDataEvent, IncomingDirection, OutgoingDataEvent, OutgoingDirection},
    proxy_handler::{ProxyHandler, ProxyHandlerManager},
    session_info::SessionInfo,
};
use std::{collections::VecDeque, net::SocketAddr, sync::Arc};
use tokio::sync::Mutex;

struct NoProxyHandler {
    info: SessionInfo,
    domain_name: Option<String>,
    client_outbuf: VecDeque<u8>,
    server_outbuf: VecDeque<u8>,
    udp_associate: bool,
}

#[async_trait::async_trait]
impl ProxyHandler for NoProxyHandler {
    fn get_server_addr(&self) -> SocketAddr {
        self.info.dst
    }

    fn get_session_info(&self) -> SessionInfo {
        self.info
    }

    fn get_domain_name(&self) -> Option<String> {
        self.domain_name.clone()
    }

    async fn push_data(&mut self, event: IncomingDataEvent<'_>) -> std::io::Result<()> {
        let IncomingDataEvent { direction, buffer } = event;
        match direction {
            IncomingDirection::FromServer => {
                self.client_outbuf.extend(buffer.iter());
            }
            IncomingDirection::FromClient => {
                self.server_outbuf.extend(buffer.iter());
            }
        }
        Ok(())
    }

    fn consume_data(&mut self, dir: OutgoingDirection, size: usize) {
        let buffer = match dir {
            OutgoingDirection::ToServer => &mut self.server_outbuf,
            OutgoingDirection::ToClient => &mut self.client_outbuf,
        };
        buffer.drain(0..size);
    }

    fn peek_data(&mut self, dir: OutgoingDirection) -> OutgoingDataEvent<'_> {
        let buffer = match dir {
            OutgoingDirection::ToServer => &mut self.server_outbuf,
            OutgoingDirection::ToClient => &mut self.client_outbuf,
        };
        OutgoingDataEvent {
            direction: dir,
            buffer: buffer.make_contiguous(),
        }
    }

    fn connection_established(&self) -> bool {
        true
    }

    fn data_len(&self, dir: OutgoingDirection) -> usize {
        match dir {
            OutgoingDirection::ToServer => self.server_outbuf.len(),
            OutgoingDirection::ToClient => self.client_outbuf.len(),
        }
    }

    fn reset_connection(&self) -> bool {
        false
    }

    fn get_udp_associate(&self) -> Option<SocketAddr> {
        self.udp_associate.then_some(self.info.dst)
    }
}

pub(crate) struct NoProxyManager;

#[async_trait::async_trait]
impl ProxyHandlerManager for NoProxyManager {
    async fn new_proxy_handler(
        &self,
        info: SessionInfo,
        domain_name: Option<String>,
        udp_associate: bool,
    ) -> std::io::Result<Arc<Mutex<dyn ProxyHandler>>> {
        Ok(Arc::new(Mutex::new(NoProxyHandler {
            info,
            domain_name,
            client_outbuf: VecDeque::default(),
            server_outbuf: VecDeque::default(),
            udp_associate,
        })))
    }
}

impl NoProxyManager {
    pub(crate) fn new() -> Self {
        Self
    }
}
