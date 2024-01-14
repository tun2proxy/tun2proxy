use std::net::{Ipv4Addr, SocketAddr};

#[allow(dead_code)]
#[derive(Hash, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Debug, Default)]
pub(crate) enum IpProtocol {
    #[default]
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

impl std::fmt::Display for IpProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            IpProtocol::Tcp => write!(f, "TCP"),
            IpProtocol::Udp => write!(f, "UDP"),
            IpProtocol::Icmp => write!(f, "ICMP"),
            IpProtocol::Other(v) => write!(f, "Other({})", v),
        }
    }
}

#[derive(Hash, Copy, Clone, Eq, PartialEq, PartialOrd, Ord, Debug)]
pub(crate) struct SessionInfo {
    pub(crate) src: SocketAddr,
    pub(crate) dst: SocketAddr,
    pub(crate) protocol: IpProtocol,
    id: u64,
}

impl Default for SessionInfo {
    fn default() -> Self {
        let src = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0);
        let dst = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0);
        Self::new(src, dst, IpProtocol::Tcp)
    }
}

static SESSION_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

impl SessionInfo {
    pub fn new(src: SocketAddr, dst: SocketAddr, protocol: IpProtocol) -> Self {
        let id = SESSION_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Self { src, dst, protocol, id }
    }
}

impl std::fmt::Display for SessionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "#{} {} {} -> {}", self.id, self.protocol, self.src, self.dst)
    }
}
