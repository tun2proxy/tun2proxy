use crate::tun2proxy::Credentials;
use crate::{http::HttpManager, socks5::Socks5Manager, tun2proxy::TunToProxy};
use std::net::SocketAddr;

pub mod http;
pub mod socks5;
pub mod tun2proxy;
pub mod virtdevice;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum ProxyType {
    Socks5,
    Http,
}

impl std::fmt::Display for ProxyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyType::Socks5 => write!(f, "socks5"),
            ProxyType::Http => write!(f, "http"),
        }
    }
}

pub fn main_entry(
    tun: &str,
    addr: SocketAddr,
    proxy_type: ProxyType,
    credentials: Option<Credentials>,
) {
    let mut ttp = TunToProxy::new(tun);
    match proxy_type {
        ProxyType::Socks5 => {
            ttp.add_connection_manager(Socks5Manager::new(addr, credentials));
        }
        ProxyType::Http => {
            ttp.add_connection_manager(HttpManager::new(addr, credentials));
        }
    }
    ttp.run();
}
