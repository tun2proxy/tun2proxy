use crate::tun2proxy::Credentials;
use crate::{http::HttpManager, socks5::Socks5Manager, tun2proxy::TunToProxy};
use std::net::SocketAddr;

pub mod http;
pub mod socks5;
pub mod tun2proxy;
pub mod virtdevice;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProxyType {
    Socks5,
    Http,
}

pub fn main_entry(tun: &str, addr: SocketAddr, proxy_type: ProxyType, credentials: Credentials) {
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
