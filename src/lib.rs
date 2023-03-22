use crate::tun2proxy::Credentials;
use crate::{http::HttpManager, socks5::Socks5Manager, tun2proxy::TunToProxy};
use std::net::{SocketAddr, ToSocketAddrs};

pub mod http;
pub mod socks5;
pub mod tun2proxy;
pub mod virtdevice;

#[derive(Clone, Debug)]
pub struct Proxy {
    pub proxy_type: ProxyType,
    pub addr: SocketAddr,
    pub credentials: Option<Credentials>,
}

impl Proxy {
    pub fn from_url(s: &str) -> Result<Proxy, String> {
        let url = url::Url::parse(s).map_err(|_| format!("`{s}` is not a valid proxy URL"))?;
        let host = url
            .host_str()
            .ok_or(format!("`{s}` does not contain a host"))?;

        let mut url_host = String::from(host);
        let port = url.port().ok_or(format!("`{s}` does not contain a port"))?;
        url_host.push(':');
        url_host.push_str(port.to_string().as_str());

        let mut addr_iter = url_host
            .to_socket_addrs()
            .map_err(|_| format!("`{host}` could not be resolved"))?;

        let addr = addr_iter
            .next()
            .ok_or(format!("`{host}` does not resolve to a usable IP address"))?;

        let credentials = if url.username() == "" && url.password().is_none() {
            None
        } else {
            let username = String::from(url.username());
            let password = String::from(url.password().unwrap_or(""));
            Some(Credentials::new(&username, &password))
        };

        let scheme = url.scheme();

        let proxy_type = match url.scheme().to_ascii_lowercase().as_str() {
            "socks5" => Some(ProxyType::Socks5),
            "http" => Some(ProxyType::Http),
            _ => None,
        }
        .ok_or(format!("`{scheme}` is an invalid proxy type"))?;

        Ok(Proxy {
            proxy_type,
            addr,
            credentials,
        })
    }
}

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

pub fn main_entry(tun: &str, proxy: Proxy) {
    let mut ttp = TunToProxy::new(tun);
    match proxy.proxy_type {
        ProxyType::Socks5 => {
            ttp.add_connection_manager(Socks5Manager::new(proxy.addr, proxy.credentials));
        }
        ProxyType::Http => {
            ttp.add_connection_manager(HttpManager::new(proxy.addr, proxy.credentials));
        }
    }
    ttp.run();
}
