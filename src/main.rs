use std::net::{SocketAddr, ToSocketAddrs};

use clap::Parser;
use env_logger::Env;

use tun2proxy::tun2proxy::Credentials;
use tun2proxy::{main_entry, ProxyType};

/// Tunnel interface to proxy
#[derive(Parser)]
#[command(author, version, about = "Tunnel interface to proxy.", long_about = None)]
struct Args {
    /// Name of the tun interface
    #[arg(short, long, value_name = "name", default_value = "tun0")]
    tun: String,

    /// The proxy URL in the form proto://[username[:password]@]host:port
    #[arg(short, long = "proxy", value_parser = proxy_url_parser, value_name = "URL")]
    proxy: ArgProxy,
}

#[derive(Clone)]
struct ArgProxy {
    proxy_type: ProxyType,
    addr: SocketAddr,
    credentials: Credentials,
}

fn proxy_url_parser(s: &str) -> Result<ArgProxy, String> {
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
        Credentials::none()
    } else {
        Credentials::new(
            String::from(url.username()),
            String::from(url.password().unwrap_or("")),
        )
    };

    let scheme = url.scheme();

    let proxy_type = match url.scheme().to_ascii_lowercase().as_str() {
        "socks5" => Some(ProxyType::Socks5),
        "http" => Some(ProxyType::Http),
        _ => None,
    }
    .ok_or(format!("`{scheme}` is an invalid proxy type"))?;

    Ok(ArgProxy {
        proxy_type,
        addr,
        credentials,
    })
}

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    let addr = args.proxy.addr;
    log::info!("Proxy server: {addr}");

    main_entry(
        &args.tun,
        args.proxy.addr,
        args.proxy.proxy_type,
        args.proxy.credentials,
    );
}
