mod http;
mod socks5;
mod tun2proxy;
mod virtdevice;

use crate::http::HttpManager;
use crate::tun2proxy::TunToProxy;
use clap::{Parser, ValueEnum};
use env_logger::Env;
use socks5::*;
use std::net::SocketAddr;

/// Tunnel interface to proxy
#[derive(Parser)]
#[command(author, version, about = "Tunnel interface to proxy.", long_about = None)]
struct Args {
    /// Name of the tun interface
    #[arg(short, long, value_name = "name")]
    tun: String,

    /// What proxy type to run
    #[arg(short, long = "proxy", value_name = "type", value_enum)]
    proxy_type: ProxyType,

    /// Server address with format ip:port
    #[clap(short, long, value_name = "ip:port")]
    addr: SocketAddr,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum ProxyType {
    /// SOCKS5 server to use
    Socks5,
    /// HTTP server to use
    Http,
}

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    let mut ttp = TunToProxy::new(&args.tun);
    match args.proxy_type {
        ProxyType::Socks5 => {
            log::info!("SOCKS5 server: {}", args.addr);
            ttp.add_connection_manager(Box::new(Socks5Manager::new(args.addr)));
        }
        ProxyType::Http => {
            log::info!("HTTP server: {}", args.addr);
            ttp.add_connection_manager(Box::new(HttpManager::new(args.addr)));
        }
    }
    ttp.run();
}
