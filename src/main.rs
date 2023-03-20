use tun2proxy::{ProxyType, main_entry};
use clap::{Parser, ValueEnum};
use env_logger::Env;
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
    proxy_type: ArgProxyType,

    /// Server address with format ip:port
    #[clap(short, long, value_name = "ip:port")]
    addr: SocketAddr,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum ArgProxyType {
    /// SOCKS5 server to use
    Socks5,
    /// HTTP server to use
    Http,
}

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    match args.proxy_type {
        ArgProxyType::Socks5 => {
            log::info!("SOCKS5 server: {}", args.addr);
            main_entry(&args.tun, args.addr, ProxyType::Socks5);
        }
        ArgProxyType::Http => {
            log::info!("HTTP server: {}", args.addr);
            main_entry(&args.tun, args.addr, ProxyType::Http);
        }
    }
}
