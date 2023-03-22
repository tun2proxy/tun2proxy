use std::net::SocketAddr;

use clap::{Parser, ValueEnum};
use env_logger::Env;

use tun2proxy::tun2proxy::Credentials;
use tun2proxy::{main_entry, ProxyType};

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

    /// Username for authentication
    #[clap(long, value_name = "username")]
    username: Option<String>,

    /// Password for authentication
    #[clap(long, value_name = "password")]
    password: Option<String>,
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

    let credentials = if args.username.is_some() || args.password.is_some() {
        Credentials::new(
            args.username.unwrap_or(String::from("")),
            args.password.unwrap_or(String::from("")),
        )
    } else {
        Credentials::none()
    };

    match args.proxy_type {
        ArgProxyType::Socks5 => {
            log::info!("SOCKS5 server: {}", args.addr);
            main_entry(&args.tun, args.addr, ProxyType::Socks5, credentials);
        }
        ArgProxyType::Http => {
            log::info!("HTTP server: {}", args.addr);
            main_entry(&args.tun, args.addr, ProxyType::Http, credentials);
        }
    }
}
