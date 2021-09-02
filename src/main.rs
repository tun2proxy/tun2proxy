#![feature(deque_make_contiguous)]
#![feature(deque_range)]

mod virtdevice;
mod socks5;
mod http;
mod tun2proxy;

use socks5::*;
use crate::http::HttpManager;
use crate::tun2proxy::TunToProxy;
use std::net::ToSocketAddrs;

fn main() {
    let matches = clap::App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .about("Tunnel interface to proxy.")
        .arg(clap::Arg::with_name("tun")
            .short("t")
            .long("tun")
            .value_name("TUN")
            .help("Name of the tun interface")
            .required(true)
            .takes_value(true))
        .arg(clap::Arg::with_name("socks5_server")
            .help("SOCKS5 server to use")
            .short("s")
            .long("socks5")
            .value_name("IP:PORT"))
        .arg(clap::Arg::with_name("http_server")
            .help("HTTP server to use")
            .short("h")
            .long("http")
            .value_name("IP:PORT"))
        .get_matches();

    if matches.value_of("socks5_server").is_some()
        && matches.value_of("http_server").is_some()
        || matches.value_of("socks5_server").is_none()
        && matches.value_of("http_server").is_none() {
        eprintln!("You need to specify exactly one server.");
        return;
    }

    let tun_name = matches.value_of("tun").unwrap();
    let mut ttp = TunToProxy::new(tun_name);
    if let Some(addr) = matches.value_of("socks5_server") {
        if let Ok(mut servers) = addr.to_socket_addrs()
        {
            let server = servers.next().unwrap();
            println!("SOCKS5 server: {}", server);
            ttp.add_connection_manager(Box::new(Socks5Manager::new(server)));
        } else {
            eprintln!("Invalid server address.");
            return;
        }
    }

    if let Some(addr) = matches.value_of("http_server") {
        if let Ok(mut servers) = addr.to_socket_addrs()
        {
            let server = servers.next().unwrap();
            println!("HTTP server: {}", server);
            ttp.add_connection_manager(Box::new(HttpManager::new(server)));
        } else {
            eprintln!("Invalid server address.");
            return;
        }
    }
    ttp.run();
}
