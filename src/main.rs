use clap::Parser;
use std::{net::IpAddr, process::ExitCode};
use tun2proxy::{error::Error, main_entry, NetworkInterface, Options, Proxy};

#[cfg(target_os = "linux")]
use tun2proxy::setup::{get_default_cidrs, Setup};

/// Tunnel interface to proxy
#[derive(Parser)]
#[command(author, version, about = "Tunnel interface to proxy.", long_about = None)]
struct Args {
    /// Name of the tun interface
    #[arg(short, long, value_name = "name", default_value = "tun0")]
    tun: String,

    /// File descriptor of the tun interface
    #[arg(long, value_name = "fd")]
    tun_fd: Option<i32>,

    /// MTU of the tun interface (only with tunnel file descriptor)
    #[arg(long, value_name = "mtu", default_value = "1500")]
    tun_mtu: usize,

    /// Proxy URL in the form proto://[username[:password]@]host:port
    #[arg(short, long, value_parser = Proxy::from_url, value_name = "URL")]
    proxy: Proxy,

    /// DNS handling strategy
    #[arg(short, long, value_name = "strategy", value_enum, default_value = "virtual")]
    dns: ArgDns,

    /// DNS resolver address
    #[arg(long, value_name = "IP", default_value = "8.8.8.8")]
    dns_addr: IpAddr,

    /// IPv6 enabled
    #[arg(short = '6', long)]
    ipv6_enabled: bool,

    /// Routing and system setup
    #[arg(short, long, value_name = "method", value_enum)]
    setup: Option<ArgSetup>,

    /// Public proxy IP used in routing setup which should bypassing the tunnel
    #[arg(long, value_name = "IP")]
    bypass_ip: Option<IpAddr>,

    /// Verbosity level
    #[arg(short, long, value_name = "level", value_enum, default_value = "info")]
    verbosity: ArgVerbosity,
}

/// DNS query handling strategy
/// - Virtual: Intercept DNS queries and resolve them locally with a fake IP address
/// - OverTcp: Use TCP to send DNS queries to the DNS server
/// - Direct: Looks as general UDP traffic but change the destination to the DNS server
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
enum ArgDns {
    Virtual,
    OverTcp,
    Direct,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
enum ArgSetup {
    Auto,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
enum ArgVerbosity {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

fn main() -> ExitCode {
    dotenvy::dotenv().ok();
    let args = Args::parse();

    let default = format!("{}={:?}", module_path!(), args.verbosity);
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default)).init();

    let addr = args.proxy.addr;
    let proxy_type = args.proxy.proxy_type;
    log::info!("Proxy {proxy_type} server: {addr}");

    let mut options = Options::new();
    match args.dns {
        ArgDns::Virtual => {
            options = options.with_virtual_dns();
        }
        ArgDns::OverTcp => {
            options = options.with_dns_over_tcp();
        }
        _ => {}
    }

    options = options.with_dns_addr(Some(args.dns_addr));

    if args.ipv6_enabled {
        options = options.with_ipv6_enabled();
    }

    #[allow(unused_assignments)]
    let interface = match args.tun_fd {
        None => NetworkInterface::Named(args.tun.clone()),
        Some(_fd) => {
            options = options.with_mtu(args.tun_mtu);
            #[cfg(not(target_family = "unix"))]
            panic!("Not supported file descriptor");
            #[cfg(target_family = "unix")]
            NetworkInterface::Fd(_fd)
        }
    };

    let bypass_tun_ip = match args.bypass_ip {
        Some(addr) => addr,
        None => args.proxy.addr.ip(),
    };
    options = options.with_bypass_ip(Some(bypass_tun_ip));

    let block = || -> Result<(), Error> {
        #[cfg(target_os = "linux")]
        {
            let mut setup: Setup;
            if args.setup == Some(ArgSetup::Auto) {
                let bypass_tun_ip = match args.bypass_ip {
                    Some(addr) => addr,
                    None => args.proxy.addr.ip(),
                };
                setup = Setup::new(&args.tun, &bypass_tun_ip, get_default_cidrs(), args.bypass_ip.is_some());

                setup.configure()?;

                setup.drop_privileges()?;
            }
        }

        main_entry(&interface, &args.proxy, options)?;

        Ok(())
    };
    if let Err(e) = block() {
        log::error!("{e}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
