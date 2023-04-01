use clap::Parser;
use env_logger::Env;

use std::net::IpAddr;
use std::process::ExitCode;

use tun2proxy::error::Error;
use tun2proxy::setup::{get_default_cidrs, Setup};
use tun2proxy::Options;
use tun2proxy::{main_entry, Proxy};

/// Tunnel interface to proxy
#[derive(Parser)]
#[command(author, version, about = "Tunnel interface to proxy.", long_about = None)]
struct Args {
    /// Name of the tun interface
    #[arg(short, long, value_name = "name", default_value = "tun0")]
    tun: String,

    /// Proxy URL in the form proto://[username[:password]@]host:port
    #[arg(short, long, value_parser = Proxy::from_url, value_name = "URL")]
    proxy: Proxy,

    /// DNS handling
    #[arg(
        short,
        long,
        value_name = "method",
        value_enum,
        default_value = "virtual"
    )]
    dns: ArgDns,

    /// Routing and system setup
    #[arg(short, long, value_name = "method", value_enum)]
    setup: Option<ArgSetup>,

    /// Public proxy IP used in routing setup
    #[arg(long, value_name = "IP")]
    setup_ip: Option<IpAddr>,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
enum ArgDns {
    Virtual,
    None,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
enum ArgSetup {
    Auto,
}

fn main() -> ExitCode {
    dotenvy::dotenv().ok();
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let args = Args::parse();

    let addr = args.proxy.addr;
    let proxy_type = args.proxy.proxy_type;
    log::info!("Proxy {proxy_type} server: {addr}");

    let mut options = Options::new();
    if args.dns == ArgDns::Virtual {
        options = options.with_virtual_dns();
    }

    if let Err(e) = (|| -> Result<(), Error> {
        let mut setup: Setup;
        if args.setup == Some(ArgSetup::Auto) {
            let bypass_tun_ip = match args.setup_ip {
                Some(addr) => addr,
                None => args.proxy.addr.ip(),
            };
            setup = Setup::new(
                &args.tun,
                &bypass_tun_ip,
                get_default_cidrs(),
                args.setup_ip.is_some(),
            );

            setup.configure()?;

            setup.drop_privileges()?;
        }

        main_entry(&args.tun, &args.proxy, options)?;

        Ok(())
    })() {
        log::error!("{e}");
        std::process::exit(1);
    };

    ExitCode::SUCCESS
}
