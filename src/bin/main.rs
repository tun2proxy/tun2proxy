use tokio_util::sync::CancellationToken;
use tproxy_config::{TproxyArgs, TUN_GATEWAY, TUN_IPV4, TUN_NETMASK};
use tun2::DEFAULT_MTU as MTU;
use tun2proxy::{self, Args};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    let args = Args::parse_args();

    let bypass_ips = args.bypass.clone();

    // let default = format!("{}={:?}", module_path!(), args.verbosity);
    let default = format!("{:?}", args.verbosity);
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default)).init();

    let mut config = tun2::Configuration::default();
    config.address(TUN_IPV4).netmask(TUN_NETMASK).mtu(MTU).up();
    config.destination(TUN_GATEWAY);
    if let Some(tun_fd) = args.tun_fd {
        config.raw_fd(tun_fd);
    } else {
        config.name(&args.tun);
    }

    #[cfg(target_os = "linux")]
    config.platform_config(|config| {
        #[allow(deprecated)]
        config.packet_information(true);
        config.ensure_root_privileges(args.setup);
    });

    #[cfg(target_os = "windows")]
    config.platform_config(|config| {
        config.device_guid(Some(12324323423423434234_u128));
    });

    #[allow(unused_variables)]
    let mut tproxy_args = TproxyArgs::new()
        .tun_dns(args.dns_addr)
        .proxy_addr(args.proxy.addr)
        .bypass_ips(&bypass_ips);
    #[allow(unused_assignments)]
    if args.tun_fd.is_none() {
        tproxy_args = tproxy_args.tun_name(&args.tun);
    }

    #[allow(unused_mut, unused_assignments, unused_variables)]
    let mut setup = true;

    #[cfg(target_os = "linux")]
    {
        setup = args.setup;
        if setup {
            tproxy_config::tproxy_setup(&tproxy_args)?;
        }
    }

    let device = tun2::create_as_async(&config)?;

    #[cfg(any(target_os = "windows", target_os = "macos"))]
    if setup {
        tproxy_config::tproxy_setup(&tproxy_args)?;
    }

    let shutdown_token = CancellationToken::new();
    let join_handle = tokio::spawn(tun2proxy::run(device, MTU, args, shutdown_token.clone()));

    ctrlc2::set_async_handler(async move {
        log::info!("Ctrl-C received, exiting...");
        shutdown_token.cancel();
    })
    .await;

    if let Err(err) = join_handle.await {
        log::trace!("main_entry error {}", err);
    }

    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    if setup {
        tproxy_config::tproxy_remove(&tproxy_args)?;
    }

    Ok(())
}
