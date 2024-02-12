#![cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]

use crate::{
    args::{ArgDns, ArgProxy},
    ArgVerbosity, Args,
};
use std::os::raw::{c_char, c_int};
use tokio_util::sync::CancellationToken;
use tproxy_config::{TproxyArgs, TUN_GATEWAY, TUN_IPV4, TUN_NETMASK};
use tun2::DEFAULT_MTU as MTU;

static TUN_QUIT: std::sync::Mutex<Option<CancellationToken>> = std::sync::Mutex::new(None);

/// # Safety
///
/// Run the tun2proxy component with some arguments.
#[no_mangle]
pub unsafe extern "C" fn tun2proxy_run_with_name(
    proxy_url: *const c_char,
    tun: *const c_char,
    bypass: *const c_char,
    dns_strategy: ArgDns,
    _root_privilege: bool,
    verbosity: ArgVerbosity,
) -> c_int {
    let shutdown_token = CancellationToken::new();
    {
        let mut lock = TUN_QUIT.lock().unwrap();
        if lock.is_some() {
            log::error!("tun2proxy already started");
            return -1;
        }
        *lock = Some(shutdown_token.clone());
    }

    log::set_max_level(verbosity.into());
    log::set_boxed_logger(Box::<crate::dump_logger::DumpLogger>::default()).unwrap();

    let proxy_url = std::ffi::CStr::from_ptr(proxy_url).to_str().unwrap();
    let proxy = ArgProxy::from_url(proxy_url).unwrap();
    let tun = std::ffi::CStr::from_ptr(tun).to_str().unwrap().to_string();

    let mut args = Args::default();
    args.proxy(proxy).tun(tun).dns(dns_strategy).verbosity(verbosity);

    #[cfg(target_os = "linux")]
    args.setup(_root_privilege);

    if let Ok(bypass) = std::ffi::CStr::from_ptr(bypass).to_str() {
        args.bypass(bypass.parse().unwrap());
    }

    let block = async move {
        let bypass_ips = args.bypass.clone();

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

        #[cfg(target_os = "linux")]
        tproxy_config::tproxy_setup(&tproxy_args)?;

        let device = tun2::create_as_async(&config)?;

        #[cfg(any(target_os = "windows", target_os = "macos"))]
        tproxy_config::tproxy_setup(&tproxy_args)?;

        log::info!("Proxy {} server: {}", args.proxy.proxy_type, args.proxy.addr);

        let join_handle = tokio::spawn(crate::run(device, MTU, args, shutdown_token));
        join_handle.await.map_err(std::io::Error::from)??;

        #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
        if _root_privilege {
            tproxy_config::tproxy_remove(&tproxy_args)?;
        }

        Ok::<(), crate::BoxError>(())
    };

    let exit_code = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Err(_e) => -1,
        Ok(rt) => match rt.block_on(block) {
            Ok(_) => 0,
            Err(_e) => -2,
        },
    };

    // release shutdown token before exit.
    if let Ok(mut lock) = TUN_QUIT.lock() {
        let _ = lock.take();
    }

    exit_code
}

/// # Safety
///
/// Shutdown the tun2proxy component.
#[no_mangle]
pub unsafe extern "C" fn tun2proxy_stop() -> c_int {
    if let Ok(lock) = TUN_QUIT.lock() {
        if let Some(shutdown_token) = lock.as_ref() {
            shutdown_token.cancel();
            return 0;
        }
    }
    -1
}
