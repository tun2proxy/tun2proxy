#![cfg(any(target_os = "windows", target_os = "macos", target_os = "linux"))]

use crate::{
    args::{ArgDns, ArgProxy},
    ArgVerbosity, Args,
};
use std::os::raw::{c_char, c_int};
use tproxy_config::{TproxyArgs, TUN_GATEWAY, TUN_IPV4, TUN_NETMASK};
use tun2::{AbstractDevice, DEFAULT_MTU as MTU};

static TUN_QUIT: std::sync::Mutex<Option<tokio_util::sync::CancellationToken>> = std::sync::Mutex::new(None);

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
    let shutdown_token = tokio_util::sync::CancellationToken::new();
    {
        if let Ok(mut lock) = TUN_QUIT.lock() {
            if lock.is_some() {
                return -1;
            }
            *lock = Some(shutdown_token.clone());
        } else {
            return -2;
        }
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

    let main_loop = async move {
        if let Err(err) = desktop_run_async(args, shutdown_token).await {
            log::error!("main loop error: {}", err);
            return Err(err);
        }
        Ok(())
    };

    let exit_code = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Err(_e) => -3,
        Ok(rt) => match rt.block_on(main_loop) {
            Ok(_) => 0,
            Err(_e) => -4,
        },
    };

    // release shutdown token before exit.
    if let Ok(mut lock) = TUN_QUIT.lock() {
        let _ = lock.take();
    }

    exit_code
}

/// Run the tun2proxy component with some arguments.
pub async fn desktop_run_async(args: Args, shutdown_token: tokio_util::sync::CancellationToken) -> std::io::Result<()> {
    let bypass_ips = args.bypass.clone();

    let mut config = tun2::Configuration::default();
    config.address(TUN_IPV4).netmask(TUN_NETMASK).mtu(MTU).up();
    config.destination(TUN_GATEWAY);
    if let Some(tun_fd) = args.tun_fd {
        config.raw_fd(tun_fd);
    } else if let Some(ref tun) = args.tun {
        config.tun_name(tun);
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

    #[allow(unused_mut, unused_assignments, unused_variables)]
    let mut setup = true;

    let device = tun2::create_as_async(&config)?;

    if let Ok(tun_name) = device.as_ref().tun_name() {
        tproxy_args = tproxy_args.tun_name(&tun_name);
    }

    let mut restore: Option<tproxy_config::TproxyRestore> = None;

    #[cfg(target_os = "linux")]
    {
        setup = args.setup;
    }

    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    if setup {
        restore = Some(tproxy_config::tproxy_setup(&tproxy_args)?);
    }

    let join_handle = tokio::spawn(crate::run(device, MTU, args, shutdown_token));
    join_handle.await.map_err(std::io::Error::from)??;

    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    if setup {
        tproxy_config::tproxy_remove(restore)?;
    }

    Ok::<(), std::io::Error>(())
}

/// # Safety
///
/// Shutdown the tun2proxy component.
#[no_mangle]
pub unsafe extern "C" fn tun2proxy_with_name_stop() -> c_int {
    if let Ok(lock) = TUN_QUIT.lock() {
        if let Some(shutdown_token) = lock.as_ref() {
            shutdown_token.cancel();
            return 0;
        }
    }
    -1
}
