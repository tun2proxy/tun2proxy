use crate::{
    args::{ArgDns, ArgProxy},
    ArgVerbosity, Args,
};
use std::os::raw::{c_char, c_int, c_ushort};

static TUN_QUIT: std::sync::Mutex<Option<tokio_util::sync::CancellationToken>> = std::sync::Mutex::new(None);

/// # Safety
///
/// Run the tun2proxy component with some arguments.
/// Parameters:
/// - proxy_url: the proxy url, e.g. "socks5://127.0.0.1:1080"
/// - tun: the tun device name, e.g. "utun5"
/// - bypass: the bypass IP/CIDR, e.g. "123.45.67.0/24"
/// - dns_strategy: the dns strategy, see ArgDns enum
/// - root_privilege: whether to run with root privilege
/// - verbosity: the verbosity level, see ArgVerbosity enum
#[no_mangle]
pub unsafe extern "C" fn tun2proxy_with_name_run(
    proxy_url: *const c_char,
    tun: *const c_char,
    bypass: *const c_char,
    dns_strategy: ArgDns,
    _root_privilege: bool,
    verbosity: ArgVerbosity,
) -> c_int {
    let proxy_url = std::ffi::CStr::from_ptr(proxy_url).to_str().unwrap();
    let proxy = ArgProxy::try_from(proxy_url).unwrap();
    let tun = std::ffi::CStr::from_ptr(tun).to_str().unwrap().to_string();

    let mut args = Args::default();
    if let Ok(bypass) = std::ffi::CStr::from_ptr(bypass).to_str() {
        args.bypass(bypass.parse().unwrap());
    }
    args.proxy(proxy).tun(tun).dns(dns_strategy).verbosity(verbosity);

    #[cfg(target_os = "linux")]
    args.setup(_root_privilege);

    general_run_for_api(args, tun::DEFAULT_MTU, false)
}

/// # Safety
///
/// Run the tun2proxy component with some arguments.
/// Parameters:
/// - proxy_url: the proxy url, e.g. "socks5://127.0.0.1:1080"
/// - tun_fd: the tun file descriptor, it will be owned by tun2proxy
/// - close_fd_on_drop: whether close the tun_fd on drop
/// - packet_information: indicates whether exists packet information in packet from TUN device
/// - tun_mtu: the tun mtu
/// - dns_strategy: the dns strategy, see ArgDns enum
/// - verbosity: the verbosity level, see ArgVerbosity enum
#[cfg(unix)]
#[no_mangle]
pub unsafe extern "C" fn tun2proxy_with_fd_run(
    proxy_url: *const c_char,
    tun_fd: c_int,
    close_fd_on_drop: bool,
    packet_information: bool,
    tun_mtu: c_ushort,
    dns_strategy: ArgDns,
    verbosity: ArgVerbosity,
) -> c_int {
    let proxy_url = std::ffi::CStr::from_ptr(proxy_url).to_str().unwrap();
    let proxy = ArgProxy::try_from(proxy_url).unwrap();

    let mut args = Args::default();
    args.proxy(proxy)
        .tun_fd(Some(tun_fd))
        .close_fd_on_drop(close_fd_on_drop)
        .dns(dns_strategy)
        .verbosity(verbosity);

    general_run_for_api(args, tun_mtu, packet_information)
}

/// # Safety
/// Run the tun2proxy component with command line arguments
/// Parameters:
/// - cli_args: The command line arguments,
///   e.g. `tun2proxy-bin --setup --proxy socks5://127.0.0.1:1080 --bypass 98.76.54.0/24 --dns over-tcp --verbosity trace`
/// - tun_mtu: The MTU of the TUN device, e.g. 1500
/// - packet_information: Whether exists packet information in packet from TUN device
#[no_mangle]
pub unsafe extern "C" fn tun2proxy_run_with_cli_args(cli_args: *const c_char, tun_mtu: c_ushort, packet_information: bool) -> c_int {
    let Ok(cli_args) = std::ffi::CStr::from_ptr(cli_args).to_str() else {
        return -5;
    };
    let args = <Args as ::clap::Parser>::parse_from(cli_args.split_whitespace());
    general_run_for_api(args, tun_mtu, packet_information)
}

pub fn general_run_for_api(args: Args, tun_mtu: u16, packet_information: bool) -> c_int {
    log::set_max_level(args.verbosity.into());
    if let Err(err) = log::set_boxed_logger(Box::<crate::dump_logger::DumpLogger>::default()) {
        log::debug!("set logger error: {}", err);
    }

    let shutdown_token = tokio_util::sync::CancellationToken::new();
    if let Ok(mut lock) = TUN_QUIT.lock() {
        if lock.is_some() {
            log::error!("tun2proxy already started");
            return -1;
        }
        *lock = Some(shutdown_token.clone());
    } else {
        log::error!("failed to lock tun2proxy quit token");
        return -2;
    }

    let Ok(rt) = tokio::runtime::Builder::new_multi_thread().enable_all().build() else {
        log::error!("failed to create tokio runtime with");
        return -3;
    };
    match rt.block_on(async move {
        if let Err(err) = general_run_async(args, tun_mtu, packet_information, shutdown_token).await {
            log::error!("main loop error: {}", err);
            return Err(err);
        }
        Ok(())
    }) {
        Ok(_) => 0,
        Err(e) => {
            log::error!("failed to run tun2proxy with error: {:?}", e);
            -4
        }
    }
}

/// Run the tun2proxy component with some arguments.
pub async fn general_run_async(
    args: Args,
    tun_mtu: u16,
    _packet_information: bool,
    shutdown_token: tokio_util::sync::CancellationToken,
) -> std::io::Result<()> {
    let mut tun_config = tun::Configuration::default();

    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    {
        use tproxy_config::{TUN_GATEWAY, TUN_IPV4, TUN_NETMASK};
        tun_config.address(TUN_IPV4).netmask(TUN_NETMASK).mtu(tun_mtu).up();
        tun_config.destination(TUN_GATEWAY);
    }

    #[cfg(unix)]
    if let Some(fd) = args.tun_fd {
        tun_config.raw_fd(fd);
        if let Some(v) = args.close_fd_on_drop {
            tun_config.close_fd_on_drop(v);
        };
    } else if let Some(ref tun) = args.tun {
        tun_config.tun_name(tun);
    }
    #[cfg(windows)]
    if let Some(ref tun) = args.tun {
        tun_config.tun_name(tun);
    }

    #[cfg(target_os = "linux")]
    tun_config.platform_config(|cfg| {
        #[allow(deprecated)]
        cfg.packet_information(true);
        cfg.ensure_root_privileges(args.setup);
    });

    #[cfg(target_os = "windows")]
    tun_config.platform_config(|cfg| {
        cfg.device_guid(12324323423423434234_u128);
    });

    #[cfg(any(target_os = "ios", target_os = "macos"))]
    tun_config.platform_config(|cfg| {
        cfg.packet_information(_packet_information);
    });

    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    #[allow(unused_variables)]
    let mut tproxy_args = tproxy_config::TproxyArgs::new()
        .tun_dns(args.dns_addr)
        .proxy_addr(args.proxy.addr)
        .bypass_ips(&args.bypass)
        .ipv6_default_route(args.ipv6_enabled);

    #[allow(unused_mut, unused_assignments, unused_variables)]
    let mut setup = true;

    let device = tun::create_as_async(&tun_config)?;

    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    if let Ok(tun_name) = tun::AbstractDevice::tun_name(&*device) {
        // Above line is equivalent to: `use tun::AbstractDevice; if let Ok(tun_name) = device.tun_name() {`
        tproxy_args = tproxy_args.tun_name(&tun_name);
    }

    // TproxyState implements the Drop trait to restore network configuration,
    // so we need to assign it to a variable, even if it is not used.
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    let mut _restore: Option<tproxy_config::TproxyState> = None;

    #[cfg(target_os = "linux")]
    {
        setup = args.setup;
    }

    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    if setup {
        _restore = Some(tproxy_config::tproxy_setup(&tproxy_args)?);
    }

    #[cfg(target_os = "linux")]
    {
        let mut admin_command_args = args.admin_command.iter();
        if let Some(command) = admin_command_args.next() {
            let child = tokio::process::Command::new(command)
                .args(admin_command_args)
                .kill_on_drop(true)
                .spawn();

            match child {
                Err(err) => {
                    log::warn!("Failed to start admin process: {err}");
                }
                Ok(mut child) => {
                    tokio::spawn(async move {
                        if let Err(err) = child.wait().await {
                            log::warn!("Admin process terminated: {err}");
                        }
                    });
                }
            };
        }
    }

    let join_handle = tokio::spawn(crate::run(device, tun_mtu, args, shutdown_token));
    Ok(join_handle.await.map_err(std::io::Error::from)??)
}

/// # Safety
///
/// Shutdown the tun2proxy component.
#[no_mangle]
pub unsafe extern "C" fn tun2proxy_stop() -> c_int {
    tun2proxy_stop_internal()
}

pub(crate) fn tun2proxy_stop_internal() -> c_int {
    if let Ok(mut lock) = TUN_QUIT.lock() {
        if let Some(shutdown_token) = lock.take() {
            shutdown_token.cancel();
            return 0;
        }
    }
    -1
}
