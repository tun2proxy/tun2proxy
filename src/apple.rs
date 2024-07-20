#![cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]

use crate::{
    args::{ArgDns, ArgProxy},
    ArgVerbosity, Args,
};
use std::os::raw::{c_char, c_int, c_ushort};

/// # Safety
///
/// Run the tun2proxy component with some arguments.
/// Parameters:
/// - proxy_url: the proxy url, e.g. "socks5://127.0.0.1:1080"
/// - tun_fd: the tun file descriptor, it will be owned by tun2proxy
/// - close_fd_on_drop: whether close the tun_fd on drop
/// - packet_information: whether exists packet information in tun_fd
/// - tun_mtu: the tun mtu
/// - dns_strategy: the dns strategy, see ArgDns enum
/// - verbosity: the verbosity level, see ArgVerbosity enum
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
    log::set_max_level(verbosity.into());
    if let Err(err) = log::set_boxed_logger(Box::<crate::dump_logger::DumpLogger>::default()) {
        log::warn!("failed to set logger: {:?}", err);
    }

    let proxy_url = std::ffi::CStr::from_ptr(proxy_url).to_str().unwrap();
    let proxy = ArgProxy::try_from(proxy_url).unwrap();

    let mut args = Args::default();
    args.proxy(proxy)
        .tun_fd(Some(tun_fd))
        .close_fd_on_drop(close_fd_on_drop)
        .dns(dns_strategy)
        .verbosity(verbosity);

    crate::mobile_api::mobile_run(args, tun_mtu, packet_information)
}

/// # Safety
///
/// Shutdown the tun2proxy component.
#[no_mangle]
pub unsafe extern "C" fn tun2proxy_with_fd_stop() -> c_int {
    crate::mobile_api::mobile_stop()
}
