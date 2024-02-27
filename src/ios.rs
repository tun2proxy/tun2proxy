#![cfg(any(target_os = "ios", target_os = "macos"))]

use crate::{
    args::{ArgDns, ArgProxy},
    ArgVerbosity, Args,
};
use std::os::raw::{c_char, c_int, c_ushort};

/// # Safety
///
/// Run the tun2proxy component with some arguments.
#[no_mangle]
pub unsafe extern "C" fn tun2proxy_run_with_fd(
    proxy_url: *const c_char,
    tun_fd: c_int,
    tun_mtu: c_ushort,
    dns_strategy: ArgDns,
    verbosity: ArgVerbosity,
) -> c_int {
    log::set_max_level(verbosity.into());
    log::set_boxed_logger(Box::<crate::dump_logger::DumpLogger>::default()).unwrap();

    let proxy_url = std::ffi::CStr::from_ptr(proxy_url).to_str().unwrap();
    let proxy = ArgProxy::from_url(proxy_url).unwrap();

    let mut args = Args::default();
    args.proxy(proxy).tun_fd(Some(tun_fd)).dns(dns_strategy).verbosity(verbosity);

    crate::mobile_api::mobile_run(args, tun_mtu)
}

/// # Safety
///
/// Shutdown the tun2proxy component.
#[no_mangle]
pub unsafe extern "C" fn tun2proxy_with_fd_stop() -> c_int {
    crate::mobile_api::mobile_stop()
}
