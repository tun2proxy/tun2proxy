#![cfg(target_os = "ios")]

use crate::{
    args::{ArgDns, ArgProxy},
    ArgVerbosity, Args,
};
use std::os::raw::{c_char, c_int, c_uint};

/// # Safety
///
/// Run the tun2proxy component with some arguments.
#[no_mangle]
pub unsafe extern "C" fn tun2proxy_run(
    proxy_url: *const c_char,
    tun_fd: c_int,
    tun_mtu: c_uint,
    dns_over_tcp: c_char,
    verbose: c_char,
) -> c_int {
    use log::LevelFilter;
    let log_level = if verbose != 0 { LevelFilter::Trace } else { LevelFilter::Info };
    log::set_max_level(log_level);
    log::set_boxed_logger(Box::<crate::dump_logger::DumpLogger>::default()).unwrap();

    let dns = if dns_over_tcp != 0 { ArgDns::OverTcp } else { ArgDns::Direct };
    let verbosity = if verbose != 0 { ArgVerbosity::Trace } else { ArgVerbosity::Info };
    let proxy_url = std::ffi::CStr::from_ptr(proxy_url).to_str().unwrap();
    let proxy = ArgProxy::from_url(proxy_url).unwrap();

    let args = Args::new(Some(tun_fd), proxy, dns, verbosity);

    crate::api::tun2proxy_internal_run(args, tun_mtu as _)
}

/// # Safety
///
/// Shutdown the tun2proxy component.
#[no_mangle]
pub unsafe extern "C" fn tun2proxy_stop() -> c_int {
    crate::api::tun2proxy_internal_stop()
}
