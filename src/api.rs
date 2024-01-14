#![cfg(any(target_os = "ios", target_os = "android"))]

use crate::{Args, Builder, Quit};
use std::{os::raw::c_int, sync::Arc};

static mut TUN_QUIT: Option<Arc<Quit>> = None;

pub(crate) fn tun2proxy_internal_run(args: Args, tun_mtu: usize) -> c_int {
    if unsafe { TUN_QUIT.is_some() } {
        log::error!("tun2proxy already started");
        return -1;
    }

    let block = async move {
        log::info!("Proxy {} server: {}", args.proxy.proxy_type, args.proxy.addr);

        let mut config = tun2::Configuration::default();
        config.raw_fd(args.tun_fd.ok_or(crate::Error::from("tun_fd"))?);

        let device = tun2::create_as_async(&config).map_err(std::io::Error::from)?;

        #[cfg(target_os = "android")]
        let tun2proxy = Builder::new(device, args).mtu(tun_mtu).build();
        #[cfg(target_os = "ios")]
        let tun2proxy = Builder::new(device, args).mtu(tun_mtu).build();
        let (join_handle, quit) = tun2proxy.start();

        unsafe { TUN_QUIT = Some(Arc::new(quit)) };

        join_handle.await
    };

    match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Err(_err) => {
            log::error!("failed to create tokio runtime with error: {:?}", _err);
            -1
        }
        Ok(rt) => match rt.block_on(block) {
            Ok(_) => 0,
            Err(_err) => {
                log::error!("failed to run tun2proxy with error: {:?}", _err);
                -2
            }
        },
    }
}

pub(crate) fn tun2proxy_internal_stop() -> c_int {
    let res = match unsafe { &TUN_QUIT } {
        None => {
            log::error!("tun2proxy not started");
            -1
        }
        Some(tun_quit) => match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
            Err(_err) => {
                log::error!("failed to create tokio runtime with error: {:?}", _err);
                -2
            }
            Ok(rt) => match rt.block_on(async move { tun_quit.trigger().await }) {
                Ok(_) => 0,
                Err(_err) => {
                    log::error!("failed to stop tun2proxy with error: {:?}", _err);
                    -3
                }
            },
        },
    };
    unsafe { TUN_QUIT = None };
    res
}
