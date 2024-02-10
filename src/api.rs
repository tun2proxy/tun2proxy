#![cfg(any(target_os = "ios", target_os = "android"))]

use crate::Args;
use std::{os::raw::c_int, sync::Mutex};
use tokio_util::sync::CancellationToken;

static TUN_QUIT: Mutex<Option<CancellationToken>> = Mutex::new(None);

pub(crate) fn tun2proxy_internal_run(args: Args, tun_mtu: u16) -> c_int {
    let shutdown_token = CancellationToken::new();
    {
        let mut lock = TUN_QUIT.lock().unwrap();
        if lock.is_some() {
            log::error!("tun2proxy already started");
            return -1;
        }
        *lock = Some(shutdown_token.clone());
    }

    let block = async move {
        log::info!("Proxy {} server: {}", args.proxy.proxy_type, args.proxy.addr);

        let mut config = tun2::Configuration::default();
        config.raw_fd(args.tun_fd.ok_or(crate::Error::from("tun_fd"))?);

        let device = tun2::create_as_async(&config).map_err(std::io::Error::from)?;
        let join_handle = tokio::spawn(crate::run(device, tun_mtu, args, shutdown_token));

        join_handle.await.map_err(std::io::Error::from)?
    };

    let exit_code = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Err(e) => {
            log::error!("failed to create tokio runtime with error: {:?}", e);
            -1
        }
        Ok(rt) => match rt.block_on(block) {
            Ok(_) => 0,
            Err(e) => {
                log::error!("failed to run tun2proxy with error: {:?}", e);
                -2
            }
        },
    };

    // release shutdown token before exit.
    let mut lock = TUN_QUIT.lock().unwrap();
    let _ = lock.take();

    exit_code
}

pub(crate) fn tun2proxy_internal_stop() -> c_int {
    let lock = TUN_QUIT.lock().unwrap();

    if let Some(shutdown_token) = lock.as_ref() {
        shutdown_token.cancel();
        0
    } else {
        log::error!("tun2proxy not started");
        -1
    }
}
