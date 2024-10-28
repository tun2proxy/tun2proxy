#![cfg(any(target_os = "ios", target_os = "android", target_os = "macos"))]

use crate::Args;
use std::os::raw::c_int;

static TUN_QUIT: std::sync::Mutex<Option<tokio_util::sync::CancellationToken>> = std::sync::Mutex::new(None);

/// Dummy function to make the build pass.
#[doc(hidden)]
#[cfg(not(target_os = "macos"))]
pub async fn desktop_run_async(_: Args, _: tokio_util::sync::CancellationToken) -> std::io::Result<()> {
    Ok(())
}

pub fn mobile_run(args: Args, tun_mtu: u16, _packet_information: bool) -> c_int {
    let shutdown_token = tokio_util::sync::CancellationToken::new();
    {
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
    }

    let block = async move {
        let mut config = tun::Configuration::default();

        #[cfg(unix)]
        if let Some(fd) = args.tun_fd {
            config.raw_fd(fd);
            if let Some(v) = args.close_fd_on_drop {
                config.close_fd_on_drop(v);
            };
        } else if let Some(ref tun) = args.tun {
            config.tun_name(tun);
        }
        #[cfg(windows)]
        if let Some(ref tun) = args.tun {
            config.tun_name(tun);
        }

        #[cfg(any(target_os = "ios", target_os = "macos"))]
        config.platform_config(|config| {
            config.packet_information(_packet_information);
        });

        let device = tun::create_as_async(&config).map_err(std::io::Error::from)?;
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

    exit_code
}

pub fn mobile_stop() -> c_int {
    if let Ok(mut lock) = TUN_QUIT.lock() {
        if let Some(shutdown_token) = lock.take() {
            shutdown_token.cancel();
            return 0;
        }
    }
    -1
}
