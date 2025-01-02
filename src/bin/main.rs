use tun::DEFAULT_MTU as MTU;
use tun2proxy::{Args, BoxError};

fn main() -> Result<(), BoxError> {
    dotenvy::dotenv().ok();
    let args = Args::parse_args();

    #[cfg(unix)]
    if args.daemonize {
        let stdout = std::fs::File::create("/tmp/tun2proxy.out")?;
        let stderr = std::fs::File::create("/tmp/tun2proxy.err")?;
        let daemonize = daemonize::Daemonize::new()
            .working_directory("/tmp")
            .umask(0o777)
            .stdout(stdout)
            .stderr(stderr)
            .privileged_action(|| "Executed before drop privileges");
        let _ = daemonize.start()?;
    }

    #[cfg(target_os = "windows")]
    if args.daemonize {
        tun2proxy::win_svc::start_service()?;
        return Ok(());
    }

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(main_async(args))
}

async fn main_async(args: Args) -> Result<(), BoxError> {
    let default = format!("{:?},hickory_proto=warn", args.verbosity);
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default)).init();

    let shutdown_token = tokio_util::sync::CancellationToken::new();
    let main_loop_handle = tokio::spawn({
        let shutdown_token = shutdown_token.clone();
        async move {
            #[cfg(target_os = "linux")]
            if args.unshare && args.socket_transfer_fd.is_none() {
                if let Err(err) = namespace_proxy_main(args, shutdown_token).await {
                    log::error!("namespace proxy error: {}", err);
                }
                return;
            }

            unsafe extern "C" fn traffic_cb(status: *const tun2proxy::TrafficStatus, _: *mut std::ffi::c_void) {
                let status = &*status;
                log::debug!("Traffic: ▲ {} : ▼ {}", status.tx, status.rx);
            }
            unsafe { tun2proxy::tun2proxy_set_traffic_status_callback(1, Some(traffic_cb), std::ptr::null_mut()) };

            if let Err(err) = tun2proxy::general_run_async(args, MTU, false, shutdown_token).await {
                log::error!("main loop error: {}", err);
            }
        }
    });

    let ctrlc_fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ctrlc_fired_clone = ctrlc_fired.clone();
    let ctrlc_handel = ctrlc2::set_async_handler(async move {
        log::info!("Ctrl-C received, exiting...");
        ctrlc_fired_clone.store(true, std::sync::atomic::Ordering::SeqCst);
        shutdown_token.cancel();
    })
    .await;

    main_loop_handle.await?;

    if ctrlc_fired.load(std::sync::atomic::Ordering::SeqCst) {
        log::info!("Ctrl-C fired, waiting the handler to finish...");
        ctrlc_handel.await.map_err(|err| err.to_string())?;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
async fn namespace_proxy_main(
    _args: Args,
    _shutdown_token: tokio_util::sync::CancellationToken,
) -> Result<std::process::ExitStatus, tun2proxy::Error> {
    use nix::fcntl::{open, OFlag};
    use nix::sys::stat::Mode;
    use std::os::fd::AsRawFd;

    let (socket, remote_fd) = tun2proxy::socket_transfer::create_transfer_socket_pair().await?;

    let fd = open("/proc/self/exe", OFlag::O_PATH, Mode::empty())?;

    let child = tokio::process::Command::new("unshare")
        .args("--user --map-current-user --net --mount --keep-caps --kill-child --fork".split(' '))
        .arg(format!("/proc/self/fd/{}", fd))
        .arg("--socket-transfer-fd")
        .arg(remote_fd.as_raw_fd().to_string())
        .args(std::env::args().skip(1))
        .kill_on_drop(true)
        .spawn();

    let mut child = match child {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            log::error!("`unshare(1)` executable wasn't located in PATH.");
            log::error!("Consider installing linux utils package: `apt install util-linux`");
            log::error!("Or similar for your distribution.");
            return Err(err.into());
        }
        child => child?,
    };

    let unshare_pid = child.id().unwrap_or(0);
    log::info!("The tun proxy is running in unprivileged mode. See `namespaces(7)`.");
    log::info!("");
    log::info!("If you need to run a process that relies on root-like capabilities (e.g. `openvpn`)");
    log::info!("Use `tun2proxy-bin --unshare --setup [...] -- openvpn --config [...]`");
    log::info!("");
    log::info!("To run a new process in the created namespace (e.g. a flatpak app)");
    log::info!(
        "Use `nsenter --preserve-credentials --user --net --mount  --target {} /bin/sh`",
        unshare_pid
    );
    log::info!("");
    if let Some(pidfile) = _args.unshare_pidfile.as_ref() {
        log::info!("Writing unshare pid to {}", pidfile);
        std::fs::write(pidfile, unshare_pid.to_string()).ok();
    }
    tokio::spawn(async move { tun2proxy::socket_transfer::process_socket_requests(&socket).await });

    Ok(child.wait().await?)
}
