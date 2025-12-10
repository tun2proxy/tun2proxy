use tun2proxy::{ArgVerbosity, Args, BoxError};

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
    rt.block_on(async move {
        let res = main_async(args).await;
        // Start a timer to force exit after FORCE_EXIT_TIMEOUT second
        let _h = tokio::spawn(async move {
            log::info!("Starting {}-seconds exit timer", tun2proxy::FORCE_EXIT_TIMEOUT);
            // Delay some seconds then try to exit current process if not exited yet, normally this case should not happen
            tokio::time::sleep(std::time::Duration::from_secs(tun2proxy::FORCE_EXIT_TIMEOUT)).await;
            log::info!("Forcing exit now.");
            std::process::exit(-1);
        });

        log::info!("Runtime.block_on exiting...");
        tokio::time::sleep(std::time::Duration::from_micros(100)).await;

        res
    })
}

fn setup_logging(args: &Args) {
    let avoid_trace = match args.verbosity {
        ArgVerbosity::Trace => ArgVerbosity::Debug,
        _ => args.verbosity,
    };
    let default = format!(
        "{:?},hickory_proto=warn,ipstack={:?},netlink_proto={:?},netlink_sys={:?}",
        args.verbosity, avoid_trace, avoid_trace, avoid_trace
    );
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default)).init();
}

async fn main_async(args: Args) -> Result<(), BoxError> {
    setup_logging(&args);

    let shutdown_token = tokio_util::sync::CancellationToken::new();
    let main_loop_handle = tokio::spawn({
        let args = args.clone();
        let shutdown_token = shutdown_token.clone();
        async move {
            #[cfg(target_os = "linux")]
            if args.unshare && args.socket_transfer_fd.is_none() {
                if let Err(err) = namespace_proxy_main(args, shutdown_token).await {
                    log::error!("namespace proxy error: {err}");
                }
                return Ok(0);
            }

            unsafe extern "C" fn traffic_cb(status: *const tun2proxy::TrafficStatus, _: *mut std::ffi::c_void) {
                let status = unsafe { &*status };
                log::debug!("Traffic: ▲ {} : ▼ {}", status.tx, status.rx);
            }
            unsafe { tun2proxy::tun2proxy_set_traffic_status_callback(1, Some(traffic_cb), std::ptr::null_mut()) };

            let ret = tun2proxy::general_run_async(args, tun::DEFAULT_MTU, cfg!(target_os = "macos"), shutdown_token).await;
            if let Err(err) = &ret {
                log::error!("main loop error: {err}");
            }
            ret
        }
    });

    let ctrlc_fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ctrlc_fired_clone = ctrlc_fired.clone();
    let ctrlc_handel = ctrlc2::AsyncCtrlC::new(move || {
        log::info!("Ctrl-C received, exiting...");
        ctrlc_fired_clone.store(true, std::sync::atomic::Ordering::SeqCst);
        shutdown_token.cancel();
        true
    })?;

    let _tasks = main_loop_handle.await??;

    if ctrlc_fired.load(std::sync::atomic::Ordering::SeqCst) {
        log::info!("Ctrl-C fired, waiting the handler to finish...");
        match tokio::time::timeout(std::time::Duration::from_secs(1), ctrlc_handel).await {
            Ok(Ok(())) => log::info!("Ctrl-C handler finished"),
            Ok(Err(e)) => log::warn!("Ctrl-C handler error: {e}"),
            Err(_) => log::warn!("Ctrl-C handler timeout, continuing..."),
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
async fn namespace_proxy_main(
    _args: Args,
    _shutdown_token: tokio_util::sync::CancellationToken,
) -> Result<std::process::ExitStatus, tun2proxy::Error> {
    use nix::fcntl::{OFlag, open};
    use nix::sys::stat::Mode;
    use std::os::fd::AsRawFd;

    let (socket, remote_fd) = tun2proxy::socket_transfer::create_transfer_socket_pair().await?;

    let fd = open("/proc/self/exe", OFlag::O_PATH, Mode::empty())?;

    let child = tokio::process::Command::new("unshare")
        .args("--user --map-current-user --net --mount --keep-caps --kill-child --fork".split(' '))
        .arg(format!("/proc/self/fd/{}", fd.as_raw_fd()))
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
    log::info!("Use `nsenter --preserve-credentials --user --net --mount  --target {unshare_pid} /bin/sh`");
    log::info!("");
    if let Some(pidfile) = _args.unshare_pidfile.as_ref() {
        log::info!("Writing unshare pid to {pidfile}");
        std::fs::write(pidfile, unshare_pid.to_string()).ok();
    }
    tokio::spawn(async move { tun2proxy::socket_transfer::process_socket_requests(&socket).await });

    Ok(child.wait().await?)
}
