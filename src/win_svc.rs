#![cfg(windows)]

const SERVICE_NAME: &str = "tun2proxy";

windows_service::define_windows_service!(ffi_service_main, my_service_main);

pub fn start_service() -> Result<(), windows_service::Error> {
    // Register generated `ffi_service_main` with the system and start the service,
    // blocking this thread until the service is stopped.
    windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

fn my_service_main(arguments: Vec<std::ffi::OsString>) {
    // The entry point where execution will start on a background thread after a call to
    // `service_dispatcher::start` from `main`.

    if let Err(_e) = run_service(arguments) {
        log::error!("Error: {:?}", _e);
    }
}

fn run_service(_arguments: Vec<std::ffi::OsString>) -> Result<(), crate::BoxError> {
    use windows_service::service::ServiceControl;
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

    let shutdown_token = crate::CancellationToken::new();
    let shutdown_token_clone = shutdown_token.clone();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                // Handle stop event and return control back to the system.
                shutdown_token_clone.cancel();
                ServiceControlHandlerResult::NoError
            }
            // All services must accept Interrogate even if it's a no-op.
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    // Register system service event handler
    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    let mut next_status = windows_service::service::ServiceStatus {
        // Should match the one from system service registry
        service_type: windows_service::service::ServiceType::OWN_PROCESS,
        // The new state
        current_state: windows_service::service::ServiceState::Running,
        // Accept stop events when running
        controls_accepted: windows_service::service::ServiceControlAccept::STOP,
        // Used to report an error when starting or stopping only, otherwise must be zero
        exit_code: windows_service::service::ServiceExitCode::Win32(0),
        // Only used for pending states, otherwise must be zero
        checkpoint: 0,
        // Only used for pending states, otherwise must be zero
        wait_hint: std::time::Duration::default(),
        // Unused for setting status
        process_id: None,
    };

    // Tell the system that the service is running now
    status_handle.set_service_status(next_status.clone())?;

    // main logic here
    {
        let args = crate::Args::parse_args();

        let default = format!("{:?},trust_dns_proto=warn", args.verbosity);
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default)).init();

        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
        rt.block_on(async {
            unsafe extern "C" fn traffic_cb(status: *const crate::TrafficStatus, _: *mut std::ffi::c_void) {
                let status = &*status;
                log::debug!("Traffic: ▲ {} : ▼ {}", status.tx, status.rx);
            }
            unsafe { crate::tun2proxy_set_traffic_status_callback(1, Some(traffic_cb), std::ptr::null_mut()) };

            if let Err(err) = crate::general_run_async(args, tun::DEFAULT_MTU, false, shutdown_token).await {
                log::error!("main loop error: {}", err);
            }
            Ok::<(), crate::Error>(())
        })?;
    }

    // Tell the system that the service is stopped now
    next_status.current_state = windows_service::service::ServiceState::Stopped;
    status_handle.set_service_status(next_status)?;

    Ok(())
}
