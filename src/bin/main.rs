use tun2proxy::{desktop_run, Args, BoxError};

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    dotenvy::dotenv().ok();
    let args = Args::parse_args();

    // let default = format!("{}={:?}", module_path!(), args.verbosity);
    let default = format!("{:?}", args.verbosity);
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default)).init();

    let shutdown_token = tokio_util::sync::CancellationToken::new();
    let join_handle = tokio::spawn(desktop_run(args, shutdown_token.clone()));

    ctrlc2::set_async_handler(async move {
        log::info!("Ctrl-C received, exiting...");
        shutdown_token.cancel();
    })
    .await;

    if let Err(err) = join_handle.await {
        log::trace!("main_entry error {}", err);
    }

    Ok(())
}
