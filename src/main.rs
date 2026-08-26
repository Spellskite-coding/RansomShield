mod baseline;
mod config;
mod detector;
mod entropy;
mod fanotify_monitor;
mod honeypot;
mod incident;
mod quarantine;
mod response;
mod trust;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(
    name = "ransomshield",
    version,
    about = "Behavior-based ransomware detection daemon"
)]
struct Args {
    /// Path to the JSON config file.
    #[arg(short, long, default_value = "/etc/ransomshield/config.json")]
    config: PathBuf,

    /// Verbose (debug-level) logging.
    #[arg(short, long)]
    verbose: bool,
}

fn init_tracing(verbose: bool) {
    let level = if verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level)),
        )
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_tracing(args.verbose);

    let cfg = config::Config::load(&args.config)?;
    info!(?cfg.mode, watch_dirs = ?cfg.watch_dirs, "loaded config");

    let honeypots = honeypot::Honeypots::provision(&cfg.honeypots)?;

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let worker_cfg = cfg.clone();
    let monitor =
        tokio::task::spawn_blocking(move || fanotify_monitor::run(worker_cfg, honeypots, ready_tx));

    // Only tell systemd (and Restart=on-failure) we're up once monitoring
    // actually initialized - not just once the worker thread was spawned.
    // Otherwise a fanotify_init/mark failure would still report READY=1,
    // the process would then exit 0 after logging the error below, and
    // systemd would never restart it: the host would be silently
    // unprotected.
    match ready_rx.await {
        Ok(Ok(())) => {
            let _ = sd_notify::notify(&[sd_notify::NotifyState::Ready]);
            info!("ransomshield ready");
        }
        Ok(Err(e)) => {
            error!(error = %e, "monitor failed to initialize, not reporting ready");
        }
        Err(_) => {
            error!("monitor worker ended before reporting readiness (likely panicked)");
        }
    }

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    tokio::select! {
        res = monitor => {
            return match res {
                Ok(Ok(())) => { info!("monitor loop exited"); Ok(()) }
                Ok(Err(e)) => { error!(error = %e, "monitor loop failed"); Err(e) }
                Err(e) => { error!(error = %e, "monitor task panicked"); Err(anyhow::anyhow!(e)) }
            };
        }
        _ = tokio::signal::ctrl_c() => {
            info!("received SIGINT, shutting down");
            // The monitor thread is parked in a blocking fanotify read()
            // syscall with no natural way to interrupt it; dropping the
            // tokio runtime at the end of main() waits for spawn_blocking
            // tasks to finish, which would hang forever here. There is no
            // in-flight work worth draining (quarantine writes are
            // synchronous and already complete by the time we react to a
            // signal), so exit immediately rather than hang until SIGKILL.
            std::process::exit(0);
        }
        _ = sigterm.recv() => {
            info!("received SIGTERM, shutting down");
            std::process::exit(0);
        }
    }
}
