//! win4tress DNS filtering resolver (SPEC §13, PLAN Phase 7): a forwarder on
//! loopback that blocks by the lists and rules the service writes into its
//! folder, and answers the service's health checks.
//!
//! `win4tress-dns console` runs in the foreground (port 53 on loopback needs
//! no admin rights, but the default folder does).

mod api;
mod cache;
mod journal;
mod resolve;
mod server;
mod state;
mod upstream;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use crate::resolve::Resolver;
use crate::state::Current;

/// How often the config file is checked.
const RELOAD_EVERY: Duration = Duration::from_secs(1);
/// How often the upstream is checked for its own filtering.
const PROBE_EVERY: Duration = Duration::from_secs(3600);

#[derive(Parser)]
#[command(version, about = "win4tress DNS filtering resolver")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run in this terminal until Ctrl+C
    Console {
        /// Folder with config.json and the compiled blocklist
        /// (default: %ProgramData%\win4tress\dns)
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Port on 127.0.0.1 and ::1 (53 for real use; another for tests)
        #[arg(long, default_value_t = 53)]
        port: u16,
        /// Pipe for the service's status and log requests
        #[arg(long, default_value = w4_dns::status::PIPE_NAME)]
        pipe: String,
        /// Stop after this many seconds (for scripted tests)
        #[arg(long)]
        exit_after: Option<u64>,
    },
}

pub fn default_dir() -> PathBuf {
    let base = std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into());
    PathBuf::from(base).join("win4tress").join("dns")
}

async fn run(dir: PathBuf, port: u16, pipe: String, shutdown: CancellationToken) -> Result<()> {
    let (udp, tcp) = server::bind(port).await.map_err(|e| anyhow!(e))?;
    let listening: Vec<String> = server::addresses(port)
        .iter()
        .map(ToString::to_string)
        .collect();
    let resolver = Arc::new(Resolver::new(Current::new(dir.clone())));
    tracing::info!(dir = %dir.display(), ?listening, "resolver running");

    let mut tasks = tokio::task::JoinSet::new();
    for socket in udp {
        tasks.spawn(server::serve_udp(
            socket,
            Arc::clone(&resolver),
            shutdown.clone(),
        ));
    }
    for listener in tcp {
        tasks.spawn(server::serve_tcp(
            listener,
            Arc::clone(&resolver),
            shutdown.clone(),
        ));
    }
    let api = Arc::new(api::Api {
        resolver: Arc::clone(&resolver),
        started_ms: resolve::now_ms(),
        listening,
    });
    let (notes, _) = broadcast::channel(16);
    let pipe_shutdown = shutdown.clone();
    tasks.spawn(async move {
        let config = w4_ipc::ServerConfig {
            pipe_name: pipe,
            sddl: w4_dns::status::PIPE_SDDL.into(),
        };
        if let Err(e) = w4_ipc::server::serve(config, api, notes, pipe_shutdown).await {
            tracing::warn!("status pipe stopped: {e}");
        }
    });
    // The config file, the upstream's own filtering, idle DoH connections.
    let watch = Arc::clone(&resolver);
    let watch_shutdown = shutdown.clone();
    tasks.spawn(async move {
        watch.probe_upstream().await;
        let mut last_probe = tokio::time::Instant::now();
        let mut tick = tokio::time::interval(RELOAD_EVERY);
        loop {
            tokio::select! {
                _ = watch_shutdown.cancelled() => break,
                _ = tick.tick() => {}
            }
            if watch.current.reload_if_changed() {
                watch.forget();
                watch.probe_upstream().await;
                last_probe = tokio::time::Instant::now();
            } else if last_probe.elapsed() >= PROBE_EVERY {
                watch.probe_upstream().await;
                last_probe = tokio::time::Instant::now();
            }
            watch.close_idle();
        }
    });
    shutdown.cancelled().await;
    tasks.shutdown().await;
    tracing::info!("resolver stopped");
    Ok(())
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Console {
            dir,
            port,
            pipe,
            exit_after,
        } => {
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_env("WIN4TRESS_LOG")
                        .unwrap_or_else(|_| "info".into()),
                )
                .init();
            let shutdown = CancellationToken::new();
            let on_signal = shutdown.clone();
            let runtime = tokio::runtime::Runtime::new()?;
            runtime.spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                on_signal.cancel();
            });
            if let Some(secs) = exit_after {
                let on_timer = shutdown.clone();
                runtime.spawn(async move {
                    tokio::time::sleep(Duration::from_secs(secs)).await;
                    on_timer.cancel();
                });
            }
            runtime.block_on(run(dir.unwrap_or_else(default_dir), port, pipe, shutdown))
        }
    }
}
