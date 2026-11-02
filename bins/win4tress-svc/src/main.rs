//! win4tress background service (SPEC §4.1).
//!
//! `win4tress-svc console` runs in the foreground for development (elevated
//! terminal). `install` / `uninstall` register it with the Service Control
//! Manager; the SCM then starts it with `service`.

mod autoprofile;
mod cleanup;
mod data;
mod dnsfilter;
mod enforcer;
mod handler;
mod logging;
mod prompts;
mod reputation;
mod resolver;
mod runtime;
mod security;
mod service;
mod usage;

use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(version, about = "win4tress background service")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run in this terminal until Ctrl+C (needs an elevated terminal)
    Console {
        /// Pipe name, so a console instance can run beside the installed service
        #[arg(long, default_value = w4_ipc::PIPE_NAME)]
        pipe: String,
        /// Shut down cleanly after this many seconds (for scripted tests)
        #[arg(long)]
        exit_after: Option<u64>,
        /// Folder for the history database (default: %ProgramData%\win4tress)
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Also write raw ETW events to this .etl file (tools/dev/record-trace.ps1)
        #[arg(long, hide = true)]
        record: Option<PathBuf>,
        /// Seconds after the first run before first-network-activity alerts start
        /// (default an hour; 0 to test them)
        #[arg(long, hide = true)]
        learning_secs: Option<i64>,
    },
    /// Register and start the Windows service (elevated)
    Install,
    /// Stop and remove the Windows service (elevated)
    Uninstall,
    /// Undo what win4tress changed in Windows (DNS routing, firewall rules and
    /// profile settings), with the service already stopped: the installer's
    /// uninstall step (elevated)
    #[command(hide = true)]
    Cleanup,
    /// Entry point used by the Service Control Manager
    #[command(hide = true)]
    Service,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Console {
            pipe,
            exit_after,
            data_dir,
            record,
            learning_secs,
        } => {
            let _guard = logging::init_console();
            if !w4_sys::process::is_elevated() {
                bail!("run from an elevated terminal: ETW network tracing needs admin rights");
            }
            let shutdown = CancellationToken::new();
            let on_stop = shutdown.clone();
            stop_handler(move || on_stop.cancel());
            if let Some(secs) = exit_after {
                let on_timer = shutdown.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_secs(secs));
                    on_timer.cancel();
                });
            }
            let mut options = runtime::Options::console(pipe, data_dir);
            options.record_to = record;
            if let Some(secs) = learning_secs {
                options.learning_ms = secs.max(0) * 1000;
            }
            runtime::run(options, shutdown)
        }
        Command::Install => service::install(),
        Command::Uninstall => service::uninstall(),
        Command::Cleanup => service::cleanup(),
        Command::Service => service::run_dispatcher(),
    }
}

/// Stops on Ctrl+C or Ctrl+Break, and when the console window is closed, the
/// user logs off or Windows shuts down. Those three allow only a few seconds
/// before Windows ends the process, so Windows' own DNS goes back first: DNS
/// filtering's routing rule left behind would send lookups to a resolver
/// that's gone.
fn stop_handler(on_stop: impl Fn() + Send + 'static) {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("signal runtime");
        rt.block_on(async {
            use tokio::signal::windows::{ctrl_close, ctrl_logoff, ctrl_shutdown};
            let (Ok(mut close), Ok(mut logoff), Ok(mut shutdown)) =
                (ctrl_close(), ctrl_logoff(), ctrl_shutdown())
            else {
                if tokio::signal::ctrl_c().await.is_ok() {
                    on_stop();
                }
                return;
            };
            let urgent = tokio::select! {
                r = tokio::signal::ctrl_c() => {
                    if r.is_err() {
                        return;
                    }
                    false
                }
                _ = close.recv() => true,
                _ = logoff.recv() => true,
                _ = shutdown.recv() => true,
            };
            if urgent {
                let _ = w4_sys::nrpt::remove();
            }
            on_stop();
        });
    });
}
