//! Logs go to stderr in console mode and to daily files under
//! `%ProgramData%\win4tress\logs` when running as a service.

use std::path::PathBuf;

use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;

const DEFAULT_FILTER: &str = "info";

fn filter() -> EnvFilter {
    EnvFilter::try_from_env("WIN4TRESS_LOG").unwrap_or_else(|_| EnvFilter::new(DEFAULT_FILTER))
}

pub fn init_console() -> Option<WorkerGuard> {
    use std::io::IsTerminal;
    tracing_subscriber::fmt()
        .with_env_filter(filter())
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .init();
    None
}

pub fn init_service() -> Option<WorkerGuard> {
    // The data folder is created (and locked down) first, so logs inherit its access list.
    if crate::data::ensure_dir(&crate::data::default_dir()).is_err() {
        return None;
    }
    let dir = log_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return None;
    }
    let (writer, guard) =
        tracing_appender::non_blocking(tracing_appender::rolling::daily(&dir, "win4tress-svc.log"));
    tracing_subscriber::fmt()
        .with_env_filter(filter())
        .with_writer(writer)
        .with_ansi(false)
        .init();
    Some(guard)
}

pub fn log_dir() -> PathBuf {
    crate::data::default_dir().join("logs")
}
