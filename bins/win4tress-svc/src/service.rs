//! Service Control Manager integration and dev install/uninstall.

use std::ffi::{OsStr, OsString};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use tokio_util::sync::CancellationToken;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use crate::{logging, runtime};

pub const SERVICE_NAME: &str = "win4tress";
const DISPLAY_NAME: &str = "Win4tress network monitor";
const DESCRIPTION: &str =
    "Monitors which apps use the network and enforces win4tress firewall rules.";

define_windows_service!(ffi_service_main, service_main);

pub fn run_dispatcher() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("not started by the Service Control Manager (use `console` to run interactively)")
}

fn service_main(_arguments: Vec<OsString>) {
    let _guard = logging::init_service();
    if let Err(e) = run_service() {
        tracing::error!("service failed: {e:#}");
    }
}

fn run_service() -> Result<()> {
    let shutdown = CancellationToken::new();
    let on_stop = shutdown.clone();
    let status = service_control_handler::register(SERVICE_NAME, move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            on_stop.cancel();
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;

    let report = |state, accepted, exit_code| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accepted,
        exit_code,
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    };
    status.set_service_status(report(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        ServiceExitCode::Win32(0),
    ))?;

    let result = runtime::run(runtime::Options::service(), shutdown);
    let exit_code = match &result {
        Ok(()) => ServiceExitCode::Win32(0),
        // Non-zero so the SCM's recovery actions restart us.
        Err(_) => ServiceExitCode::ServiceSpecific(1),
    };
    status.set_service_status(report(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        exit_code,
    ))?;
    result
}

/// Registers this executable as an auto-start LocalSystem service, restarting on failure.
pub fn install() -> Result<()> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("opening the Service Control Manager (run elevated)")?;
    let info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe()?,
        launch_arguments: vec!["service".into()],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let service = manager
        .create_service(
            &info,
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS,
        )
        .context("creating the service (already installed? run `uninstall` first)")?;
    service.set_description(DESCRIPTION)?;
    let restart = ServiceAction {
        action_type: ServiceActionType::Restart,
        delay: Duration::from_secs(5),
    };
    service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 3600)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart.clone(), restart.clone(), restart]),
    })?;
    service
        .start(&[] as &[&OsStr])
        .context("starting the service")?;
    println!(
        "Installed and started '{SERVICE_NAME}' ({}).",
        info.executable_path.display()
    );
    Ok(())
}

pub fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("opening the Service Control Manager (run elevated)")?;
    let service = manager
        .open_service(
            SERVICE_NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        )
        .context("opening the service (is it installed?)")?;

    if service.query_status()?.current_state != ServiceState::Stopped {
        service.stop()?;
        let deadline = Instant::now() + Duration::from_secs(15);
        while service.query_status()?.current_state != ServiceState::Stopped {
            if Instant::now() > deadline {
                bail!("the service did not stop within 15 s");
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    service.delete()?;
    println!("Stopped and removed '{SERVICE_NAME}'.");
    cleanup()
}

/// Undoes what win4tress changed in Windows, with the service stopped: by
/// `uninstall`, and by the installer when it removes win4tress (never when
/// it upgrades it, which keeps rules and settings).
pub fn cleanup() -> Result<()> {
    // DNS filtering: Windows' own DNS again, whatever state the service left.
    match w4_sys::nrpt::remove() {
        Ok(true) => println!("Removed DNS filtering's routing rule: Windows' DNS is as before."),
        Ok(false) => {}
        Err(e) => eprintln!("Couldn't remove DNS filtering's routing rule: {e}"),
    }

    // Uninstalling leaves no win4tress rules in Windows Firewall (Phase 2 exit).
    // The stored rules stay in history, so reinstalling puts them back.
    let firewall = w4_enforce::ComFirewall::start(w4_enforce::GROUP)
        .context("opening Windows Firewall to remove win4tress rules")?;
    let removed = w4_enforce::remove_all(&firewall).context("removing win4tress rules")?;
    println!("Removed {removed} win4tress firewall rules.");
    // And puts back any profile settings win4tress changed (Ask to Connect).
    let db = crate::data::default_dir().join(w4_store::DB_NAME);
    if db.exists() {
        let mut store = w4_store::Store::open(&db).context("opening history")?;
        if let Some(saved) = store.profile_originals()? {
            for p in &saved {
                w4_enforce::EnforcementBackend::set_defaults(
                    &firewall,
                    &p.name,
                    p.inbound_default_block,
                    p.outbound_default_block,
                )
                .with_context(|| format!("restoring the {} profile", p.name))?;
            }
            store.clear_profile_originals(w4_core::time::now_unix_ms(), "win4tress uninstall")?;
            println!("Restored the original firewall profile settings.");
        }
    }
    Ok(())
}
