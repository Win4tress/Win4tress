//! "Require elevation" (SPEC §4.3): a change the service refused for want of
//! elevation runs again through the command-line client, elevated with a UAC
//! prompt. The request goes on the command line rather than in a file, so a
//! process running as the user can't swap what gets elevated.

use std::path::PathBuf;
use std::time::Duration;

use base64::Engine as _;
use serde_json::Value;
use windows::Win32::Foundation::{CloseHandle, ERROR_CANCELLED, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
use windows::Win32::UI::Shell::{
    SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;
use windows::core::{HSTRING, PCWSTR, w};

/// How long the user has to answer the UAC prompt and the change to run.
const WAIT: Duration = Duration::from_secs(120);

/// The command-line client, installed next to the app.
fn cli() -> Result<PathBuf, String> {
    let dir = std::env::current_exe()
        .map_err(|e| e.to_string())?
        .parent()
        .map(PathBuf::from)
        .ok_or("no folder for the app")?;
    let cli = dir.join("win4tress.exe");
    if cli.exists() {
        Ok(cli)
    } else {
        Err(format!("{} is missing", cli.display()))
    }
}

/// Calls `method` on the service from an elevated helper. Blocking: it waits
/// for the UAC prompt and the call.
pub fn call(pipe: &str, method: &str, params: &Value) -> Result<Value, String> {
    let cli = cli()?;
    let encoded = base64::engine::general_purpose::STANDARD
        .encode(serde_json::to_vec(params).map_err(|e| e.to_string())?);
    let result = std::env::temp_dir().join(format!(
        "win4tress-elevated-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    let args = format!(
        "--pipe \"{pipe}\" rpc {method} --params {encoded} --result \"{}\"",
        result.display()
    );
    let file = HSTRING::from(cli.as_os_str());
    let params_w = HSTRING::from(args);
    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
        lpVerb: w!("runas"),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(params_w.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    // SAFETY: `info` and the strings it points to outlive the call; the process
    // handle it returns is closed below.
    unsafe {
        if let Err(e) = ShellExecuteExW(&mut info) {
            return Err(if e.code() == ERROR_CANCELLED.to_hresult() {
                "cancelled: the change needs an administrator's approval".into()
            } else {
                format!("couldn't start the elevated helper: {e}")
            });
        }
        let process = info.hProcess;
        let waited = WaitForSingleObject(process, WAIT.as_millis() as u32);
        let mut code = 1u32;
        let _ = GetExitCodeProcess(process, &mut code);
        let _ = CloseHandle(process);
        if waited != WAIT_OBJECT_0 {
            return Err("the elevated helper didn't finish".into());
        }
    }
    let text =
        std::fs::read(&result).map_err(|_| "the elevated helper gave no answer".to_string())?;
    let _ = std::fs::remove_file(&result);
    let answer: Value = serde_json::from_slice(&text).map_err(|e| e.to_string())?;
    match (answer.get("result"), answer.get("error")) {
        (Some(v), _) => Ok(v.clone()),
        (None, Some(e)) => Err(e.as_str().unwrap_or("failed").to_string()),
        _ => Err("the elevated helper's answer was unreadable".into()),
    }
}
