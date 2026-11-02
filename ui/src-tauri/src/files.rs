//! Windows' own Save and Open dialogs, for exporting and importing rules
//! (SPEC §7.2). The app runs as the signed-in user, so files go where they
//! choose, with their rights.

use std::ffi::c_void;

use windows::Win32::Foundation::{ERROR_CANCELLED, HWND};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoCreateInstance,
    CoInitializeEx, CoTaskMemFree, CoUninitialize,
};
use windows::Win32::UI::Shell::Common::COMDLG_FILTERSPEC;
use windows::Win32::UI::Shell::{
    FOS_FILEMUSTEXIST, FOS_FORCEFILESYSTEM, FOS_OVERWRITEPROMPT, FOS_PATHMUSTEXIST, FileOpenDialog,
    FileSaveDialog, IFileDialog, IFileOpenDialog, IFileSaveDialog, SIGDN_FILESYSPATH,
};
use windows::core::{HSTRING, Interface, w};

/// Rules files are a few hundred KB at most; anything far bigger isn't one.
const MAX_READ: u64 = 8 * 1024 * 1024;

/// Runs a dialog on a thread of its own, in a single-threaded apartment as
/// the shell's dialogs want. `owner` is the window it belongs to (its handle).
fn on_dialog_thread<T: Send + 'static>(
    owner: Option<isize>,
    f: impl FnOnce(HWND) -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    std::thread::spawn(move || {
        // SAFETY: COM for this thread only, ended before it returns.
        let init =
            unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) };
        let result = f(HWND(owner.unwrap_or(0) as *mut c_void));
        if init.is_ok() {
            // SAFETY: matched with the successful CoInitializeEx above.
            unsafe { CoUninitialize() };
        }
        result
    })
    .join()
    .map_err(|_| "the file dialog failed".to_string())?
}

const FILTERS: [COMDLG_FILTERSPEC; 2] = [
    COMDLG_FILTERSPEC {
        pszName: w!("win4tress rules (*.json)"),
        pszSpec: w!("*.json"),
    },
    COMDLG_FILTERSPEC {
        pszName: w!("All files (*.*)"),
        pszSpec: w!("*.*"),
    },
];

/// Shows the dialog; the chosen file's path, or `None` if cancelled.
fn show(dialog: &IFileDialog, owner: HWND) -> Result<Option<String>, String> {
    // SAFETY: COM calls on a live dialog; the path string is copied, then freed.
    unsafe {
        if let Err(e) = dialog.Show(Some(owner)) {
            if e.code() == ERROR_CANCELLED.to_hresult() {
                return Ok(None);
            }
            return Err(format!("the file dialog failed: {e}"));
        }
        let item = dialog.GetResult().map_err(|e| e.to_string())?;
        let path = item
            .GetDisplayName(SIGDN_FILESYSPATH)
            .map_err(|e| e.to_string())?;
        let text = path.to_string().map_err(|e| e.to_string());
        CoTaskMemFree(Some(path.0 as *const c_void));
        text.map(Some)
    }
}

/// Asks where to save `contents` (suggesting `name`), and saves it there.
/// Returns where, or `None` if the user cancelled.
pub fn save(
    owner: Option<isize>,
    name: String,
    contents: String,
) -> Result<Option<String>, String> {
    let path = on_dialog_thread(owner, move |owner| {
        // SAFETY: COM calls on a dialog created here.
        unsafe {
            let d: IFileSaveDialog = CoCreateInstance(&FileSaveDialog, None, CLSCTX_INPROC_SERVER)
                .map_err(|e| e.to_string())?;
            let options = d.GetOptions().map_err(|e| e.to_string())?;
            d.SetOptions(options | FOS_OVERWRITEPROMPT | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST)
                .map_err(|e| e.to_string())?;
            d.SetFileTypes(&FILTERS).map_err(|e| e.to_string())?;
            d.SetDefaultExtension(w!("json"))
                .map_err(|e| e.to_string())?;
            d.SetFileName(&HSTRING::from(name.as_str()))
                .map_err(|e| e.to_string())?;
            d.SetTitle(w!("Export win4tress rules"))
                .map_err(|e| e.to_string())?;
            show(&d.cast().map_err(|e| e.to_string())?, owner)
        }
    })?;
    let Some(path) = path else { return Ok(None) };
    std::fs::write(&path, contents).map_err(|e| format!("saving {path}: {e}"))?;
    Ok(Some(path))
}

/// Asks for a rules file and reads it; `None` if the user cancelled.
pub fn open(owner: Option<isize>) -> Result<Option<String>, String> {
    let path = on_dialog_thread(owner, |owner| {
        // SAFETY: COM calls on a dialog created here.
        unsafe {
            let d: IFileOpenDialog = CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER)
                .map_err(|e| e.to_string())?;
            let options = d.GetOptions().map_err(|e| e.to_string())?;
            d.SetOptions(options | FOS_FILEMUSTEXIST | FOS_FORCEFILESYSTEM)
                .map_err(|e| e.to_string())?;
            d.SetFileTypes(&FILTERS).map_err(|e| e.to_string())?;
            d.SetTitle(w!("Import win4tress rules"))
                .map_err(|e| e.to_string())?;
            show(&d.cast().map_err(|e| e.to_string())?, owner)
        }
    })?;
    let Some(path) = path else { return Ok(None) };
    let size = std::fs::metadata(&path)
        .map_err(|e| format!("reading {path}: {e}"))?
        .len();
    if size > MAX_READ {
        return Err(format!("{path} is too big to be a rules file"));
    }
    std::fs::read_to_string(&path)
        .map(Some)
        .map_err(|e| format!("reading {path}: {e}"))
}
