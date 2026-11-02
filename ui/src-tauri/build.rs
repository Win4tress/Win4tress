fn main() {
    // The exe's icon (tools/dev/make-logo.py): tauri-build doesn't watch it,
    // so a new one would otherwise only reach the exe after a clean build.
    println!("cargo:rerun-if-changed=icons/icon.ico");
    tauri_build::build()
}
