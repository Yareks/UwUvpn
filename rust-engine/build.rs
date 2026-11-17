fn main() {
    println!("cargo:rerun-if-env-changed=XRAY_FFI_LIB_DIR");
    if let Ok(dir) = std::env::var("XRAY_FFI_LIB_DIR") {
        if !dir.is_empty() && std::path::Path::new(&dir).exists() {
            println!("cargo:rustc-link-search=native={dir}");
            return;
        }
    }
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if target_os == "linux" && target_arch == "x86_64" {
        let fallback = "../third_party/xray-host";
        if std::path::Path::new(fallback).exists() {
            println!("cargo:rustc-link-search=native={fallback}");
        }
    }
}
