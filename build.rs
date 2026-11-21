use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=assets/icon.ico");
    println!("cargo:rerun-if-changed=assets/icon-128.png");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "windows" {
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let icon_path = manifest_dir.join("assets").join("icon.ico");
    if !icon_path.is_file() {
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let rc_path = out_dir.join("app_icon.rc");
    let icon_escaped = icon_path.to_string_lossy().replace('\\', "/");
    let rc_content = format!("1 ICON \"{icon_escaped}\"\n");
    if fs::write(&rc_path, rc_content).is_err() {
        return;
    }

    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_env == "gnu" {
        let res_obj = out_dir.join("app_icon.o");
        let status = Command::new("windres")
            .args([
                rc_path.to_str().unwrap(),
                "-O",
                "coff",
                "-o",
                res_obj.to_str().unwrap(),
            ])
            .status();
        if let Ok(st) = status {
            if st.success() {
                println!("cargo:rustc-link-arg={}", res_obj.display());
            }
        }
    } else if target_env == "msvc" {
        let res_file = out_dir.join("app_icon.res");
        let status = Command::new("rc.exe")
            .args([
                "/nologo",
                "/fo",
                res_file.to_str().unwrap(),
                rc_path.to_str().unwrap(),
            ])
            .status();
        if let Ok(st) = status {
            if st.success() {
                println!("cargo:rustc-link-arg={}", res_file.display());
            }
        }
    }
}
