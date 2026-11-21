use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn find_windows_sdk_rc() -> Option<PathBuf> {
    if Command::new("rc.exe").arg("/?").output().is_ok() {
        return Some(PathBuf::from("rc.exe"));
    }
    let bases = [
        r"C:\Program Files (x86)\Windows Kits\10\bin",
        r"C:\Program Files\Windows Kits\10\bin",
    ];
    for base in bases {
        let base_path = Path::new(base);
        let Ok(entries) = fs::read_dir(base_path) else {
            continue;
        };
        let mut versions: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        versions.sort();
        for dir in versions.into_iter().rev() {
            let candidate = dir.join("x64").join("rc.exe");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        let direct = base_path.join("x64").join("rc.exe");
        if direct.is_file() {
            return Some(direct);
        }
    }
    None
}

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
        println!("cargo:warning=assets/icon.ico not found; skipping Windows icon embedding");
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
    let in_ci = env::var("CI").is_ok();

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
        match status {
            Ok(st) if st.success() => {
                println!("cargo:rustc-link-arg={}", res_obj.display());
            }
            _ => {
                println!("cargo:warning=windres failed to compile Windows icon resource");
                if in_ci {
                    panic!("windres failed in CI");
                }
            }
        }
    } else if target_env == "msvc" {
        let res_file = out_dir.join("app_icon.res");
        let Some(rc_exe) = find_windows_sdk_rc() else {
            println!("cargo:warning=Windows SDK rc.exe not found; icon not embedded");
            if in_ci {
                panic!("Windows SDK rc.exe not found in CI");
            }
            return;
        };
        let status = Command::new(&rc_exe)
            .args([
                "/nologo",
                "/fo",
                res_file.to_str().unwrap(),
                rc_path.to_str().unwrap(),
            ])
            .status();
        match status {
            Ok(st) if st.success() => {
                println!("cargo:rustc-link-arg={}", res_file.display());
            }
            _ => {
                println!("cargo:warning=rc.exe failed to compile Windows icon resource");
                if in_ci {
                    panic!("rc.exe failed in CI");
                }
            }
        }
    }
}
