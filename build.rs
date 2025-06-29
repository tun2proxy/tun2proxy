fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Ok(git_hash) = get_git_hash() {
        // Set the environment variables
        println!("cargo:rustc-env=GIT_HASH={}", git_hash.trim());
    }

    // Get the build time
    let build_time = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    println!("cargo:rustc-env=BUILD_TIME={build_time}");

    #[cfg(target_os = "windows")]
    if let Ok(cargo_target_dir) = get_cargo_target_dir() {
        let mut f = std::fs::File::create(cargo_target_dir.join("build.log"))?;
        use std::io::Write;
        f.write_all(format!("CARGO_TARGET_DIR: '{}'\r\n", cargo_target_dir.display()).as_bytes())?;

        // The wintun-bindings crate's root directory
        let crate_dir = get_crate_dir("wintun-bindings")?;

        // The path to the DLL file, relative to the crate root, depending on the target architecture
        let dll_path = get_wintun_bin_relative_path()?;
        let src_path = crate_dir.join(dll_path);

        let dst_path = cargo_target_dir.join("wintun.dll");

        f.write_all(format!("Source path: '{}'\r\n", src_path.display()).as_bytes())?;
        f.write_all(format!("Target path: '{}'\r\n", dst_path.display()).as_bytes())?;

        // Copy to the target directory
        if let Err(e) = std::fs::copy(src_path, &dst_path) {
            f.write_all(format!("Failed to copy 'wintun.dll': {e}\r\n").as_bytes())?;
        } else {
            f.write_all(format!("Copied 'wintun.dll' to '{}'\r\n", dst_path.display()).as_bytes())?;

            // Set the modified time to the current time, or the publishing process will fail.
            let file = std::fs::OpenOptions::new().write(true).open(&dst_path)?;
            file.set_modified(std::time::SystemTime::now())?;
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn get_cargo_target_dir() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
    let profile = std::env::var("PROFILE")?;
    let mut target_dir = None;
    let mut sub_path = out_dir.as_path();
    while let Some(parent) = sub_path.parent() {
        if parent.ends_with(&profile) {
            target_dir = Some(parent);
            break;
        }
        sub_path = parent;
    }
    Ok(target_dir.ok_or("not found")?.to_path_buf())
}

#[allow(dead_code)]
fn get_wintun_bin_relative_path() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH")?;

    let dll_path = match target_arch.as_str() {
        "x86" => "wintun/bin/x86/wintun.dll",
        "x86_64" => "wintun/bin/amd64/wintun.dll",
        "arm" => "wintun/bin/arm/wintun.dll",
        "aarch64" => "wintun/bin/arm64/wintun.dll",
        _ => return Err("Unsupported architecture".into()),
    };

    Ok(dll_path.into())
}

#[allow(dead_code)]
fn get_crate_dir(crate_name: &str) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let output = std::process::Command::new("cargo")
        .arg("metadata")
        .arg("--format-version=1")
        .output()?;

    let metadata = serde_json::from_slice::<serde_json::Value>(&output.stdout)?;
    let packages = metadata["packages"].as_array().ok_or("packages")?;

    let mut crate_dir = None;

    for package in packages {
        let name = package["name"].as_str().ok_or("name")?;
        if name == crate_name {
            let path = package["manifest_path"].as_str().ok_or("manifest_path")?;
            let path = std::path::PathBuf::from(path);
            crate_dir = Some(path.parent().ok_or("parent")?.to_path_buf());
            break;
        }
    }
    Ok(crate_dir.ok_or("crate_dir")?)
}

fn get_git_hash() -> std::io::Result<String> {
    use std::process::Command;
    let git_hash = Command::new("git").args(["rev-parse", "--short", "HEAD"]).output()?.stdout;
    let git_hash = String::from_utf8(git_hash).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(git_hash)
}
