//! The `asm proxy-router` service: a systemd user unit (Linux) or a LaunchAgent
//! (macOS). Used by `asm browser install`/`uninstall`.

use crate::error::CliError;
use crate::state;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// systemd user unit name.
pub(crate) const SYSTEMD_UNIT: &str = "asm-proxy-router.service";
/// launchd label.
pub(crate) const LAUNCHD_LABEL: &str = "com.thinkscape.asm.proxy-router";
/// How long `install_service` waits for the router's `/status`.
const HEALTH_WAIT: Duration = Duration::from_secs(5);

/// The unit file (`~/.config/systemd/user/asm-proxy-router.service`) or LaunchAgent
/// plist (`~/Library/LaunchAgents/com.thinkscape.asm.proxy-router.plist`).
pub(crate) fn service_file() -> Result<PathBuf, CliError> {
    let home = state::home_dir()?;
    Ok(if cfg!(target_os = "macos") {
        home.join("Library/LaunchAgents").join(format!("{LAUNCHD_LABEL}.plist"))
    } else {
        home.join(".config/systemd/user").join(SYSTEMD_UNIT)
    })
}

/// Whether the router service is installed (its unit file or plist exists).
pub(crate) fn service_installed() -> Result<bool, CliError> {
    Ok(service_file()?.exists())
}

/// macOS: where the LaunchAgent sends the router's stdout and stderr.
pub(crate) fn log_file() -> Result<PathBuf, CliError> {
    Ok(state::home_dir()?.join("Library/Logs/asm-proxy-router.log"))
}

/// Install and start the router service on `port`, then wait up to 5 s for its
/// `/status`. An error means the router is not known to be running.
pub(crate) fn install_service(port: u16) -> Result<(), CliError> {
    let exe = router_exe()?;
    let xdg = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string_lossy().into_owned());
    if cfg!(target_os = "macos") {
        install_launchd(&exe, port, xdg.as_deref())?;
    } else if cfg!(target_os = "linux") {
        install_systemd(&exe, port, xdg.as_deref())?;
    } else {
        return Err(CliError::failure("the proxy router service needs Linux (systemd) or macOS"));
    }
    wait_healthy(port)
}

/// Stop and remove the router service (nothing to do when it is not installed).
pub(crate) fn remove_service() -> Result<(), CliError> {
    let file = service_file()?;
    if cfg!(target_os = "macos") {
        let _ = Command::new("launchctl").arg("bootout").arg(launchd_target()).output();
        remove_file(&file)
    } else {
        if file.exists() {
            run(Command::new("systemctl").args(["--user", "disable", "--now", SYSTEMD_UNIT]))?;
        }
        remove_file(&file)?;
        run(Command::new("systemctl").args(["--user", "daemon-reload"]))
    }
}

fn remove_file(path: &Path) -> Result<(), CliError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(CliError::failure(format!("removing {}: {e}", path.display()))),
    }
}

/// The first `asm` on `PATH` that is this executable (a stable path across upgrades),
/// else this executable's path.
fn router_exe() -> Result<PathBuf, CliError> {
    let current = std::env::current_exe()
        .map_err(|e| CliError::failure(format!("locating the asm executable: {e}")))?;
    let canonical = std::fs::canonicalize(&current).unwrap_or_else(|_| current.clone());
    let on_path = std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join("asm"))
            .find(|p| std::fs::canonicalize(p).is_ok_and(|c| c == canonical))
    });
    Ok(on_path.unwrap_or(current))
}

/// Run a command; fail with its stderr when it exits non-zero.
fn run(cmd: &mut Command) -> Result<(), CliError> {
    let shown = format!("{cmd:?}").replace('"', "");
    let out = cmd
        .output()
        .map_err(|e| CliError::failure(format!("running {shown}: {e}")))?;
    if out.status.success() {
        return Ok(());
    }
    Err(CliError::failure(format!(
        "{shown} failed: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    )))
}

/// Write `data` to `path` atomically with mode 0644, creating the parent directory.
fn write_public(path: &Path, data: &str) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt;
    let dir = path.parent().expect("service files have a parent directory");
    std::fs::create_dir_all(dir)
        .map_err(|e| CliError::failure(format!("creating {}: {e}", dir.display())))?;
    let name = path.file_name().expect("service files have a name").to_string_lossy();
    let written = crate::files::write_file_atomic(dir, &name, data.as_bytes())?;
    std::fs::set_permissions(&written, std::fs::Permissions::from_mode(0o644))
        .map_err(|e| CliError::failure(format!("setting permissions of {}: {e}", written.display())))
}

/// A systemd unit-file word: double-quoted, with `\`, `"` and `%` escaped.
fn systemd_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', r"\\").replace('"', "\\\"").replace('%', "%%"))
}

fn systemd_unit(exe: &Path, port: u16, xdg_config_home: Option<&str>) -> String {
    let env = xdg_config_home
        .map(|x| format!("Environment={}\n", systemd_quote(&format!("XDG_CONFIG_HOME={x}"))))
        .unwrap_or_default();
    format!(
        "[Service]\nExecStart={} proxy-router run --port {port}\n{env}Restart=on-failure\nRestartSec=2\n\n[Install]\nWantedBy=default.target\n",
        systemd_quote(&exe.to_string_lossy())
    )
}

fn install_systemd(exe: &Path, port: u16, xdg: Option<&str>) -> Result<(), CliError> {
    let session = Command::new("systemctl")
        .args(["--user", "show-environment"])
        .output()
        .is_ok_and(|o| o.status.success());
    if !session {
        return Err(CliError::failure(
            "no systemd user session; run \"asm proxy-router run\" under your process supervisor, then re-run with --no-service",
        ));
    }
    let file = service_file()?;
    let unit = systemd_unit(exe, port, xdg);
    let changed = std::fs::read_to_string(&file).is_ok_and(|old| old != unit);
    write_public(&file, &unit)?;
    run(Command::new("systemctl").args(["--user", "daemon-reload"]))?;
    run(Command::new("systemctl").args(["--user", "enable", "--now", SYSTEMD_UNIT]))?;
    if changed {
        // `enable --now` leaves an already running router on its old settings.
        run(Command::new("systemctl").args(["--user", "restart", SYSTEMD_UNIT]))?;
    }
    Ok(())
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn launchd_plist(exe: &Path, port: u16, xdg_config_home: Option<&str>, log: &Path) -> String {
    let string = |s: &str| format!("<string>{}</string>", xml_escape(s));
    let args = [&*exe.to_string_lossy(), "proxy-router", "run", "--port", &port.to_string()]
        .iter()
        .map(|a| format!("\t\t{}\n", string(a)))
        .collect::<String>();
    let env = xdg_config_home
        .map(|x| {
            format!(
                "\t<key>EnvironmentVariables</key>\n\t<dict>\n\t\t<key>XDG_CONFIG_HOME</key>\n\t\t{}\n\t</dict>\n",
                string(x)
            )
        })
        .unwrap_or_default();
    let log = string(&log.to_string_lossy());
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n<dict>\n\
\t<key>Label</key>\n\t{}\n\
\t<key>ProgramArguments</key>\n\t<array>\n{args}\t</array>\n\
{env}\
\t<key>RunAtLoad</key>\n\t<true/>\n\
\t<key>KeepAlive</key>\n\t<true/>\n\
\t<key>StandardOutPath</key>\n\t{log}\n\
\t<key>StandardErrorPath</key>\n\t{log}\n\
</dict>\n</plist>\n",
        string(LAUNCHD_LABEL)
    )
}

/// `gui/<uid>`.
fn launchd_domain() -> String {
    // SAFETY: getuid has no preconditions.
    format!("gui/{}", unsafe { libc::getuid() })
}

/// `gui/<uid>/com.thinkscape.asm.proxy-router`.
fn launchd_target() -> String {
    format!("{}/{LAUNCHD_LABEL}", launchd_domain())
}

fn install_launchd(exe: &Path, port: u16, xdg: Option<&str>) -> Result<(), CliError> {
    let file = service_file()?;
    let log = log_file()?;
    if let Some(dir) = log.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| CliError::failure(format!("creating {}: {e}", dir.display())))?;
    }
    write_public(&file, &launchd_plist(exe, port, xdg, &log))?;
    let _ = Command::new("launchctl").arg("bootout").arg(launchd_target()).output();
    // bootout finishes asynchronously; bootstrap fails until the old job is gone.
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match run(Command::new("launchctl").arg("bootstrap").arg(launchd_domain()).arg(&file)) {
            Ok(()) => return Ok(()),
            Err(e) if Instant::now() >= deadline => return Err(e),
            Err(_) => std::thread::sleep(Duration::from_millis(300)),
        }
    }
}

/// Wait up to [`HEALTH_WAIT`] for a router answering `/status` on `port`.
fn wait_healthy(port: u16) -> Result<(), CliError> {
    let deadline = Instant::now() + HEALTH_WAIT;
    loop {
        if let Ok(Some(st)) = crate::router::status()
            && st.port == port
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            let logs = if cfg!(target_os = "macos") {
                log_file()?.display().to_string()
            } else {
                "journalctl --user -u asm-proxy-router".to_owned()
            };
            return Err(CliError::failure(format!(
                "the proxy router did not answer within 5 s on port {port} (logs: {logs})"
            )));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn systemd_unit_contents() {
        assert_eq!(
            systemd_unit(Path::new("/home/u/.local/bin/asm"), 7418, None),
            "[Service]\nExecStart=\"/home/u/.local/bin/asm\" proxy-router run --port 7418\nRestart=on-failure\nRestartSec=2\n\n[Install]\nWantedBy=default.target\n"
        );
        let unit = systemd_unit(Path::new("/opt/my asm/asm"), 7500, Some("/home/u/cfg 100%"));
        assert!(unit.contains("ExecStart=\"/opt/my asm/asm\" proxy-router run --port 7500\n"), "{unit}");
        assert!(unit.contains("Environment=\"XDG_CONFIG_HOME=/home/u/cfg 100%%\"\n"), "{unit}");
    }

    #[test]
    fn launchd_plist_contents() {
        let plist = launchd_plist(
            Path::new("/usr/local/bin/asm"),
            7418,
            Some("/Users/u/a&b"),
            Path::new("/Users/u/Library/Logs/asm-proxy-router.log"),
        );
        assert!(plist.contains("<key>Label</key>\n\t<string>com.thinkscape.asm.proxy-router</string>"));
        assert!(plist.contains("\t\t<string>/usr/local/bin/asm</string>\n\t\t<string>proxy-router</string>\n\t\t<string>run</string>\n\t\t<string>--port</string>\n\t\t<string>7418</string>\n"));
        assert!(plist.contains("<key>XDG_CONFIG_HOME</key>\n\t\t<string>/Users/u/a&amp;b</string>"));
        assert!(plist.contains("<key>RunAtLoad</key>\n\t<true/>"));
        assert!(plist.contains("<key>KeepAlive</key>\n\t<true/>"));
        assert_eq!(plist.matches("<string>/Users/u/Library/Logs/asm-proxy-router.log</string>").count(), 2);
    }
}
