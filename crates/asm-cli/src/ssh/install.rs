//! `asm ssh install` / `uninstall`: one `Include` of `asm-ssh-hosts.conf` at the top of
//! `~/.ssh/config`, so plain `ssh`, `scp`, `git` and Ansible use active leases by host name.

use super::ssh_dir;
use super::store::{HOSTS_CONF, prune};
use crate::error::CliError;
use crate::files::{ensure_private_dir, write_file_atomic};
use crate::state;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

const MARKER: &str = "# Added by asm ssh install; remove with asm ssh uninstall.";

/// `Include "<ssh dir>/asm-ssh-hosts.conf"`.
fn include_line(dir: &Path) -> Result<String, CliError> {
    let path = dir.join(HOSTS_CONF);
    match path.to_str() {
        Some(p) if !p.contains(|c: char| matches!(c, '"' | '%' | '*' | '?' | '[') || c.is_control()) => {
            Ok(format!("Include \"{p}\""))
        }
        _ => Err(CliError::invalid(format!(
            "{} cannot be used in an ssh Include line; set XDG_CONFIG_HOME to a simpler directory",
            path.display()
        ))),
    }
}

fn ssh_config_path() -> Result<PathBuf, CliError> {
    Ok(state::home_dir()?.join(".ssh/config"))
}

/// The file to edit: `path`, or what it resolves to when it is a symlink (the symlink
/// stays). A missing file is returned as is.
fn resolve(path: &Path) -> Result<PathBuf, CliError> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(path.to_owned()),
        Err(e) => return Err(CliError::failure(format!("inspecting {}: {e}", path.display()))),
    };
    let resolved = if meta.file_type().is_symlink() {
        match fs::canonicalize(path) {
            Ok(p) => p,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                return Err(CliError::invalid(format!("{} is a broken symlink", path.display())));
            }
            Err(e) => return Err(CliError::failure(format!("resolving {}: {e}", path.display()))),
        }
    } else {
        path.to_owned()
    };
    match fs::metadata(&resolved) {
        Ok(m) if m.is_file() => Ok(resolved),
        Ok(_) => Err(CliError::invalid(format!("{} is not a regular file", path.display()))),
        Err(e) => Err(CliError::failure(format!("inspecting {}: {e}", resolved.display()))),
    }
}

/// The content of `path`; `None` when it does not exist.
fn read(path: &Path) -> Result<Option<Vec<u8>>, CliError> {
    match fs::read(path) {
        Ok(d) => Ok(Some(d)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(CliError::failure(format!("reading {}: {e}", path.display()))),
    }
}

/// Each line of `data` without its line ending.
fn lines(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    data.split_inclusive(|&b| b == b'\n').map(strip_eol)
}

fn strip_eol(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn has_line(data: &[u8], line: &str) -> bool {
    lines(data).any(|l| l == line.as_bytes())
}

fn prefix(include: &str) -> String {
    format!("{MARKER}\n{include}\n\n")
}

/// `old` with the marker and include lines removed; `None` when neither is present.
fn without_include(old: &[u8], include: &str) -> Option<Vec<u8>> {
    if let Some(rest) = old.strip_prefix(prefix(include).as_bytes()) {
        return Some(rest.to_vec());
    }
    let ours = |l: &[u8]| l == MARKER.as_bytes() || l == include.as_bytes();
    if !lines(old).any(ours) {
        return None;
    }
    Some(
        old.split_inclusive(|&b| b == b'\n')
            .filter(|l| !ours(strip_eol(l)))
            .flatten()
            .copied()
            .collect(),
    )
}

/// Replace `path` with `data` through a temporary file in its directory, keeping its
/// mode (0600 for a new file).
fn replace(path: &Path, data: &[u8], mode: Option<u32>) -> Result<(), CliError> {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str())) else {
        return Err(CliError::failure(format!("cannot write {}", path.display())));
    };
    let written = write_file_atomic(dir, name, data)?;
    if let Some(mode) = mode.filter(|m| *m != 0o600) {
        fs::set_permissions(&written, fs::Permissions::from_mode(mode))
            .map_err(|e| CliError::failure(format!("setting permissions of {}: {e}", written.display())))?;
    }
    Ok(())
}

fn mode_of(path: &Path) -> Option<u32> {
    fs::metadata(path).ok().map(|m| m.permissions().mode() & 0o7777)
}

/// `asm ssh install`.
pub fn install() -> Result<(), CliError> {
    let dir = ssh_dir()?;
    let include = include_line(&dir)?;
    ensure_private_dir(&dir)?;
    prune(&dir)?;
    let config = ssh_config_path()?;
    if let Some(ssh) = config.parent() {
        match fs::DirBuilder::new().mode(0o700).create(ssh) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
            Err(e) => return Err(CliError::failure(format!("creating {}: {e}", ssh.display()))),
        }
    }
    let target = resolve(&config)?;
    let old = read(&target)?;
    if old.as_deref().is_some_and(|d| has_line(d, &include)) {
        println!("already installed: {}", config.display());
        return Ok(());
    }
    let mut data = prefix(&include).into_bytes();
    data.extend_from_slice(old.as_deref().unwrap_or_default());
    replace(&target, &data, mode_of(&target))?;
    println!(
        "installed: {} now includes {}",
        config.display(),
        dir.join(HOSTS_CONF).display()
    );
    Ok(())
}

/// `asm ssh uninstall`.
pub fn uninstall() -> Result<(), CliError> {
    let include = include_line(&ssh_dir()?)?;
    let config = ssh_config_path()?;
    let target = resolve(&config)?;
    let Some(data) = read(&target)?.and_then(|old| without_include(&old, &include)) else {
        println!("not installed");
        return Ok(());
    };
    replace(&target, &data, mode_of(&target))?;
    println!("uninstalled: {}", config.display());
    Ok(())
}

/// Whether `~/.ssh/config` includes `asm-ssh-hosts.conf`; errors count as no.
pub fn installed() -> bool {
    (|| {
        let include = include_line(&ssh_dir()?)?;
        let target = resolve(&ssh_config_path()?)?;
        Ok::<_, CliError>(read(&target)?.is_some_and(|d| has_line(&d, &include)))
    })()
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    const INCLUDE: &str = "Include \"/h/.config/asm/ssh/asm-ssh-hosts.conf\"";

    #[test]
    fn include_line_refuses_pattern_characters() {
        assert_eq!(
            include_line(Path::new("/h/.config/asm/ssh")).unwrap(),
            INCLUDE
        );
        for bad in ["/a\"b", "/a%b", "/a*b", "/a?b", "/a[b", "/a\nb"] {
            let e = include_line(Path::new(bad)).unwrap_err();
            assert!(e.message.contains("cannot be used in an ssh Include line"), "{bad:?}");
        }
    }

    #[test]
    fn uninstall_drops_the_prefix_or_the_lines() {
        let original = b"Host other\n  User x\n";
        let mut installed = prefix(INCLUDE).into_bytes();
        installed.extend_from_slice(original);
        assert!(has_line(&installed, INCLUDE));
        assert_eq!(without_include(&installed, INCLUDE).unwrap(), original);

        // Moved by hand: only the two lines go.
        let moved = format!("Host other\n{MARKER}\r\n  User x\n{INCLUDE}\n");
        assert_eq!(without_include(moved.as_bytes(), INCLUDE).unwrap(), b"Host other\n  User x\n");
        assert_eq!(without_include(original, INCLUDE), None);
    }
}
