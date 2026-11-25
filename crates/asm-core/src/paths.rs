//! Manager data directories. All are created with mode 0700.

use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct DataDirs {
    /// `~/Library/Application Support/asm/` (or a test temp dir)
    pub data: PathBuf,
    pub tls: PathBuf,
    pub proxy: PathBuf,
    pub bw: PathBuf,
    pub logs: PathBuf,
    /// `<temp_dir>/net.thinkscape.asm/values/` — proxy value files (outside Time Machine).
    pub values: PathBuf,
    /// `<temp_dir>/net.thinkscape.asm/gcloud/` — isolated SDK workspaces.
    pub gcloud: PathBuf,
    /// `<data>/ssh/` — pinned SSH target host keys.
    pub ssh: PathBuf,
    /// `<temp_dir>/net.thinkscape.asm/ssh/` — keys and configs of certificate runs.
    pub ssh_run: PathBuf,
}

impl DataDirs {
    /// `values_root` defaults to `std::env::temp_dir()`; tests pass their own.
    pub fn create(data: &Path, values_root: Option<&Path>) -> std::io::Result<Self> {
        let values_root = values_root
            .map(Path::to_path_buf)
            .unwrap_or_else(std::env::temp_dir);
        let runtime = values_root.join("net.thinkscape.asm");
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&values_root)?;
        ensure_private_runtime_dir(&runtime)?;
        let d = Self {
            data: data.to_path_buf(),
            tls: data.join("tls"),
            proxy: data.join("proxy"),
            bw: data.join("bw"),
            logs: data.join("logs"),
            values: runtime.join("values"),
            gcloud: runtime.join("gcloud"),
            ssh: data.join("ssh"),
            ssh_run: runtime.join("ssh"),
        };
        for p in [&d.data, &d.tls, &d.proxy, &d.bw, &d.logs, &d.values, &d.ssh] {
            ensure_private_dir(p)?;
        }
        ensure_private_runtime_dir(&d.gcloud)?;
        ensure_private_runtime_dir(&d.ssh_run)?;
        Ok(d)
    }

    pub fn db(&self) -> PathBuf {
        self.data.join("asm.db")
    }
    pub fn bw_vault(&self, vault_id: &str) -> PathBuf {
        self.bw.join(vault_id)
    }
    /// Known-hosts file the manager's own ssh uses for SSH targets.
    pub fn ssh_known_hosts(&self) -> PathBuf {
        self.ssh.join("known_hosts")
    }
}

/// Create `p` (and parents) and force mode 0700 on it.
pub fn ensure_private_dir(p: &Path) -> std::io::Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(p)?;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))
}

/// Do not follow links or chmod existing entries in the transient credential tree.
fn ensure_private_runtime_dir(path: &Path) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};

    match std::fs::DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let dir = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = dir.metadata()?;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o777 != 0o700 {
        return Err(Error::new(ErrorKind::PermissionDenied, "unsafe ASM runtime directory"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn google_workspaces_are_private_and_outside_data() {
        let scratch = tempfile::tempdir().unwrap();
        let data = scratch.path().join("data");
        let runtime = scratch.path().join("temporary");
        let dirs = DataDirs::create(&data, Some(&runtime)).unwrap();
        assert_eq!(dirs.gcloud.parent(), dirs.values.parent());
        assert!(!dirs.gcloud.starts_with(data));
        assert_eq!(dirs.gcloud.metadata().unwrap().mode() & 0o777, 0o700);
    }

    #[test]
    fn google_workspace_root_does_not_follow_symlinks() {
        let scratch = tempfile::tempdir().unwrap();
        let data = scratch.path().join("data");
        let runtime = scratch.path().join("temporary");
        let dirs = DataDirs::create(&data, Some(&runtime)).unwrap();
        std::fs::remove_dir(&dirs.gcloud).unwrap();
        symlink(&dirs.values, &dirs.gcloud).unwrap();
        assert!(DataDirs::create(&data, Some(&runtime)).is_err());
        assert!(dirs.gcloud.symlink_metadata().unwrap().is_symlink());
        assert!(dirs.values.is_dir());
    }
}
