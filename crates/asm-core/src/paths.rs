//! Manager data directories. All are created with mode 0700.

use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
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
}

impl DataDirs {
    /// `values_root` defaults to `std::env::temp_dir()`; tests pass their own.
    pub fn create(data: &Path, values_root: Option<&Path>) -> std::io::Result<Self> {
        let values_root = values_root
            .map(Path::to_path_buf)
            .unwrap_or_else(std::env::temp_dir);
        let d = Self {
            data: data.to_path_buf(),
            tls: data.join("tls"),
            proxy: data.join("proxy"),
            bw: data.join("bw"),
            logs: data.join("logs"),
            values: values_root.join("net.thinkscape.asm").join("values"),
        };
        for p in [&d.data, &d.tls, &d.proxy, &d.bw, &d.logs, &d.values] {
            ensure_private_dir(p)?;
        }
        Ok(d)
    }

    pub fn db(&self) -> PathBuf {
        self.data.join("asm.db")
    }
    pub fn bw_vault(&self, vault_id: &str) -> PathBuf {
        self.bw.join(vault_id)
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
