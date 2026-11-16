//! Private file writes, value files and the ended-sentinel store.

use std::collections::{HashSet, VecDeque};
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use asm_proto::crypto::{hex_encode, random_bytes};
use asm_proto::rules::sanitize_segment;
use serde::{Deserialize, Serialize};

/// Write `data` to `dir/name` with mode 0600 via a fresh temp file and rename.
pub fn write_private_atomic(dir: &Path, name: &str, data: &[u8]) -> io::Result<PathBuf> {
    let target = dir.join(name);
    let tmp = dir.join(format!(".{name}.tmp-{}", hex_encode(&random_bytes::<6>())));
    let res = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        std::fs::rename(&tmp, &target)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res.map(|()| target)
}

/// `<lease_id>.<n>`, with the lease id sanitised as a path segment.
pub fn value_file_name(lease_id: &str, index: usize) -> String {
    format!("{}.{index}", sanitize_segment(lease_id))
}

/// Delete every non-directory entry of `dir` whose name is not in `keep`.
pub fn prune_dir(dir: &Path, keep: &HashSet<String>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if keep.contains(&name) || e.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        let _ = std::fs::remove_file(e.path());
    }
}

/// Most recently ended sentinels kept as blocked entries.
pub const MAX_ENDED: usize = 1000;

/// Sentinels that were applied and have since ended. They stay in the proxy config as
/// never-matching entries so a request carrying one gets the patched proxy's 403 instead
/// of reaching the destination. Persisted so the block survives manager restarts (also
/// covering leases left out at start because their vault is unavailable).
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SentinelStore {
    active: Vec<String>,
    /// Oldest first.
    ended: VecDeque<String>,
}

impl SentinelStore {
    pub fn path(proxy_dir: &Path) -> PathBuf {
        proxy_dir.join("sentinels.json")
    }

    pub fn load(proxy_dir: &Path) -> Self {
        std::fs::read(Self::path(proxy_dir))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, proxy_dir: &Path) -> io::Result<()> {
        let data = serde_json::to_vec(self).map_err(io::Error::other)?;
        write_private_atomic(proxy_dir, "sentinels.json", &data).map(|_| ())
    }

    /// Record the new active set; previously active sentinels not in it become ended.
    pub fn update(&mut self, active: &[&str]) {
        let now: HashSet<&str> = active.iter().copied().collect();
        let gone: Vec<String> = self
            .active
            .iter()
            .filter(|s| !now.contains(s.as_str()))
            .cloned()
            .collect();
        self.ended
            .retain(|s| !now.contains(s.as_str()) && !gone.contains(s));
        self.ended.extend(gone);
        while self.ended.len() > MAX_ENDED {
            self.ended.pop_front();
        }
        let mut seen = HashSet::new();
        self.active = active
            .iter()
            .filter(|s| seen.insert(**s))
            .map(|s| s.to_string())
            .collect();
    }

    pub fn ended(&self) -> Vec<String> {
        self.ended.iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn atomic_write_is_private_and_replaces() {
        let d = tempfile::tempdir().unwrap();
        let p = write_private_atomic(d.path(), "a.0", b"one").unwrap();
        write_private_atomic(d.path(), "a.0", b"two").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 1);
    }

    #[test]
    fn prune_keeps_listed_files_only() {
        let d = tempfile::tempdir().unwrap();
        for n in ["keep.0", "old.0", ".x.tmp-1"] {
            std::fs::write(d.path().join(n), "v").unwrap();
        }
        std::fs::create_dir(d.path().join("sub")).unwrap();
        prune_dir(d.path(), &HashSet::from(["keep.0".to_string()]));
        let mut names: Vec<String> = std::fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        assert_eq!(names, ["keep.0", "sub"]);
    }

    #[test]
    fn value_file_names_are_sanitised() {
        assert_eq!(value_file_name("6f1c-aa", 2), "6f1c-aa.2");
        assert_eq!(value_file_name("../x", 0), ".._x.0");
    }

    #[test]
    fn sentinel_store_tracks_ended_and_persists() {
        let d = tempfile::tempdir().unwrap();
        let mut s = SentinelStore::default();
        s.update(&["a", "b"]);
        assert!(s.ended().is_empty());
        s.update(&["b"]);
        assert_eq!(s.ended(), ["a"]);
        s.update(&["a"]); // re-activated: no longer blocked; b ended
        assert_eq!(s.ended(), ["b"]);
        s.save(d.path()).unwrap();
        let mut loaded = SentinelStore::load(d.path());
        assert_eq!(loaded, s);
        // Restart with a lease left out (vault unavailable): it is blocked.
        loaded.update(&[]);
        assert_eq!(loaded.ended(), ["b", "a"]);
        for i in 0..MAX_ENDED + 5 {
            loaded.update(&[&format!("s{i}")]);
        }
        assert_eq!(loaded.ended().len(), MAX_ENDED);
    }
}
