//! Private directories, safe atomic file writes, the secrets directory and its
//! lease manifest (`.leases.json`).

use crate::error::CliError;
use asm_proto::crypto::{hex_encode, random_bytes};
use asm_proto::rules::check_relative_path;
use asm_proto::wire::{GetResult, LeaseMode};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const MANIFEST: &str = ".leases.json";

fn io_err(what: &str, path: &Path, e: std::io::Error) -> CliError {
    CliError::failure(format!("{what} {}: {e}", path.display()))
}

/// Create `dir` (and missing parents) with mode 0700; refuse a path that is not a
/// directory owned by the current user (symlinks included); tighten its mode to 0700.
pub fn ensure_private_dir(dir: &Path) -> Result<(), CliError> {
    match fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
    {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
        Err(e) => return Err(io_err("creating", dir, e)),
    }
    let meta = fs::symlink_metadata(dir).map_err(|e| io_err("inspecting", dir, e))?;
    if !meta.file_type().is_dir() {
        return Err(CliError::failure(format!(
            "{} is not a directory",
            dir.display()
        )));
    }
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    if meta.uid() != uid {
        return Err(CliError::failure(format!(
            "refusing {}: owned by uid {}, not by the current user (uid {uid})",
            dir.display(),
            meta.uid()
        )));
    }
    if meta.mode() & 0o777 != 0o700 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| io_err("setting permissions of", dir, e))?;
    }
    Ok(())
}

/// Write `name` inside `dir` atomically: a temp file created with
/// `O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0600, then renamed over the target (a symlink
/// at the target is replaced, never followed).
pub fn write_file_atomic(dir: &Path, name: &str, data: &[u8]) -> Result<PathBuf, CliError> {
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return Err(CliError::failure(format!("invalid file name {name:?}")));
    }
    let target = dir.join(name);
    let tmp = dir.join(format!(".{name}.tmp-{}", hex_encode(&random_bytes::<6>())));
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)
            .map_err(|e| io_err("creating", &tmp, e))?;
        f.write_all(data).map_err(|e| io_err("writing", &tmp, e))?;
        f.sync_all().map_err(|e| io_err("syncing", &tmp, e))?;
        fs::rename(&tmp, &target).map_err(|e| io_err("renaming to", &target, e))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.map(|()| target)
}

/// One lease's files, as recorded in `.leases.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub mode: LeaseMode,
    pub expires_at: Option<String>,
    /// Paths relative to the secrets directory.
    pub paths: Vec<String>,
}

/// Lease id → files.
pub type Manifest = BTreeMap<String, ManifestEntry>;

/// The secrets directory: where lease files are written.
#[derive(Debug, Clone)]
pub struct SecretsDir {
    root: PathBuf,
}

/// `$ASM_SECRETS_DIR`, else `$XDG_RUNTIME_DIR/asm/secrets`, else `~/.asm/secrets`.
pub fn default_secrets_path() -> Result<PathBuf, CliError> {
    let abs = |v: std::ffi::OsString| Some(PathBuf::from(v)).filter(|p| p.is_absolute());
    if let Some(p) = std::env::var_os("ASM_SECRETS_DIR").and_then(abs) {
        return Ok(p);
    }
    if let Some(p) = std::env::var_os("XDG_RUNTIME_DIR").and_then(abs) {
        return Ok(p.join("asm").join("secrets"));
    }
    Ok(crate::state::home_dir()?.join(".asm").join("secrets"))
}

/// The written file of one result entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredFile {
    pub field: String,
    pub relative_path: String,
    pub path: PathBuf,
}

impl SecretsDir {
    /// Open (creating, 0700, ownership-checked) the default secrets directory.
    pub fn open_default() -> Result<Self, CliError> {
        Self::open(default_secrets_path()?)
    }

    /// Open (creating, 0700, ownership-checked) `root`.
    pub fn open(root: PathBuf) -> Result<Self, CliError> {
        ensure_private_dir(&root)?;
        Ok(SecretsDir { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn load_manifest(&self) -> Result<Manifest, CliError> {
        let path = self.root.join(MANIFEST);
        match fs::read(&path) {
            Ok(b) => serde_json::from_slice(&b).map_err(|e| {
                CliError::failure(format!(
                    "{} is not valid ({e}); delete it and request the leases again",
                    path.display()
                ))
            }),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(Manifest::new()),
            Err(e) => Err(io_err("reading", &path, e)),
        }
    }

    fn save_manifest(&self, m: &Manifest) -> Result<(), CliError> {
        let json = serde_json::to_vec_pretty(m).expect("manifest serializes");
        write_file_atomic(&self.root, MANIFEST, &json).map(|_| ())
    }

    /// Delete the files of every lease whose expiry has passed (an unparseable
    /// expiry counts as passed).
    pub fn remove_expired(&self) -> Result<(), CliError> {
        let now = asm_proto::time::parse_unix(&asm_proto::time::now_rfc3339()).unwrap_or(i64::MAX);
        self.retain(|_, e| match &e.expires_at {
            None => true,
            Some(t) => asm_proto::time::parse_unix(t).is_some_and(|t| t > now),
        })
    }

    /// Delete the files of every lease not in `active` (the ids `GET /leases`
    /// reports as active).
    pub fn reconcile(&self, active: &HashSet<String>) -> Result<(), CliError> {
        self.retain(|id, _| active.contains(id))
    }

    fn retain(&self, keep: impl Fn(&str, &ManifestEntry) -> bool) -> Result<(), CliError> {
        let mut m = self.load_manifest()?;
        let gone: Vec<String> = m
            .iter()
            .filter(|(id, e)| !keep(id, e))
            .map(|(id, _)| id.clone())
            .collect();
        if gone.is_empty() {
            return Ok(());
        }
        let mut first_err = None;
        for id in &gone {
            let entry = m.remove(id).expect("listed above");
            for p in &entry.paths {
                if let Err(e) = self.remove_rel(p) {
                    first_err.get_or_insert(e);
                }
            }
        }
        self.save_manifest(&m)?;
        first_err.map_or(Ok(()), Err)
    }

    /// Delete one file given relative to the secrets directory. Anything that is
    /// not a safe relative path inside the directory is left alone.
    fn remove_rel(&self, rel: &str) -> Result<(), CliError> {
        let Ok(segs) = check_relative_path(rel) else {
            return Ok(());
        };
        if segs.len() == 2 {
            let sub = self.root.join(segs[0]);
            match fs::symlink_metadata(&sub) {
                Ok(m) if m.file_type().is_dir() => {}
                _ => return Ok(()),
            }
        }
        let path = self.root.join(rel);
        match fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_dir() => return Ok(()),
            Ok(_) => fs::remove_file(&path).map_err(|e| io_err("deleting", &path, e))?,
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(io_err("inspecting", &path, e)),
        }
        if segs.len() == 2 {
            // Drop the vault subdirectory once it is empty.
            let _ = fs::remove_dir(self.root.join(segs[0]));
        }
        Ok(())
    }

    /// Write the files of an approved `get` and record them in the manifest.
    /// A path already used by another lease gets `~<first 8 of lease id>`.
    pub fn store(&self, result: &GetResult) -> Result<Vec<StoredFile>, CliError> {
        for f in &result.files {
            check_relative_path(&f.relative_path).map_err(|e| {
                CliError::failure(format!("manager sent an unsafe path: {}", e.message))
            })?;
        }
        let mut m = self.load_manifest()?;
        let taken: HashSet<&str> = m
            .iter()
            .filter(|(id, _)| **id != result.lease_id)
            .flat_map(|(_, e)| e.paths.iter().map(String::as_str))
            .collect();
        let suffix: String = result
            .lease_id
            .chars()
            .filter(|c| *c != '-')
            .take(8)
            .collect();
        let paths: Vec<String> = result
            .files
            .iter()
            .map(|f| {
                if taken.contains(f.relative_path.as_str()) {
                    format!("{}~{suffix}", f.relative_path)
                } else {
                    f.relative_path.clone()
                }
            })
            .collect();
        drop(taken);
        let old = m.insert(
            result.lease_id.clone(),
            ManifestEntry {
                mode: result.mode,
                expires_at: result.expires_at.clone(),
                paths: paths.clone(),
            },
        );
        self.save_manifest(&m)?;
        if let Some(old) = old {
            for p in old.paths.iter().filter(|p| !paths.contains(p)) {
                self.remove_rel(p)?;
            }
        }
        let mut out = Vec::with_capacity(paths.len());
        for (f, rel) in result.files.iter().zip(&paths) {
            let segs = check_relative_path(rel).map_err(CliError::from)?;
            let (dir, name) = match segs.as_slice() {
                [name] => (self.root.clone(), *name),
                [sub, name] => {
                    let dir = self.root.join(sub);
                    ensure_private_dir(&dir)?;
                    (dir, *name)
                }
                _ => unreachable!("check_relative_path allows at most two segments"),
            };
            let path = write_file_atomic(&dir, name, f.content.as_bytes())?;
            out.push(StoredFile {
                field: f.field.clone(),
                relative_path: rel.clone(),
                path,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asm_proto::wire::ResultFile;
    use std::os::unix::fs::symlink;

    fn result(lease: &str, files: &[(&str, &str)], expires: Option<&str>) -> GetResult {
        GetResult {
            lease_id: lease.into(),
            mode: LeaseMode::Sentinel,
            hosts: vec!["api.example.com".into()],
            expires_at: expires.map(Into::into),
            files: files
                .iter()
                .map(|(p, c)| ResultFile {
                    field: "value".into(),
                    relative_path: (*p).into(),
                    content: (*c).into(),
                })
                .collect(),
        }
    }

    const L1: &str = "11111111-2222-4333-8444-555555555555";
    const L2: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

    #[test]
    fn rejects_unsafe_relative_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = SecretsDir::open(tmp.path().join("secrets")).unwrap();
        for bad in ["../escape", "/etc/passwd", "a/b/c", "a/../b", "..", "a//b"] {
            let err = dir.store(&result(L1, &[(bad, "x")], None)).unwrap_err();
            assert!(err.message.contains("unsafe"), "{bad}: {}", err.message);
        }
        assert!(!tmp.path().join("escape").exists());
        assert!(dir.load_manifest().unwrap().is_empty());
    }

    #[test]
    fn symlink_at_target_is_not_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("outside.txt");
        fs::write(&outside, "keep me").unwrap();
        let dir = SecretsDir::open(tmp.path().join("secrets")).unwrap();
        symlink(&outside, dir.root().join("TOKEN")).unwrap();
        let stored = dir
            .store(&result(L1, &[("TOKEN", "asm_value")], None))
            .unwrap();
        assert_eq!(fs::read_to_string(&outside).unwrap(), "keep me");
        let meta = fs::symlink_metadata(&stored[0].path).unwrap();
        assert!(meta.file_type().is_file());
        assert_eq!(meta.mode() & 0o777, 0o600);
        assert_eq!(fs::read_to_string(&stored[0].path).unwrap(), "asm_value");
    }

    #[test]
    fn symlinked_vault_subdirectory_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let elsewhere = tmp.path().join("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        let dir = SecretsDir::open(tmp.path().join("secrets")).unwrap();
        symlink(&elsewhere, dir.root().join("work")).unwrap();
        assert!(
            dir.store(&result(L1, &[("work/TOKEN", "x")], None))
                .is_err()
        );
        assert!(!elsewhere.join("TOKEN").exists());
    }

    #[test]
    fn directories_are_private() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("a").join("secrets");
        let dir = SecretsDir::open(root.clone()).unwrap();
        dir.store(&result(L1, &[("work/X.password", "x")], None))
            .unwrap();
        for d in [root.clone(), root.join("work")] {
            assert_eq!(
                fs::metadata(&d).unwrap().mode() & 0o777,
                0o700,
                "{}",
                d.display()
            );
        }
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        SecretsDir::open(root.clone()).unwrap();
        assert_eq!(fs::metadata(&root).unwrap().mode() & 0o777, 0o700);
    }

    #[test]
    fn collision_with_another_lease_gets_suffix() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = SecretsDir::open(tmp.path().join("s")).unwrap();
        let a = dir.store(&result(L1, &[("TOKEN", "a")], None)).unwrap();
        let b = dir.store(&result(L2, &[("TOKEN", "b")], None)).unwrap();
        assert_eq!(a[0].relative_path, "TOKEN");
        assert_eq!(b[0].relative_path, "TOKEN~aaaaaaaa");
        // The same lease delivered again reuses its path.
        let a2 = dir.store(&result(L1, &[("TOKEN", "a")], None)).unwrap();
        assert_eq!(a2[0].relative_path, "TOKEN");
        assert_eq!(
            fs::read_to_string(dir.root().join("TOKEN~aaaaaaaa")).unwrap(),
            "b"
        );
    }

    #[test]
    fn expired_and_inactive_leases_are_removed() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = SecretsDir::open(tmp.path().join("s")).unwrap();
        dir.store(&result(
            L1,
            &[("work/OLD", "a")],
            Some("2000-01-01T00:00:00Z"),
        ))
        .unwrap();
        dir.store(&result(L2, &[("NEW", "b")], Some("2999-01-01T00:00:00Z")))
            .unwrap();
        dir.remove_expired().unwrap();
        assert!(!dir.root().join("work").exists());
        assert!(dir.root().join("NEW").exists());
        dir.reconcile(&HashSet::new()).unwrap();
        assert!(!dir.root().join("NEW").exists());
        assert!(dir.load_manifest().unwrap().is_empty());
    }

    #[test]
    fn cleanup_only_deletes_inside_the_secrets_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let victim = tmp.path().join("victim");
        fs::write(&victim, "keep").unwrap();
        let outside_dir = tmp.path().join("outdir");
        fs::create_dir(&outside_dir).unwrap();
        fs::write(outside_dir.join("f"), "keep").unwrap();
        let dir = SecretsDir::open(tmp.path().join("s")).unwrap();
        symlink(&outside_dir, dir.root().join("link")).unwrap();
        let mut m = Manifest::new();
        m.insert(
            L1.into(),
            ManifestEntry {
                mode: LeaseMode::Raw,
                expires_at: Some("2000-01-01T00:00:00Z".into()),
                paths: vec![
                    "../victim".into(),
                    victim.to_string_lossy().into_owned(),
                    "link/f".into(),
                    "a/../../victim".into(),
                ],
            },
        );
        dir.save_manifest(&m).unwrap();
        dir.remove_expired().unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "keep");
        assert_eq!(fs::read_to_string(outside_dir.join("f")).unwrap(), "keep");
        assert!(dir.load_manifest().unwrap().is_empty());
    }

    #[test]
    fn refuses_directory_owned_by_someone_else() {
        // /  is owned by root; when the tests run as root this check is meaningless.
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        assert!(ensure_private_dir(Path::new("/")).is_err());
    }
}
