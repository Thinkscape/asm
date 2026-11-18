//! Private directories, safe atomic file writes, the secrets directory and its
//! lease manifest (`.leases.json`, changed under an flock on `.leases.lock`).

use crate::error::CliError;
use asm_proto::crypto::{hex_encode, random_bytes};
use asm_proto::rules::check_relative_path;
use asm_proto::wire::{GetResult, LeaseMode};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const MANIFEST: &str = ".leases.json";
/// Serialises read-modify-write of the manifest between `asm` processes (the
/// background reaper included).
const MANIFEST_LOCK: &str = ".leases.lock";
/// Root-only temporary files, removed under the manifest lock after an interrupted
/// generated publication. Secret paths may not use this internal namespace.
const STAGE_PREFIX: &str = ".leases-stage-";

/// Open (creating, 0600, never through a symlink) `dir/name` and take an exclusive
/// `flock` on it, released when the file is dropped. With `wait == false`,
/// `Ok(None)` when another open file holds the lock.
pub fn lock_file(dir: &Path, name: &str, wait: bool) -> std::io::Result<Option<File>> {
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir.join(name))?;
    let op = if wait {
        libc::LOCK_EX
    } else {
        libc::LOCK_EX | libc::LOCK_NB
    };
    loop {
        // SAFETY: flock on a descriptor owned by `f`.
        if unsafe { libc::flock(f.as_raw_fd(), op) } == 0 {
            return Ok(Some(f));
        }
        let e = std::io::Error::last_os_error();
        match e.kind() {
            ErrorKind::Interrupted => continue,
            ErrorKind::WouldBlock if !wait => return Ok(None),
            _ => return Err(e),
        }
    }
}

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

/// A stable local view of an authorized field. `requested_path` is the caller's
/// unsuffixed destination; `path` is its permanently reserved collision-safe path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestBinding {
    pub field: String,
    pub requested_path: String,
    pub path: String,
}

/// One lease's files, as recorded in `.leases.json`. No credential values belong
/// in this record, including while a generated publication is incomplete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub mode: LeaseMode,
    pub expires_at: Option<String>,
    /// Complete cleanup/reservation set, including legacy unindexed paths.
    pub paths: Vec<String>,
    #[serde(default)]
    pub bindings: Vec<ManifestBinding>,
    #[serde(default)]
    pub credential_version: Option<u64>,
    #[serde(default)]
    pub credential_expires_at: Option<String>,
    #[serde(default = "material_present_default")]
    pub material_present: bool,
}

fn material_present_default() -> bool {
    true
}

/// A requested file view. These are delivery assignments, not authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileBinding {
    pub field: String,
    pub requested_path: String,
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

    /// Wait for the manifest lock; hold the returned file while changing the manifest.
    fn lock_manifest(&self) -> Result<File, CliError> {
        let path = self.root.join(MANIFEST_LOCK);
        lock_file(&self.root, MANIFEST_LOCK, true)
            .map_err(|e| io_err("locking", &path, e))
            .map(|f| f.expect("a blocking lock is always taken"))
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

    pub(crate) fn save_manifest(&self, m: &Manifest) -> Result<(), CliError> {
        let json = serde_json::to_vec_pretty(m).expect("manifest serializes");
        write_file_atomic(&self.root, MANIFEST, &json)?;
        File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .map_err(|e| io_err("syncing", &self.root, e))
    }

    /// Remove ended leases and expired raw generated material. Token expiry
    /// retains bindings and the version high-water mark until the lease ends.
    pub fn remove_expired(&self) -> Result<(), CliError> {
        let now = asm_proto::time::parse_unix(&asm_proto::time::now_rfc3339()).unwrap_or(i64::MAX);
        self.cleanup(now, |_, _| true)
    }

    /// Delete leases not reported active, while also clearing incomplete or
    /// expired generated publications.
    pub fn reconcile(&self, active: &HashSet<String>) -> Result<(), CliError> {
        let now = asm_proto::time::parse_unix(&asm_proto::time::now_rfc3339()).unwrap_or(i64::MAX);
        self.cleanup(now, |id, _| active.contains(id))
    }

    fn cleanup(
        &self,
        now: i64,
        keep: impl Fn(&str, &ManifestEntry) -> bool,
    ) -> Result<(), CliError> {
        let _lock = self.lock_manifest()?;
        self.remove_staged()?;
        let mut m = self.load_manifest()?;
        let mut changed = false;
        let mut first_err = None;
        for (id, entry) in &mut m {
            let ended = !keep(id, entry)
                || entry.expires_at.as_deref().is_some_and(|t| {
                    asm_proto::time::parse_unix(t).is_none_or(|t| t <= now)
                });
            let expired_token = entry.mode == LeaseMode::Raw
                && entry.credential_version.is_some()
                && entry.credential_expires_at.as_deref().is_none_or(|t| {
                    asm_proto::time::parse_unix(t).is_none_or(|t| t <= now)
                });
            if !ended && entry.material_present && !expired_token {
                continue;
            }
            // Persist the absence marker before deleting. A failed deletion is
            // retried next cleanup, rather than becoming an untracked stray.
            if entry.material_present {
                entry.material_present = false;
                changed = true;
            }
        }
        if changed && let Err(error) = self.save_manifest(&m) {
            // A manifest failure must not prevent best-effort removal of
            // material whose authorization or provider lifetime has ended.
            first_err = Some(error);
        }
        let mut removed_entries = false;
        for id in m.keys().cloned().collect::<Vec<_>>() {
            let entry = &m[&id];
            if entry.material_present {
                continue;
            }
            let mut removed = true;
            for p in &entry.paths {
                if let Err(e) = self.remove_rel(p) {
                    first_err.get_or_insert(e);
                    removed = false;
                }
            }
            let ended = !keep(&id, entry)
                || entry.expires_at.as_deref().is_some_and(|t| {
                    asm_proto::time::parse_unix(t).is_none_or(|t| t <= now)
                });
            if ended && removed {
                m.remove(&id);
                removed_entries = true;
            }
        }
        if removed_entries && let Err(error) = self.save_manifest(&m) {
            first_err.get_or_insert(error);
        }
        first_err.map_or(Ok(()), Err)
    }

    fn remove_staged(&self) -> Result<(), CliError> {
        for item in fs::read_dir(&self.root).map_err(|e| io_err("reading", &self.root, e))? {
            let item = item.map_err(|e| io_err("reading", &self.root, e))?;
            let name = item.file_name();
            let Some(name) = name.to_str() else { continue };
            if name.strip_prefix(STAGE_PREFIX).is_some_and(|suffix| {
                suffix.len() == 24 && suffix.bytes().all(|b| b.is_ascii_hexdigit())
            }) {
                self.remove_rel(name)?;
            }
        }
        Ok(())
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

    /// Store the manager's normal file views.
    pub fn store(&self, result: &GetResult) -> Result<Vec<StoredFile>, CliError> {
        let bindings: Vec<FileBinding> = result
            .files
            .iter()
            .map(|f| FileBinding {
                field: f.field.clone(),
                requested_path: f.relative_path.clone(),
            })
            .collect();
        self.store_bindings(result, &bindings)
    }

    /// Add/reuse requested local views, updating every indexed alias of each
    /// returned field. Only the requested views are returned for CLI output.
    pub fn store_bindings(
        &self,
        result: &GetResult,
        bindings: &[FileBinding],
    ) -> Result<Vec<StoredFile>, CliError> {
        let now = asm_proto::time::parse_unix(&asm_proto::time::now_rfc3339()).unwrap_or(i64::MAX);
        self.store_bindings_at(result, bindings, now)
    }

    fn store_bindings_at(
        &self,
        result: &GetResult,
        bindings: &[FileBinding],
        now: i64,
    ) -> Result<Vec<StoredFile>, CliError> {
        let mut fields = BTreeMap::new();
        for file in &result.files {
            validate_storage_path(&file.relative_path)?;
            if file.field.is_empty() || fields.insert(file.field.as_str(), file).is_some() {
                return Err(CliError::failure("manager sent duplicate or empty fields"));
            }
        }
        if fields.is_empty() || bindings.is_empty() {
            return Err(CliError::failure("no secret fields were selected for storage"));
        }
        for binding in bindings {
            validate_storage_path(&binding.requested_path)?;
            if !fields.contains_key(binding.field.as_str()) {
                return Err(CliError::failure("file binding refers to an undelivered field"));
            }
        }
        let generated = result.generation.is_some();
        if generated {
            if result.credential_version.is_none_or(|v| v == 0)
                || result.credential_expires_at.as_deref().is_none_or(|t| {
                    asm_proto::time::parse_unix(t).is_none_or(|t| t <= now)
                })
                || result.expires_at.as_deref().is_some_and(|t| {
                    asm_proto::time::parse_unix(t).is_none_or(|t| t <= now)
                })
            {
                return Err(CliError::failure(
                    "manager sent invalid or expired generated credential metadata",
                ));
            }
        } else if result.credential_version.is_some() || result.credential_expires_at.is_some() {
            return Err(CliError::failure("manager sent incomplete generated credential metadata"));
        }

        let _lock = self.lock_manifest()?;
        self.remove_staged()?;
        let mut manifest = self.load_manifest()?;
        if let Some(previous) = manifest.get(&result.lease_id) {
            match (previous.credential_version, result.credential_version) {
                (Some(old), Some(new)) if new < old => {
                    return Err(CliError::failure("refusing an older generated credential version"));
                }
                (Some(_), None) | (None, Some(_)) => {
                    return Err(CliError::failure("credential kind changed for an existing lease"));
                }
                _ => {}
            }
            if previous.mode != result.mode || previous.expires_at != result.expires_at {
                return Err(CliError::failure("authorization changed for an existing lease"));
            }
            if generated
                && previous.credential_version == result.credential_version
                && previous.credential_expires_at != result.credential_expires_at
            {
                return Err(CliError::failure("credential expiry changed without a new version"));
            }
        }
        let mut entry = manifest.get(&result.lease_id).cloned().unwrap_or_else(|| ManifestEntry {
            mode: result.mode,
            expires_at: result.expires_at.clone(),
            paths: Vec::new(),
            bindings: Vec::new(),
            credential_version: result.credential_version,
            credential_expires_at: result.credential_expires_at.clone(),
            material_present: true,
        });
        let suffix: String = result.lease_id.chars().filter(|c| *c != '-').take(8).collect();
        attach_legacy_bindings(&mut entry, result, &suffix);

        let other_paths: HashSet<&str> = manifest
            .iter()
            .filter(|(id, _)| **id != result.lease_id)
            .flat_map(|(_, e)| e.paths.iter().map(String::as_str))
            .collect();
        let mut requested = Vec::with_capacity(bindings.len());
        for binding in bindings {
            if entry.bindings.iter().any(|b| {
                b.requested_path == binding.requested_path && b.field != binding.field
            }) {
                return Err(CliError::failure("local destination is already bound to another field"));
            }
            let path = if let Some(existing) = entry.bindings.iter().find(|b| {
                b.field == binding.field && b.requested_path == binding.requested_path
            }) {
                existing.path.clone()
            } else {
                let path = if other_paths.contains(binding.requested_path.as_str()) {
                    format!("{}~{suffix}", binding.requested_path)
                } else {
                    binding.requested_path.clone()
                };
                if other_paths.contains(path.as_str()) || entry.paths.contains(&path) {
                    return Err(CliError::failure("local destination is already reserved"));
                }
                entry.paths.push(path.clone());
                entry.bindings.push(ManifestBinding {
                    field: binding.field.clone(),
                    requested_path: binding.requested_path.clone(),
                    path: path.clone(),
                });
                path
            };
            validate_storage_path(&path)?;
            if !requested.iter().any(|f: &StoredFile| {
                f.field == binding.field && f.relative_path == path
            }) {
                requested.push(StoredFile {
                    field: binding.field.clone(),
                    path: self.root.join(&path),
                    relative_path: path,
                });
            }
        }
        drop(other_paths);

        let mut writes = Vec::new();
        for binding in &entry.bindings {
            if let Some(file) = fields.get(binding.field.as_str()) {
                validate_storage_path(&binding.path)?;
                if !entry.paths.contains(&binding.path) {
                    return Err(CliError::failure("manifest binding has no path reservation"));
                }
                if writes.iter().any(|(path, _)| path == &binding.path) {
                    return Err(CliError::failure("manifest contains conflicting file bindings"));
                }
                writes.push((binding.path.clone(), file.content.as_bytes()));
            }
        }
        if generated {
            // Staging is before the watermark: failure leaves the previous
            // complete version untouched. Interrupted staging is swept next time.
            let mut staged = Vec::with_capacity(writes.len());
            for (path, content) in &writes {
                self.destination(path)?;
                staged.push(StagedFile::create(&self.root, content)?);
            }
            entry.credential_version = result.credential_version;
            entry.credential_expires_at = result.credential_expires_at.clone();
            entry.material_present = false;
            manifest.insert(result.lease_id.clone(), entry.clone());
            if let Err(error) = self.save_manifest(&manifest) {
                // The rename may have succeeded before a later I/O failure.
                for path in &entry.paths {
                    let _ = self.remove_rel(path);
                }
                return Err(error);
            }
            let publish = (|| {
                // Unindexed legacy paths stay reserved but cannot safely be
                // assigned a field or retain an older generated value.
                for path in &entry.paths {
                    if !entry.bindings.iter().any(|b| b.path == *path) {
                        self.remove_rel(path)?;
                    }
                }
                for ((path, _), staged) in writes.iter().zip(&mut staged) {
                    let (dir, name) = self.destination(path)?;
                    staged.install(&dir.join(name))?;
                }
                manifest.get_mut(&result.lease_id).expect("inserted above").material_present = true;
                self.save_manifest(&manifest)
            })();
            if let Err(error) = publish {
                // The durable high-water mark remains, even if removing a
                // partial publication also fails. Cleanup retries all paths.
                manifest.get_mut(&result.lease_id).expect("inserted above").material_present = false;
                let _ = self.save_manifest(&manifest);
                for path in &entry.paths {
                    let _ = self.remove_rel(path);
                }
                return Err(error);
            }
        } else {
            // Reserve all static paths before creating any file. Subset results
            // never replace the lease's other fields or their local aliases.
            manifest.insert(result.lease_id.clone(), entry);
            self.save_manifest(&manifest)?;
            for (path, content) in writes {
                let (dir, name) = self.destination(&path)?;
                write_file_atomic(&dir, name, content)?;
            }
        }
        Ok(requested)
    }

    fn destination<'a>(&self, relative_path: &'a str) -> Result<(PathBuf, &'a str), CliError> {
        let segments = check_relative_path(relative_path).map_err(CliError::from)?;
        match segments.as_slice() {
            [name] => Ok((self.root.clone(), *name)),
            [sub, name] => {
                let dir = self.root.join(sub);
                ensure_private_dir(&dir)?;
                Ok((dir, *name))
            }
            _ => unreachable!("check_relative_path allows at most two segments"),
        }
    }
}

fn validate_storage_path(path: &str) -> Result<(), CliError> {
    let segments = check_relative_path(path).map_err(|e| {
        CliError::failure(format!("manager sent an unsafe path: {}", e.message))
    })?;
    if matches!(segments[0], MANIFEST | MANIFEST_LOCK | ".reaper.lock")
        || segments[0].starts_with(STAGE_PREFIX)
    {
        return Err(CliError::failure("secret path uses a reserved storage name"));
    }
    Ok(())
}

fn attach_legacy_bindings(entry: &mut ManifestEntry, result: &GetResult, suffix: &str) {
    for file in &result.files {
        if entry.bindings.iter().any(|binding| {
            binding.requested_path == file.relative_path
        }) {
            continue;
        }
        let suffixed = format!("{}~{suffix}", file.relative_path);
        let mut candidates = entry.paths.iter().filter(|path| {
            !entry.bindings.iter().any(|binding| binding.path == **path)
                && (**path == file.relative_path || **path == suffixed)
                && result.files.iter().filter(|other| {
                    **path == other.relative_path
                        || path.strip_prefix(other.relative_path.as_str())
                            .is_some_and(|tail| tail.strip_prefix('~') == Some(suffix))
                }).count() == 1
        });
        let Some(path) = candidates.next() else { continue };
        if candidates.next().is_none() {
            entry.bindings.push(ManifestBinding {
                field: file.field.clone(),
                requested_path: file.relative_path.clone(),
                path: path.clone(),
            });
        }
    }
}

/// A staged generated value never outlives its publication attempt. If the
/// process dies, cleanup removes this reserved root-only staging namespace.
struct StagedFile {
    path: PathBuf,
}

impl StagedFile {
    fn create(root: &Path, content: &[u8]) -> Result<Self, CliError> {
        let path = root.join(format!("{STAGE_PREFIX}{}", hex_encode(&random_bytes::<12>())));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|e| io_err("staging", &path, e))?;
        let staged = Self { path };
        file.write_all(content).map_err(|e| io_err("staging", &staged.path, e))?;
        file.sync_all().map_err(|e| io_err("syncing", &staged.path, e))?;
        Ok(staged)
    }

    fn install(&mut self, target: &Path) -> Result<(), CliError> {
        fs::rename(&self.path, target).map_err(|e| io_err("publishing", target, e))?;
        let parent = target.parent().expect("destination is inside the secrets directory");
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|e| io_err("syncing", parent, e))
    }
}

impl Drop for StagedFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
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
            generation: None,
            operator_selected_grant: false,
            credential_expires_at: None,
            credential_version: None,
            generator_name: None,
            files: files
                .iter()
                .map(|(p, c)| ResultFile {
                    field: "value".into(),
                    relative_path: (*p).into(),
                    content: (*c).into(),
                    substituted: true,
                })
                .collect(),
        }
    }

    const L1: &str = "11111111-2222-4333-8444-555555555555";

    fn binding(field: &str, requested_path: &str) -> FileBinding {
        FileBinding { field: field.into(), requested_path: requested_path.into() }
    }

    fn generated(version: u64, content: &str, mode: LeaseMode) -> GetResult {
        let mut result = result(
            L1,
            &[("GH_TOKEN", content)],
            Some(&asm_proto::time::fmt_unix(43_200)),
        );
        result.mode = mode;
        result.generation = Some(serde_json::from_value(serde_json::json!({
            "generator_id": "generator-a",
            "generator_revision": 1,
            "grant": {
                "provider": "github_app",
                "scope": {
                    "installation_id": 7,
                    "repositories": [{"id": 11, "full_name": "acme/web"}],
                    "permissions": {"metadata": "read", "contents": "read"}
                }
            }
        })).unwrap());
        result.credential_version = Some(version);
        result.credential_expires_at = Some(asm_proto::time::fmt_unix(4_600));
        result.generator_name = Some("release-bot".into());
        result.files[0].substituted = mode == LeaseMode::Sentinel;
        result
    }

    fn fields_result(fields: &[(&str, &str, &str)]) -> GetResult {
        let mut result = result(L1, &[], None);
        result.files = fields.iter().map(|(field, path, content)| ResultFile {
            field: (*field).into(),
            relative_path: (*path).into(),
            content: (*content).into(),
            substituted: *field != "username",
        }).collect();
        result
    }

    fn assert_no_staged(dir: &SecretsDir) {
        assert!(fs::read_dir(dir.root()).unwrap().all(|item| {
            !item.unwrap().file_name().to_string_lossy().starts_with(STAGE_PREFIX)
        }));
    }

    #[test]
    fn legacy_manifest_defaults_are_nonsecret_and_compatible() {
        let manifest: Manifest = serde_json::from_value(serde_json::json!({
            (L1): {"mode": "raw", "expires_at": null, "paths": ["TOKEN"]}
        })).unwrap();
        let entry = &manifest[L1];
        assert!(entry.bindings.is_empty());
        assert_eq!(entry.credential_version, None);
        assert_eq!(entry.credential_expires_at, None);
        assert!(entry.material_present);
    }

    #[test]
    fn generated_aliases_share_versions_and_only_requested_views_are_returned() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = SecretsDir::open(tmp.path().join("s")).unwrap();
        let initial = generated(1, "first-token", LeaseMode::Raw);
        dir.store_bindings_at(&initial, &[binding("value", "GH_TOKEN")], 1_000).unwrap();
        let alias = dir.store_bindings_at(
            &initial, &[binding("value", "GITHUB_TOKEN")], 1_001,
        ).unwrap();
        assert_eq!(alias.len(), 1);
        assert_eq!(alias[0].relative_path, "GITHUB_TOKEN");
        let renewed = generated(2, "replacement-token", LeaseMode::Raw);
        let printed = dir.store_bindings_at(
            &renewed, &[binding("value", "release-bot/GITHUB_TOKEN")], 2_000,
        ).unwrap();
        assert_eq!(printed.len(), 1);
        assert_eq!(printed[0].relative_path, "release-bot/GITHUB_TOKEN");
        for path in ["GH_TOKEN", "GITHUB_TOKEN", "release-bot/GITHUB_TOKEN"] {
            assert_eq!(fs::read_to_string(dir.root().join(path)).unwrap(), "replacement-token");
        }
        let manifest = dir.load_manifest().unwrap();
        assert_eq!(manifest.len(), 1);
        assert_eq!(manifest[L1].bindings.len(), 3);
        assert_eq!(manifest[L1].credential_version, Some(2));
        assert!(manifest[L1].material_present);
        let serialized = fs::read_to_string(dir.root().join(MANIFEST)).unwrap();
        assert!(!serialized.contains("first-token"));
        assert!(!serialized.contains("replacement-token"));
        assert_no_staged(&dir);
    }

    #[test]
    fn suffix_assignment_survives_competitor_removal_token_cleanup_and_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("s");
        let dir = SecretsDir::open(root.clone()).unwrap();
        dir.store(&result(L2, &[("GH_TOKEN", "static")], None)).unwrap();
        let initial = generated(1, "first-token", LeaseMode::Raw);
        let first = dir.store_bindings_at(
            &initial, &[binding("value", "GH_TOKEN")], 1_000,
        ).unwrap();
        assert_eq!(first[0].relative_path, "GH_TOKEN~11111111");
        dir.cleanup(4_600, |id, _| id == L1).unwrap();
        let reserved = dir.load_manifest().unwrap();
        assert!(!reserved[L1].material_present);
        assert_eq!(reserved[L1].paths, vec!["GH_TOKEN~11111111"]);
        assert!(!dir.root().join("GH_TOKEN").exists());
        let dir = SecretsDir::open(root).unwrap();
        let mut renewed = generated(2, "new-token", LeaseMode::Raw);
        renewed.credential_expires_at = Some(asm_proto::time::fmt_unix(8_200));
        let again = dir.store_bindings_at(
            &renewed, &[binding("value", "GH_TOKEN")], 4_600,
        ).unwrap();
        assert_eq!(again[0].relative_path, "GH_TOKEN~11111111");
        assert!(!dir.root().join("GH_TOKEN").exists());
        assert_eq!(fs::read_to_string(&again[0].path).unwrap(), "new-token");
    }

    #[test]
    fn versions_never_move_back_even_with_equal_expiry_after_restart() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("s");
        let dir = SecretsDir::open(root.clone()).unwrap();
        let newer = generated(9, "new-token", LeaseMode::Raw);
        dir.store_bindings_at(&newer, &[binding("value", "GH_TOKEN")], 1_000).unwrap();
        let dir = SecretsDir::open(root).unwrap();
        let old = generated(8, "old-token", LeaseMode::Raw);
        assert!(dir.store_bindings_at(&old, &[binding("value", "GITHUB_TOKEN")], 1_001)
            .unwrap_err().message.contains("older"));
        assert!(!dir.root().join("GITHUB_TOKEN").exists());
        assert_eq!(fs::read_to_string(dir.root().join("GH_TOKEN")).unwrap(), "new-token");
        dir.store_bindings_at(&newer, &[binding("value", "GITHUB_TOKEN")], 1_001).unwrap();
        let mut inconsistent = newer;
        inconsistent.credential_expires_at = Some(asm_proto::time::fmt_unix(4_601));
        assert!(dir.store_bindings_at(
            &inconsistent, &[binding("value", "GH_TOKEN")], 1_002,
        ).is_err());
        assert_eq!(dir.load_manifest().unwrap()[L1].credential_version, Some(9));
    }

    #[test]
    fn partial_generated_publication_keeps_watermark_and_same_version_can_retry() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = SecretsDir::open(tmp.path().join("s")).unwrap();
        let views = [binding("value", "GH_TOKEN"), binding("value", "GITHUB_TOKEN")];
        dir.store_bindings_at(&generated(1, "first-token", LeaseMode::Raw), &views, 1_000).unwrap();
        fs::remove_file(dir.root().join("GITHUB_TOKEN")).unwrap();
        fs::create_dir(dir.root().join("GITHUB_TOKEN")).unwrap();
        let next = generated(2, "replacement-token", LeaseMode::Raw);
        assert!(dir.store_bindings_at(&next, &views[..1], 1_001).is_err());
        let incomplete = dir.load_manifest().unwrap();
        assert_eq!(incomplete[L1].credential_version, Some(2));
        assert!(!incomplete[L1].material_present);
        assert_eq!(incomplete[L1].bindings.len(), 2);
        assert!(!dir.root().join("GH_TOKEN").exists());
        assert_no_staged(&dir);
        assert!(dir.store_bindings_at(
            &generated(1, "first-token", LeaseMode::Raw), &views[..1], 1_002,
        ).is_err());
        fs::remove_dir(dir.root().join("GITHUB_TOKEN")).unwrap();
        dir.store_bindings_at(&next, &views[..1], 1_002).unwrap();
        for path in ["GH_TOKEN", "GITHUB_TOKEN"] {
            assert_eq!(fs::read_to_string(dir.root().join(path)).unwrap(), "replacement-token");
        }
        assert!(dir.load_manifest().unwrap()[L1].material_present);
    }

    #[test]
    fn staging_failure_leaves_previous_complete_version_untouched() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tmp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        let dir = SecretsDir::open(tmp.path().join("s")).unwrap();
        dir.store_bindings_at(
            &generated(1, "first-token", LeaseMode::Raw),
            &[binding("value", "GH_TOKEN")], 1_000,
        ).unwrap();
        symlink(&outside, dir.root().join("blocked")).unwrap();
        assert!(dir.store_bindings_at(
            &generated(2, "replacement-token", LeaseMode::Raw),
            &[binding("value", "blocked/GITHUB_TOKEN")], 1_001,
        ).is_err());
        assert_eq!(fs::read_to_string(dir.root().join("GH_TOKEN")).unwrap(), "first-token");
        assert!(!outside.join("GITHUB_TOKEN").exists());
        let manifest = dir.load_manifest().unwrap();
        assert_eq!(manifest[L1].credential_version, Some(1));
        assert!(manifest[L1].material_present);
        assert_eq!(manifest[L1].bindings.len(), 1);
        assert_no_staged(&dir);
    }

    #[test]
    fn cleanup_retries_incomplete_publications_and_removes_abandoned_staging() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = SecretsDir::open(tmp.path().join("s")).unwrap();
        let views = [binding("value", "GH_TOKEN"), binding("value", "work/GITHUB_TOKEN")];
        dir.store_bindings_at(&generated(3, "token", LeaseMode::Raw), &views, 1_000).unwrap();
        let mut manifest = dir.load_manifest().unwrap();
        manifest.get_mut(L1).unwrap().material_present = false;
        dir.save_manifest(&manifest).unwrap();
        let abandoned = format!("{STAGE_PREFIX}{}", "a".repeat(24));
        fs::write(dir.root().join(&abandoned), "staged-token").unwrap();
        dir.cleanup(1_001, |_, _| true).unwrap();
        assert!(!dir.root().join("GH_TOKEN").exists());
        assert!(!dir.root().join("work").exists());
        assert!(!dir.root().join(abandoned).exists());
        assert_eq!(dir.load_manifest().unwrap(), manifest);
        dir.cleanup(1_002, |_, _| true).unwrap();
        assert_eq!(dir.load_manifest().unwrap(), manifest);
    }

    #[test]
    fn raw_token_expiry_keeps_reservations_until_authorization_ends() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = SecretsDir::open(tmp.path().join("s")).unwrap();
        dir.store_bindings_at(
            &generated(5, "raw-token", LeaseMode::Raw),
            &[binding("value", "GH_TOKEN"), binding("value", "GITHUB_TOKEN")], 1_000,
        ).unwrap();
        dir.cleanup(4_599, |_, _| true).unwrap();
        assert!(dir.root().join("GH_TOKEN").exists());
        dir.cleanup(4_600, |_, _| true).unwrap();
        let manifest = dir.load_manifest().unwrap();
        assert_eq!(manifest[L1].credential_version, Some(5));
        assert_eq!(manifest[L1].credential_expires_at, Some(asm_proto::time::fmt_unix(4_600)));
        assert_eq!(manifest[L1].paths.len(), 2);
        assert_eq!(manifest[L1].bindings.len(), 2);
        assert!(!manifest[L1].material_present);
        assert!(!dir.root().join("GH_TOKEN").exists());
        assert!(!dir.root().join("GITHUB_TOKEN").exists());
        let reserved = dir.store(&result(L2, &[("GH_TOKEN", "static")], None)).unwrap();
        assert_eq!(reserved[0].relative_path, "GH_TOKEN~aaaaaaaa");
        dir.cleanup(43_200, |_, _| true).unwrap();
        assert!(!dir.load_manifest().unwrap().contains_key(L1));
        assert!(dir.root().join("GH_TOKEN~aaaaaaaa").exists());
    }

    #[test]
    fn lease_expiry_precedes_token_expiry_but_sentinel_material_survives_token_expiry() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = SecretsDir::open(tmp.path().join("s")).unwrap();
        let mut short = generated(1, "raw-token", LeaseMode::Raw);
        short.expires_at = Some(asm_proto::time::fmt_unix(2_000));
        dir.store_bindings_at(&short, &[binding("value", "GH_TOKEN")], 1_000).unwrap();
        dir.cleanup(2_000, |_, _| true).unwrap();
        assert!(dir.load_manifest().unwrap().is_empty());
        assert!(!dir.root().join("GH_TOKEN").exists());
        let sentinel = generated(1, "asm_sentinel", LeaseMode::Sentinel);
        dir.store_bindings_at(&sentinel, &[binding("value", "GH_TOKEN")], 1_000).unwrap();
        dir.cleanup(4_600, |_, _| true).unwrap();
        assert_eq!(fs::read_to_string(dir.root().join("GH_TOKEN")).unwrap(), "asm_sentinel");
        assert!(dir.load_manifest().unwrap()[L1].material_present);
        dir.cleanup(43_200, |_, _| true).unwrap();
        assert!(dir.load_manifest().unwrap().is_empty());
    }

    #[test]
    fn malformed_generated_metadata_never_creates_material() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = SecretsDir::open(tmp.path().join("s")).unwrap();
        let valid = generated(1, "secret-token", LeaseMode::Raw);
        for expiry in [None, Some("not-a-time"), Some("1970-01-01T00:16:40Z")] {
            let mut invalid = valid.clone();
            invalid.credential_expires_at = expiry.map(Into::into);
            assert!(dir.store_bindings_at(&invalid, &[binding("value", "GH_TOKEN")], 1_000).is_err());
        }
        for version in [None, Some(0)] {
            let mut invalid = valid.clone();
            invalid.credential_version = version;
            assert!(dir.store_bindings_at(&invalid, &[binding("value", "GH_TOKEN")], 1_000).is_err());
        }
        let mut invalid = valid;
        invalid.generation = None;
        assert!(dir.store_bindings_at(&invalid, &[binding("value", "GH_TOKEN")], 1_000).is_err());
        assert!(!dir.root().join("GH_TOKEN").exists());
        assert!(dir.load_manifest().unwrap().is_empty());
    }

    #[test]
    fn static_subset_updates_only_returned_fields_and_keeps_other_views() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = SecretsDir::open(tmp.path().join("s")).unwrap();
        let full = fields_result(&[
            ("username", "google.username", "first-user"),
            ("password", "google.password", "unchanged-password"),
        ]);
        dir.store(&full).unwrap();
        let subset = fields_result(&[("username", "google.username", "new-user")]);
        let printed = dir.store_bindings(&subset, &[binding("username", "GOOGLE_USER")]).unwrap();
        assert_eq!(printed.len(), 1);
        for path in ["google.username", "GOOGLE_USER"] {
            assert_eq!(fs::read_to_string(dir.root().join(path)).unwrap(), "new-user");
        }
        assert_eq!(
            fs::read_to_string(dir.root().join("google.password")).unwrap(), "unchanged-password",
        );
        assert_eq!(dir.load_manifest().unwrap()[L1].paths.len(), 3);
        let password = fields_result(&[("password", "google.password", "new-password")]);
        assert!(dir.store_bindings(&password, &[binding("password", "GOOGLE_USER")]).is_err());
        assert_eq!(fs::read_to_string(dir.root().join("GOOGLE_USER")).unwrap(), "new-user");
    }

    #[test]
    fn legacy_field_metadata_attaches_only_to_unique_authoritative_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = SecretsDir::open(tmp.path().join("s")).unwrap();
        let mut manifest: Manifest = serde_json::from_value(serde_json::json!({
            (L1): {"mode": "sentinel", "expires_at": null,
                "paths": ["google.username~11111111", "old-view"]}
        })).unwrap();
        for path in &manifest[L1].paths {
            fs::write(dir.root().join(path), "legacy-value").unwrap();
        }
        dir.save_manifest(&manifest).unwrap();
        let subset = fields_result(&[("username", "google.username", "new-user")]);
        dir.store_bindings(&subset, &[binding("username", "GOOGLE_USER")]).unwrap();
        manifest = dir.load_manifest().unwrap();
        assert_eq!(manifest[L1].bindings.len(), 2);
        assert!(!manifest[L1].bindings.iter().any(|binding| binding.path == "old-view"));
        assert_eq!(fs::read_to_string(dir.root().join("old-view")).unwrap(), "legacy-value");
        assert_eq!(
            fs::read_to_string(dir.root().join("google.username~11111111")).unwrap(), "new-user",
        );
        let authoritative = dir.store(&subset).unwrap();
        assert_eq!(authoritative[0].relative_path, "google.username~11111111");
    }

    #[test]
    fn ambiguous_legacy_paths_remain_reserved_without_invented_field_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = SecretsDir::open(tmp.path().join("s")).unwrap();
        let manifest: Manifest = serde_json::from_value(serde_json::json!({
            (L1): {"mode": "sentinel", "expires_at": null,
                "paths": ["google.username", "google.username~11111111"]}
        })).unwrap();
        for path in &manifest[L1].paths {
            fs::write(dir.root().join(path), "legacy-value").unwrap();
        }
        dir.save_manifest(&manifest).unwrap();
        let subset = fields_result(&[("username", "google.username", "new-user")]);
        dir.store_bindings(&subset, &[binding("username", "GOOGLE_USER")]).unwrap();
        let manifest = dir.load_manifest().unwrap();
        assert_eq!(manifest[L1].bindings.len(), 1);
        assert_eq!(manifest[L1].paths.len(), 3);
        assert!(dir.store(&subset).is_err());
        assert_eq!(fs::read_to_string(dir.root().join("google.username")).unwrap(), "legacy-value");
    }

    #[test]
    fn static_write_failure_records_all_paths_for_later_cleanup() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = SecretsDir::open(tmp.path().join("s")).unwrap();
        fs::create_dir(dir.root().join("BLOCKED")).unwrap();
        let result = fields_result(&[("one", "FIRST", "one"), ("two", "BLOCKED", "two")]);
        assert!(dir.store(&result).is_err());
        let manifest = dir.load_manifest().unwrap();
        assert_eq!(manifest[L1].paths, vec!["FIRST", "BLOCKED"]);
        assert_eq!(manifest[L1].bindings.len(), 2);
        assert_eq!(fs::read_to_string(dir.root().join("FIRST")).unwrap(), "one");
        dir.reconcile(&HashSet::new()).unwrap();
        assert!(!dir.root().join("FIRST").exists());
        assert!(dir.load_manifest().unwrap().is_empty());
    }

    #[test]
    fn internal_storage_names_and_competing_field_destinations_are_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = SecretsDir::open(tmp.path().join("s")).unwrap();
        for path in [MANIFEST, MANIFEST_LOCK, ".reaper.lock", ".leases-stage-reserved/TOKEN"] {
            assert!(dir.store(&result(L1, &[(path, "value")], None)).is_err());
        }
        let result = fields_result(&[("one", "ONE", "one"), ("two", "TWO", "two")]);
        assert!(dir.store_bindings(&result, &[binding("one", "SAME"), binding("two", "SAME")]).is_err());
        assert!(dir.load_manifest().unwrap().is_empty());
        assert!(!dir.root().join("SAME").exists());
    }
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
                bindings: Vec::new(),
                credential_version: None,
                credential_expires_at: None,
                material_present: true,
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
