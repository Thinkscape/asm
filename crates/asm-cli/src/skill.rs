//! `asm skill`: install the agent skill embedded in this binary into agents' skill folders
//! (`<DIR>/asm/SKILL.md` and its companion `<DIR>/asm/SETUP.md`, default DIR
//! `~/.agents/skills`).
//!
//! An installed `SKILL.md` carries `installed-by: asm` and `asm-version` under the
//! frontmatter's `metadata` map (the Agent Skills spec's place for client properties); only
//! files with `installed-by: asm` are updated or removed without `--force`. Content is compared
//! with the version value normalised, so a version-only difference is reported as such.
//! `SETUP.md` belongs to the asm-installed `SKILL.md` beside it: written and removed with it.

use crate::error::CliError;
use asm_proto::error::EXIT_FAILURE;
use clap::{Args, Subcommand};
use serde_json::json;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// The skill, as shipped with this CLI version.
pub const SKILL: &str = include_str!("../../../skill/asm/SKILL.md");
/// Setup and troubleshooting guide the skill refers to, installed beside it.
pub const SETUP: &str = include_str!("../../../skill/asm/SETUP.md");

const VERSION: &str = env!("CARGO_PKG_VERSION");
const MANAGED_KEY: &str = "installed-by";
const MANAGED_VALUE: &str = "asm";
const VERSION_KEY: &str = "asm-version";
const SKILL_DIR: &str = "asm";
const SKILL_FILE: &str = "SKILL.md";
const SETUP_FILE: &str = "SETUP.md";

#[derive(Subcommand)]
pub enum SkillCommand {
    /// Install or update the asm skill in agents' skill folders (<DIR>/asm/SKILL.md).
    Install {
        #[command(flatten)]
        dirs: DirArgs,
        /// Replace a skill not installed by asm, or an `asm` symlink, with asm's copy.
        #[arg(long, conflicts_with = "print")]
        force: bool,
        /// Print the embedded SKILL.md to stdout instead of installing it.
        #[arg(long, conflicts_with_all = ["dir", "print_setup"])]
        print: bool,
        /// Print the embedded SETUP.md (setup and troubleshooting) instead of installing.
        #[arg(long, conflicts_with_all = ["dir", "force"])]
        print_setup: bool,
    },
    /// Remove the asm skill from skill folders (only files installed by asm).
    Uninstall {
        #[command(flatten)]
        dirs: DirArgs,
    },
    /// Show whether each skill folder has the current asm skill.
    Status {
        #[command(flatten)]
        dirs: DirArgs,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Args)]
pub struct DirArgs {
    /// Skill folder; repeatable (default: ~/.agents/skills).
    #[arg(long, value_name = "DIR")]
    dir: Vec<PathBuf>,
}

impl DirArgs {
    fn resolve(self) -> Result<Vec<PathBuf>, CliError> {
        if !self.dir.is_empty() {
            return Ok(self.dir);
        }
        Ok(vec![
            crate::state::home_dir()?.join(".agents").join("skills"),
        ])
    }
}

pub fn run(cmd: SkillCommand) -> Result<(), CliError> {
    match cmd {
        SkillCommand::Install { print: true, .. } => {
            print!("{SKILL}");
            Ok(())
        }
        SkillCommand::Install { print_setup: true, .. } => {
            print!("{SETUP}");
            Ok(())
        }
        SkillCommand::Install { dirs, force, .. } => {
            let mut failed = false;
            for dir in dirs.resolve()? {
                match install(&dir, force) {
                    Ok((outcome, path)) => println!("{}: {}", outcome.label(), path.display()),
                    Err(message) => {
                        eprintln!("{message}");
                        failed = true;
                    }
                }
            }
            exit_status(failed)
        }
        SkillCommand::Uninstall { dirs } => {
            let mut failed = false;
            for dir in dirs.resolve()? {
                match uninstall(&dir) {
                    Ok(Removal::Removed(path)) => println!("removed: {}", path.display()),
                    Ok(Removal::NotInstalled(path)) => {
                        println!("not installed: {}", path.display())
                    }
                    Ok(Removal::LeftAlone(path, state)) => println!(
                        "left alone ({}, not installed by asm): {}",
                        state.label(),
                        path.display()
                    ),
                    Err(message) => {
                        eprintln!("{message}");
                        failed = true;
                    }
                }
            }
            exit_status(failed)
        }
        SkillCommand::Status { dirs, json } => {
            let dirs = dirs.resolve()?;
            let states: Vec<_> = dirs.iter().map(|d| (d, status(d))).collect();
            if json {
                let entries: Vec<_> = states
                    .iter()
                    .map(|(dir, (state, installed))| {
                        json!({
                            "dir": dir,
                            "path": skill_path(dir),
                            "status": state.key(),
                            "installed_version": installed,
                        })
                    })
                    .collect();
                let j = json!({"version": VERSION, "dirs": entries});
                println!("{}", serde_json::to_string_pretty(&j).expect("serializes"));
            } else {
                for (dir, (state, installed)) in &states {
                    let path = skill_path(dir);
                    match (state, installed) {
                        (State::Current | State::Outdated, v) => println!(
                            "{}: {} (asm-version {})",
                            state.label(),
                            path.display(),
                            v.as_deref().unwrap_or("unknown")
                        ),
                        _ => println!("{}: {}", state.label(), path.display()),
                    }
                }
            }
            Ok(())
        }
    }
}

fn exit_status(failed: bool) -> Result<(), CliError> {
    if failed {
        Err(CliError::new(EXIT_FAILURE, ""))
    } else {
        Ok(())
    }
}

fn skill_path(dir: &Path) -> PathBuf {
    dir.join(SKILL_DIR).join(SKILL_FILE)
}

/// The embedded skill with the asm metadata added at the end of its frontmatter, so `name`
/// and `description` stay first.
fn render(version: &str) -> String {
    let metadata =
        format!("metadata:\n  {MANAGED_KEY}: {MANAGED_VALUE}\n  {VERSION_KEY}: \"{version}\"\n");
    match frontmatter(SKILL) {
        Some((_, end)) => format!("{}{metadata}{}", &SKILL[..end], &SKILL[end..]),
        None => format!("---\n{metadata}---\n\n{SKILL}"),
    }
}

/// Byte range of the frontmatter's lines: after the opening `---` line, up to the start of
/// the closing `---` line.
fn frontmatter(content: &str) -> Option<(usize, usize)> {
    let mut lines = content.split_inclusive('\n');
    let first = lines.next()?;
    if first.trim_end() != "---" {
        return None;
    }
    let start = first.len();
    let mut offset = start;
    for line in lines {
        if line.trim_end() == "---" {
            return Some((start, offset));
        }
        offset += line.len();
    }
    None
}

/// `key: value` of a frontmatter line, the value without surrounding quotes.
fn key_value(line: &str) -> Option<(&str, &str)> {
    let (key, value) = line.split_once(':')?;
    let value = value.trim();
    let value = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
        .unwrap_or(value);
    Some((key.trim(), value))
}

/// When `content` was installed by asm: `Some(asm-version)`, the version when recorded.
fn managed(content: &str) -> Option<Option<String>> {
    let (start, end) = frontmatter(content)?;
    let mut is_managed = false;
    let mut version = None;
    for line in content[start..end].lines() {
        match key_value(line) {
            Some((MANAGED_KEY, MANAGED_VALUE)) => is_managed = true,
            Some((VERSION_KEY, v)) => version = Some(v.to_string()),
            _ => {}
        }
    }
    is_managed.then_some(version)
}

/// `content` with the frontmatter's `asm-version` value removed.
fn normalized(content: &str) -> String {
    let Some((start, end)) = frontmatter(content) else {
        return content.to_string();
    };
    let mut out = String::with_capacity(content.len());
    out.push_str(&content[..start]);
    for line in content[start..end].split_inclusive('\n') {
        match key_value(line) {
            Some((VERSION_KEY, _)) => {
                let indent = &line[..line.len() - line.trim_start().len()];
                out.push_str(&format!("{indent}{VERSION_KEY}:\n"));
            }
            _ => out.push_str(line),
        }
    }
    out.push_str(&content[end..]);
    out
}

/// How an asm-managed file compares with this CLI's skill.
fn compare(content: &str, version: Option<&str>) -> Outcome {
    if normalized(content) != normalized(&SKILL_RENDERED) {
        Outcome::Updated
    } else if version != Some(VERSION) {
        Outcome::VersionOnly
    } else {
        Outcome::UpToDate
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Current,
    Outdated,
    Foreign,
    Symlink,
    Missing,
}

impl State {
    fn label(self) -> &'static str {
        match self {
            State::Current => "installed (current)",
            State::Outdated => "installed (outdated)",
            State::Foreign => "foreign",
            State::Symlink => "symlink",
            State::Missing => "missing",
        }
    }
    fn key(self) -> &'static str {
        match self {
            State::Current => "current",
            State::Outdated => "outdated",
            State::Foreign => "foreign",
            State::Symlink => "symlink",
            State::Missing => "missing",
        }
    }
}

/// What lies at `<dir>/asm` and `<dir>/asm/SKILL.md`, without following symlinks there.
enum Found {
    /// `<dir>/asm` does not exist.
    NoDir,
    /// `<dir>/asm` is a symlink.
    DirSymlink,
    /// `<dir>/asm` is something other than a directory.
    DirNotDir,
    /// `<dir>/asm` is a directory without SKILL.md.
    NoFile,
    /// SKILL.md is a symlink.
    FileSymlink,
    /// SKILL.md is something other than a regular file.
    FileNotFile,
    /// SKILL.md is a regular file with this content (lossy UTF-8).
    File(String),
}

fn inspect(dir: &Path) -> Result<Found, String> {
    let sub = dir.join(SKILL_DIR);
    match fs::symlink_metadata(&sub) {
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Found::NoDir),
        Err(e) => return Err(io_message("inspecting", &sub, &e)),
        Ok(m) if m.file_type().is_symlink() => return Ok(Found::DirSymlink),
        Ok(m) if !m.is_dir() => return Ok(Found::DirNotDir),
        Ok(_) => {}
    }
    let path = sub.join(SKILL_FILE);
    match fs::symlink_metadata(&path) {
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Found::NoFile),
        Err(e) => return Err(io_message("inspecting", &path, &e)),
        Ok(m) if m.file_type().is_symlink() => return Ok(Found::FileSymlink),
        Ok(m) if !m.is_file() => return Ok(Found::FileNotFile),
        Ok(_) => {}
    }
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|e| io_message("reading", &path, &e))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| io_message("reading", &path, &e))?;
    Ok(Found::File(String::from_utf8_lossy(&bytes).into_owned()))
}

/// The state of the skill in `dir` and the asm version that installed it.
pub fn status(dir: &Path) -> (State, Option<String>) {
    match inspect(dir) {
        Ok(Found::NoDir | Found::NoFile) => (State::Missing, None),
        Ok(Found::DirSymlink | Found::FileSymlink) => (State::Symlink, None),
        Ok(Found::DirNotDir | Found::FileNotFile) | Err(_) => (State::Foreign, None),
        Ok(Found::File(content)) => match managed(&content) {
            None => (State::Foreign, None),
            Some(version) => {
                let state = match compare(&content, version.as_deref()) {
                    Outcome::UpToDate if setup_current(&dir.join(SKILL_DIR)) => State::Current,
                    _ => State::Outdated,
                };
                (state, version)
            }
        },
    }
}

/// Whether `<sub>/SETUP.md` is a regular file with this CLI's guide.
fn setup_current(sub: &Path) -> bool {
    let path = sub.join(SETUP_FILE);
    fs::symlink_metadata(&path).is_ok_and(|m| m.is_file())
        && fs::read(&path).is_ok_and(|bytes| bytes == SETUP.as_bytes())
}

static SKILL_RENDERED: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| render(VERSION));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Installed,
    /// The skill text differed.
    Updated,
    /// Only `asm-version` differed.
    VersionOnly,
    UpToDate,
}

impl Outcome {
    fn label(self) -> &'static str {
        match self {
            Outcome::Installed => "installed",
            Outcome::Updated => "updated",
            Outcome::VersionOnly => "updated (asm-version only)",
            Outcome::UpToDate => "up to date",
        }
    }
}

/// Installs the skill into `dir`; the error is the message for stderr.
pub fn install(dir: &Path, force: bool) -> Result<(Outcome, PathBuf), String> {
    let sub = dir.join(SKILL_DIR);
    let path = sub.join(SKILL_FILE);
    let refuse = |what: String| {
        Err(format!(
            "refused: {what}; use --force to replace it with asm's skill"
        ))
    };
    let outcome = match inspect(dir)? {
        Found::File(content) => match managed(&content) {
            Some(version) => match compare(&content, version.as_deref()) {
                Outcome::UpToDate if setup_current(&sub) => return Ok((Outcome::UpToDate, path)),
                Outcome::UpToDate => Outcome::Updated,
                outcome => outcome,
            },
            None if force => Outcome::Updated,
            None => {
                return refuse(format!(
                    "{} exists and was not installed by asm",
                    path.display()
                ));
            }
        },
        Found::FileSymlink if force => Outcome::Updated,
        Found::FileSymlink => {
            return refuse(format!("{} is a symlink", path.display()));
        }
        Found::FileNotFile => {
            return Err(format!(
                "error: {} is not a regular file; remove it first",
                path.display()
            ));
        }
        Found::NoFile => Outcome::Installed,
        Found::DirSymlink | Found::DirNotDir if !force => {
            let what = match fs::read_link(&sub) {
                Ok(target) => format!("{} is a symlink to {}", sub.display(), target.display()),
                Err(_) => format!("{} is not a directory", sub.display()),
            };
            return refuse(what);
        }
        Found::DirSymlink | Found::DirNotDir => {
            // Removes the link itself (or the file), never what a link points to.
            fs::remove_file(&sub).map_err(|e| io_message("removing", &sub, &e))?;
            make_skill_dir(dir, &sub)?;
            Outcome::Installed
        }
        Found::NoDir => {
            make_skill_dir(dir, &sub)?;
            Outcome::Installed
        }
    };
    write_atomic(&sub, &path, SKILL_RENDERED.as_bytes())?;
    if setup_current(&sub) {
        return Ok((outcome, path));
    }
    write_atomic(&sub, &sub.join(SETUP_FILE), SETUP.as_bytes())?;
    // A changed guide is a content update, not a version-only one.
    let outcome = if outcome == Outcome::VersionOnly { Outcome::Updated } else { outcome };
    Ok((outcome, path))
}

fn make_skill_dir(dir: &Path, sub: &Path) -> Result<(), String> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(dir)
        .map_err(|e| io_message("creating", dir, &e))?;
    match fs::DirBuilder::new().mode(0o755).create(sub) {
        Ok(()) => fs::set_permissions(sub, fs::Permissions::from_mode(0o755))
            .map_err(|e| io_message("setting permissions on", sub, &e)),
        Err(e) => Err(io_message("creating", sub, &e)),
    }
}

/// Writes `bytes` to a new 0644 file in `sub` (`O_EXCL|O_NOFOLLOW`) and renames it over
/// `path`; `sub` must still be a real directory.
fn write_atomic(sub: &Path, path: &Path, bytes: &[u8]) -> Result<(), String> {
    match fs::symlink_metadata(sub) {
        Ok(m) if m.is_dir() => {}
        Ok(_) => return Err(format!("error: {} is no longer a directory", sub.display())),
        Err(e) => return Err(io_message("inspecting", sub, &e)),
    }
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let tmp = sub.join(format!(".{name}.{}.tmp", std::process::id()));
    let result = (|| {
        let _ = fs::remove_file(&tmp);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)?;
        file.set_permissions(fs::Permissions::from_mode(0o644))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&tmp, path)
    })();
    result.map_err(|e| {
        let _ = fs::remove_file(&tmp);
        io_message("writing", path, &e)
    })
}

pub enum Removal {
    Removed(PathBuf),
    NotInstalled(PathBuf),
    LeftAlone(PathBuf, State),
}

/// Removes an asm-installed skill from `dir`, then `<dir>/asm` when empty.
pub fn uninstall(dir: &Path) -> Result<Removal, String> {
    let sub = dir.join(SKILL_DIR);
    let path = sub.join(SKILL_FILE);
    match inspect(dir)? {
        Found::NoDir | Found::NoFile => Ok(Removal::NotInstalled(path)),
        Found::DirSymlink => Ok(Removal::LeftAlone(sub, State::Symlink)),
        Found::FileSymlink => Ok(Removal::LeftAlone(path, State::Symlink)),
        Found::DirNotDir => Ok(Removal::LeftAlone(sub, State::Foreign)),
        Found::FileNotFile => Ok(Removal::LeftAlone(path, State::Foreign)),
        Found::File(content) if managed(&content).is_none() => {
            Ok(Removal::LeftAlone(path, State::Foreign))
        }
        Found::File(_) => {
            fs::remove_file(&path).map_err(|e| io_message("removing", &path, &e))?;
            // SETUP.md belongs to the asm-installed SKILL.md; a symlink there is removed,
            // never what it points to.
            let setup = sub.join(SETUP_FILE);
            match fs::remove_file(&setup) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(io_message("removing", &setup, &e)),
            }
            // Only an empty directory goes; anything the user put beside SKILL.md stays.
            let _ = fs::remove_dir(&sub);
            Ok(Removal::Removed(path))
        }
    }
}

fn io_message(action: &str, path: &Path, e: &std::io::Error) -> String {
    format!("error: {action} {}: {e}", path.display())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn read(dir: &Path) -> String {
        fs::read_to_string(skill_path(dir)).unwrap()
    }

    #[test]
    fn metadata_ends_frontmatter() {
        assert!(
            frontmatter(SKILL)
                .is_some_and(|(s, e)| !SKILL[s..e].lines().any(|l| l.starts_with("metadata:"))),
            "SKILL.md needs frontmatter without its own metadata map"
        );
        let rendered = render("1.2.3");
        assert!(rendered.starts_with("---\nname: asm\ndescription: "));
        let (start, end) = frontmatter(&rendered).unwrap();
        assert!(
            rendered[start..end]
                .ends_with("metadata:\n  installed-by: asm\n  asm-version: \"1.2.3\"\n")
        );
        assert_eq!(managed(&rendered), Some(Some("1.2.3".to_string())));
        assert_eq!(managed(SKILL), None);
        let body = |s: &str| s[frontmatter(s).unwrap().1..].to_string();
        assert_eq!(body(&rendered), body(SKILL));
    }

    #[test]
    fn marker_detection() {
        let flat = "---\nname: asm\ninstalled-by: 'asm'\nasm-version: 0.1.0\n---\nbody\n";
        assert_eq!(managed(flat), Some(Some("0.1.0".into())));
        assert_eq!(
            managed("---\nname: asm\ninstalled-by: asm\n---\n"),
            Some(None)
        );
        assert_eq!(
            managed("---\nname: asm\n---\ninstalled-by: asm\n"),
            None,
            "body ignored"
        );
        assert_eq!(managed("installed-by: asm\n"), None);
        assert_eq!(managed("---\ninstalled-by: someone\n---\n"), None);
    }

    #[test]
    fn version_is_normalised() {
        assert_eq!(normalized(&render("0.0.1")), normalized(&render(VERSION)));
        assert_ne!(
            normalized(&render("0.0.1")),
            normalized(&format!("{}x", render(VERSION)))
        );
        assert_eq!(compare(&render(VERSION), Some(VERSION)), Outcome::UpToDate);
        assert_eq!(
            compare(&render("0.0.1"), Some("0.0.1")),
            Outcome::VersionOnly
        );
        let changed = format!("{}x", render(VERSION));
        assert_eq!(compare(&changed, Some(VERSION)), Outcome::Updated);
    }

    #[test]
    fn fresh_install_then_up_to_date() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("skills");
        assert_eq!(status(&dir).0, State::Missing);
        assert_eq!(install(&dir, false).unwrap().0, Outcome::Installed);
        assert_eq!(read(&dir), *SKILL_RENDERED);
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir.join("asm")), 0o755);
        assert_eq!(mode(&skill_path(&dir)), 0o644);
        assert_eq!(fs::read_to_string(dir.join("asm/SETUP.md")).unwrap(), SETUP);
        assert_eq!(mode(&dir.join("asm/SETUP.md")), 0o644);
        assert_eq!(status(&dir), (State::Current, Some(VERSION.to_string())));
        assert_eq!(install(&dir, false).unwrap().0, Outcome::UpToDate);
    }

    #[test]
    fn setup_guide_follows_the_skill() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path();
        install(dir, false).unwrap();
        let setup = dir.join("asm/SETUP.md");
        fs::write(&setup, "edited\n").unwrap();
        assert_eq!(status(dir).0, State::Outdated, "a changed guide is outdated");
        assert_eq!(install(dir, false).unwrap().0, Outcome::Updated);
        assert_eq!(fs::read_to_string(&setup).unwrap(), SETUP);
        fs::remove_file(&setup).unwrap();
        assert_eq!(status(dir).0, State::Outdated, "a missing guide is outdated");
        assert_eq!(install(dir, false).unwrap().0, Outcome::Updated);
        assert!(matches!(uninstall(dir).unwrap(), Removal::Removed(_)));
        assert!(!dir.join("asm").exists(), "the guide goes with the skill");
    }

    #[test]
    fn other_version_with_same_text_gets_new_version() {
        let t = tempfile::tempdir().unwrap();
        fs::create_dir(t.path().join("asm")).unwrap();
        fs::write(skill_path(t.path()), render("0.0.1")).unwrap();
        fs::write(t.path().join("asm/SETUP.md"), SETUP).unwrap();
        assert_eq!(status(t.path()), (State::Outdated, Some("0.0.1".into())));
        assert_eq!(install(t.path(), false).unwrap().0, Outcome::VersionOnly);
        assert_eq!(read(t.path()), *SKILL_RENDERED);
        assert_eq!(status(t.path()).0, State::Current);
    }

    #[test]
    fn outdated_is_updated() {
        let t = tempfile::tempdir().unwrap();
        fs::create_dir(t.path().join("asm")).unwrap();
        fs::write(
            skill_path(t.path()),
            format!("{}old text\n", render("0.0.1")),
        )
        .unwrap();
        assert_eq!(status(t.path()).0, State::Outdated);
        assert_eq!(install(t.path(), false).unwrap().0, Outcome::Updated);
        assert_eq!(read(t.path()), *SKILL_RENDERED);
    }

    #[test]
    fn foreign_file_refused_unless_forced() {
        let t = tempfile::tempdir().unwrap();
        fs::create_dir(t.path().join("asm")).unwrap();
        fs::write(skill_path(t.path()), "my own notes\n").unwrap();
        assert_eq!(status(t.path()).0, State::Foreign);
        let err = install(t.path(), false).unwrap_err();
        assert!(
            err.contains("not installed by asm") && err.contains("--force"),
            "{err}"
        );
        assert_eq!(read(t.path()), "my own notes\n");
        assert!(matches!(
            uninstall(t.path()),
            Ok(Removal::LeftAlone(_, State::Foreign))
        ));
        assert_eq!(read(t.path()), "my own notes\n");
        assert_eq!(install(t.path(), true).unwrap().0, Outcome::Updated);
        assert_eq!(read(t.path()), *SKILL_RENDERED);
    }

    #[test]
    fn symlinked_dir_refused_unless_forced() {
        let t = tempfile::tempdir().unwrap();
        let target = t.path().join("share/asm");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join(SKILL_FILE), "packaged\n").unwrap();
        let dir = t.path().join("skills");
        fs::create_dir(&dir).unwrap();
        symlink(&target, dir.join("asm")).unwrap();
        assert_eq!(status(&dir).0, State::Symlink);
        let err = install(&dir, false).unwrap_err();
        assert!(err.contains("is a symlink to"), "{err}");
        assert!(matches!(
            uninstall(&dir),
            Ok(Removal::LeftAlone(_, State::Symlink))
        ));
        assert_eq!(install(&dir, true).unwrap().0, Outcome::Installed);
        assert!(fs::symlink_metadata(dir.join("asm")).unwrap().is_dir());
        assert_eq!(read(&dir), *SKILL_RENDERED);
        assert_eq!(
            fs::read_to_string(target.join(SKILL_FILE)).unwrap(),
            "packaged\n",
            "the link target is untouched"
        );
    }

    #[test]
    fn symlinked_file_refused_unless_forced() {
        let t = tempfile::tempdir().unwrap();
        let outside = t.path().join("outside.md");
        fs::write(&outside, render("0.0.1")).unwrap();
        fs::create_dir(t.path().join("asm")).unwrap();
        symlink(&outside, skill_path(t.path())).unwrap();
        assert_eq!(status(t.path()).0, State::Symlink);
        assert!(
            install(t.path(), false)
                .unwrap_err()
                .contains("is a symlink")
        );
        assert_eq!(install(t.path(), true).unwrap().0, Outcome::Updated);
        assert!(
            fs::symlink_metadata(skill_path(t.path()))
                .unwrap()
                .is_file()
        );
        assert_eq!(fs::read_to_string(&outside).unwrap(), render("0.0.1"));
    }

    #[test]
    fn uninstall_is_idempotent() {
        let t = tempfile::tempdir().unwrap();
        install(t.path(), false).unwrap();
        assert!(matches!(uninstall(t.path()), Ok(Removal::Removed(_))));
        assert!(!t.path().join("asm").exists(), "empty asm dir removed");
        assert!(matches!(uninstall(t.path()), Ok(Removal::NotInstalled(_))));
    }

    #[test]
    fn uninstall_keeps_dir_with_other_files() {
        let t = tempfile::tempdir().unwrap();
        install(t.path(), false).unwrap();
        fs::write(t.path().join("asm/notes.txt"), "mine").unwrap();
        assert!(matches!(uninstall(t.path()), Ok(Removal::Removed(_))));
        assert!(t.path().join("asm/notes.txt").exists());
    }
}
