//! Runs `asm skill install|uninstall|status` in a temporary HOME.

use serde_json::Value;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

const SKILL: &str = include_str!("../../../skill/asm/SKILL.md");

fn asm(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_asm"))
        .args(args)
        .env_clear()
        .env("HOME", home)
        .output()
        .unwrap()
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn default_skill(home: &Path) -> PathBuf {
    home.join(".agents/skills/asm/SKILL.md")
}

#[test]
fn fresh_install_then_up_to_date_without_write() {
    let home = tempfile::tempdir().unwrap();
    let path = default_skill(home.path());

    let o = asm(home.path(), &["skill", "status"]);
    assert_eq!(out(&o), format!("missing: {}\n", path.display()));

    let o = asm(home.path(), &["skill", "install"]);
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(out(&o), format!("installed: {}\n", path.display()));
    let content = fs::read_to_string(&path).unwrap();
    assert!(
        content.starts_with("---\nname: asm\ndescription: "),
        "name and description first"
    );
    let frontmatter = content.split("\n---\n").next().unwrap();
    assert!(frontmatter.ends_with(&format!(
        "\nmetadata:\n  installed-by: asm\n  asm-version: \"{}\"",
        env!("CARGO_PKG_VERSION")
    )));
    let before = fs::metadata(&path).unwrap().modified().unwrap();

    std::thread::sleep(Duration::from_millis(20));
    let o = asm(home.path(), &["skill", "install"]);
    assert!(o.status.success());
    assert_eq!(out(&o), format!("up to date: {}\n", path.display()));
    assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), before);

    let o = asm(home.path(), &["skill", "status", "--json"]);
    let j: Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(j["dirs"][0]["status"], "current");
    assert_eq!(j["dirs"][0]["installed_version"], env!("CARGO_PKG_VERSION"));
}

#[test]
fn outdated_marker_file_is_updated() {
    let home = tempfile::tempdir().unwrap();
    let path = default_skill(home.path());
    assert!(asm(home.path(), &["skill", "install"]).status.success());
    let current = fs::read_to_string(&path).unwrap();
    let version_line = format!("asm-version: \"{}\"", env!("CARGO_PKG_VERSION"));
    let old_version = current.replace(&version_line, "asm-version: \"0.0.1\"");

    // Same text, older version: rewritten so the recorded version stays accurate.
    fs::write(&path, &old_version).unwrap();
    let o = asm(home.path(), &["skill", "status"]);
    assert_eq!(
        out(&o),
        format!(
            "installed (outdated): {} (asm-version 0.0.1)\n",
            path.display()
        )
    );
    let o = asm(home.path(), &["skill", "install"]);
    assert!(o.status.success());
    assert_eq!(
        out(&o),
        format!("updated (asm-version only): {}\n", path.display())
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), current);

    // Different text.
    fs::write(&path, format!("{old_version}\nan older paragraph\n")).unwrap();
    let o = asm(home.path(), &["skill", "install"]);
    assert!(o.status.success());
    assert_eq!(out(&o), format!("updated: {}\n", path.display()));
    assert_eq!(fs::read_to_string(&path).unwrap(), current);
    let o = asm(home.path(), &["skill", "status"]);
    assert_eq!(
        out(&o),
        format!(
            "installed (current): {} (asm-version {})\n",
            path.display(),
            env!("CARGO_PKG_VERSION")
        )
    );
}

#[test]
fn foreign_file_refused_then_forced() {
    let home = tempfile::tempdir().unwrap();
    let path = default_skill(home.path());
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, "---\nname: asm\n---\nmine\n").unwrap();

    let o = asm(home.path(), &["skill", "status"]);
    assert_eq!(out(&o), format!("foreign: {}\n", path.display()));
    let o = asm(home.path(), &["skill", "install"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(err(&o).contains("not installed by asm"), "{}", err(&o));
    assert!(err(&o).contains("--force"));
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        "---\nname: asm\n---\nmine\n"
    );

    let o = asm(home.path(), &["skill", "uninstall"]);
    assert!(o.status.success());
    assert!(out(&o).starts_with("left alone (foreign"), "{}", out(&o));
    assert!(path.exists());

    let o = asm(home.path(), &["skill", "install", "--force"]);
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(out(&o), format!("updated: {}\n", path.display()));
    assert!(
        fs::read_to_string(&path)
            .unwrap()
            .contains("\n  installed-by: asm\n")
    );
}

#[test]
fn symlinked_dir_refused_then_forced() {
    let home = tempfile::tempdir().unwrap();
    let share = home.path().join("share/asm/skill/asm");
    fs::create_dir_all(&share).unwrap();
    fs::write(share.join("SKILL.md"), SKILL).unwrap();
    let skills = home.path().join(".agents/skills");
    fs::create_dir_all(&skills).unwrap();
    symlink(&share, skills.join("asm")).unwrap();

    let o = asm(home.path(), &["skill", "status"]);
    assert!(out(&o).starts_with("symlink: "), "{}", out(&o));
    let o = asm(home.path(), &["skill", "install"]);
    assert_eq!(o.status.code(), Some(1));
    assert!(err(&o).contains("is a symlink to"), "{}", err(&o));

    let o = asm(home.path(), &["skill", "install", "--force"]);
    assert!(o.status.success(), "{}", err(&o));
    assert!(fs::symlink_metadata(skills.join("asm")).unwrap().is_dir());
    assert_eq!(fs::read_to_string(share.join("SKILL.md")).unwrap(), SKILL);
    let o = asm(home.path(), &["skill", "status"]);
    assert!(out(&o).starts_with("installed (current): "), "{}", out(&o));
}

#[test]
fn uninstall_is_idempotent() {
    let home = tempfile::tempdir().unwrap();
    let path = default_skill(home.path());
    assert!(asm(home.path(), &["skill", "install"]).status.success());

    let o = asm(home.path(), &["skill", "uninstall"]);
    assert!(o.status.success());
    assert_eq!(out(&o), format!("removed: {}\n", path.display()));
    assert!(!path.parent().unwrap().exists());

    let o = asm(home.path(), &["skill", "uninstall"]);
    assert!(o.status.success());
    assert_eq!(out(&o), format!("not installed: {}\n", path.display()));
}

#[test]
fn multiple_dirs() {
    let home = tempfile::tempdir().unwrap();
    let a = home.path().join("a");
    let b = home.path().join("deep/b");
    fs::create_dir_all(a.join("asm")).unwrap();
    fs::write(a.join("asm/SKILL.md"), "mine\n").unwrap();
    let (a_s, b_s) = (a.to_str().unwrap(), b.to_str().unwrap());

    // One refusal does not stop the other directory; the exit reports it.
    let o = asm(
        home.path(),
        &["skill", "install", "--dir", a_s, "--dir", b_s],
    );
    assert_eq!(o.status.code(), Some(1));
    assert_eq!(
        out(&o),
        format!("installed: {}/asm/SKILL.md\n", b.display())
    );
    assert!(err(&o).contains(&format!("{}/asm/SKILL.md", a.display())));
    assert!(
        !default_skill(home.path()).exists(),
        "default dir untouched"
    );

    let o = asm(
        home.path(),
        &["skill", "status", "--dir", a_s, "--dir", b_s],
    );
    assert!(o.status.success());
    assert_eq!(
        out(&o),
        format!(
            "foreign: {}/asm/SKILL.md\ninstalled (current): {}/asm/SKILL.md (asm-version {})\n",
            a.display(),
            b.display(),
            env!("CARGO_PKG_VERSION")
        )
    );

    let o = asm(
        home.path(),
        &["skill", "uninstall", "--dir", a_s, "--dir", b_s],
    );
    assert!(o.status.success());
    assert_eq!(
        fs::read_to_string(a.join("asm/SKILL.md")).unwrap(),
        "mine\n"
    );
    assert!(!b.join("asm").exists());
}

#[test]
fn print_outputs_embedded_skill() {
    let home = tempfile::tempdir().unwrap();
    let o = asm(home.path(), &["skill", "install", "--print"]);
    assert!(o.status.success());
    assert_eq!(out(&o), SKILL);
    assert!(!home.path().join(".agents").exists());
}
