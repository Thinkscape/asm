use super::*;

const SLEEPER_ENV: &str = "ASM_TEST_SLEEPER";

/// The body of [`named_process`] when this binary runs as one; otherwise nothing.
#[test]
fn sleeper_process() {
    if std::env::var_os(SLEEPER_ENV).is_some() {
        std::thread::sleep(Duration::from_secs(60));
    }
}

/// A long-running process whose process name is `name`, with `args`: this test binary
/// under another name (macOS kills copies of system binaries).
fn named_process(dir: &Path, name: &str, args: &[String]) -> Child {
    let exe = dir.join(name);
    let this = std::env::current_exe().unwrap();
    if std::fs::hard_link(&this, &exe).is_err() {
        std::fs::copy(&this, &exe).unwrap();
    }
    // Arguments after `--` are test name filters that match nothing.
    Command::new(&exe).args(["--exact", "broker::tests::sleeper_process", "--"]).args(args)
        .env(SLEEPER_ENV, "1")
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
        .process_group(0).spawn().unwrap()
}

fn alive(child: &mut Child) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().unwrap().is_some() {
            return false;
        }
        if Instant::now() >= deadline {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn startup_cleanup_kills_only_the_broker_chrome_and_deletes_every_profile() {
    let tmp = tempfile::tempdir().unwrap();
    let bin = tmp.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let root = tmp.path().join("broker");
    std::fs::create_dir(&root).unwrap();

    // The Chrome of a crashed session: named like Chrome and running on its profile.
    let leftover = root.join("request-a");
    std::fs::create_dir(&leftover).unwrap();
    let mut chrome = named_process(&bin, "Chromium", &[format!("--user-data-dir={}", leftover.display())]);
    std::fs::write(leftover.join(PID_FILE), format!("{}\n", chrome.id())).unwrap();
    // A reused pid: a Chrome on another profile (the operator's own browser, say).
    let reused = root.join("request-b");
    std::fs::create_dir(&reused).unwrap();
    let mut other_chrome = named_process(&bin, "Google Chrome", &["--user-data-dir=/elsewhere".into()]);
    std::fs::write(reused.join(PID_FILE), format!("{}\n", other_chrome.id())).unwrap();
    // A reused pid of something that is not Chrome at all.
    let not_chrome = root.join("request-c");
    std::fs::create_dir(&not_chrome).unwrap();
    let mut shell = named_process(&bin, "worker", &[format!("--user-data-dir={}", not_chrome.display())]);
    std::fs::write(not_chrome.join(PID_FILE), format!("{}\n", shell.id())).unwrap();
    // No pid file, a stray file.
    std::fs::create_dir_all(root.join("request-d/Default")).unwrap();
    std::fs::write(root.join("stray"), "x").unwrap();

    cleanup_leftovers(&root);

    assert!(!alive(&mut chrome), "the leftover broker Chrome is killed");
    assert!(alive(&mut other_chrome), "a Chrome on another profile is left alone");
    assert!(alive(&mut shell), "a process that is not Chrome is left alone");
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0, "every old profile is deleted");
    for mut c in [other_chrome, shell] {
        let _ = c.kill();
        let _ = c.wait();
    }
}

#[test]
fn chrome_is_found_only_at_the_known_paths() {
    assert!(find_chrome().is_none_or(|p| CHROME_PATHS.iter().any(|c| Path::new(c) == p)));
}
