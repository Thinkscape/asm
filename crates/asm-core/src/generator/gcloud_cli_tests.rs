use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::thread;
use std::time::Instant;

const SDK_VERSION: &str = r#"{"Google Cloud SDK":"582.0.0","bq":"fixture"}"#;
const ADC: &str = r#"{"type":"authorized_user","client_id":"fixture-client","client_secret":"fixture-secret","refresh_token":"fixture-refresh","account":"discard@example.test","quota_project_id":"discard-me","universe_domain":"googleapis.com","rapt_token":"discard-this","token":"discard-this-too"}"#;
const PROJECTED_ADC: &str = r#"{"type":"authorized_user","client_id":"fixture-client","client_secret":"fixture-secret","refresh_token":"fixture-refresh"}"#;
const STORAGE_SCOPE: &str = "https://www.googleapis.com/auth/devstorage.read_only";

struct Fixture {
    root: tempfile::TempDir,
    runner: GcloudRunner,
    sdk: PathBuf,
}

impl Fixture {
    fn new(body: &str) -> Self {
        Self::with_script(&format!(
            "if [ \"$1\" = version ]; then printf '%s\\n' '{SDK_VERSION}'; exit; fi\n{body}",
        ))
    }

    fn with_script(body: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        let sdk = root.path().join("gcloud");
        fs::write(&sdk, format!("#!/bin/sh\nset -eu\n{body}\n")).unwrap();
        fs::set_permissions(&sdk, fs::Permissions::from_mode(0o700)).unwrap();
        let runner = GcloudRunner::new(root.path().join("operations")).unwrap();
        Self { root, runner, sdk }
    }

    fn assert_clean(&self) {
        assert_eq!(fs::read_dir(&self.runner.inner.root).unwrap().count(), 1);
    }
}

#[test]
fn projects_only_standard_authorized_user_fields() {
    let adc = AuthorizedUser::parse(ADC).unwrap();
    assert_eq!(adc.to_json().unwrap(), PROJECTED_ADC);
    assert!(!format!("{adc:?}").contains("fixture"));
    for invalid in [
        ADC.replace("authorized_user", "external_account"),
        ADC.replace("authorized_user", "service_account"),
        ADC.replace("fixture-secret", ""),
        ADC.replace("googleapis.com", "example.test"),
        ADC.replace('}', r#", "token_uri":"https://evil.example/token"}"#),
        ADC.replace('}', r#", "source_credentials":{}}"#),
        ADC.replace('}', r#", "private_key":"must-never-leak"}"#),
        ADC.replace('}', r#", "delegates":[]}"#),
        ADC.replace('}', r#", "credential_source":{"executable":{"command":"id"}}}"#),
        ADC.replace('}', r#", "service_account_impersonation_url":"https://evil.example"}"#),
        ADC.replace('}', r#", "client_secret":"duplicate"}"#),
        "x".repeat(ADC_LIMIT + 1),
    ] {
        let error = AuthorizedUser::parse(&invalid).unwrap_err();
        assert!(!error.to_string().contains("fixture"));
        assert!(!error.to_string().contains("must-never-leak"));
    }
}

#[test]
fn isolates_login_and_exactly_scoped_child_argv() {
    let fixture = Fixture::new(&format!(r#"
        [ "$1" = auth ] && [ "$2" = application-default ] || exit 12
        [ "$PWD" != "$HOME" ] && [ "$PWD" = "$TMPDIR" ] || exit 13
        [ "$CLOUDSDK_CONFIG" = "$PWD/config" ] || exit 14
        [ "$(stat -f '%Lp' "$PWD")" = 700 ] && [ "$(stat -f '%Lp' "$CLOUDSDK_CONFIG")" = 700 ] || exit 15
        [ "$(umask)" = 0077 ] || exit 16
        if read -r _; then exit 17; fi
        verb="$3"
        shift 3
        case "$verb" in
            login)
                [ "$*" = '--launch-browser --disable-quota-project --scopes=openid,https://www.googleapis.com/auth/userinfo.email,https://www.googleapis.com/auth/cloud-platform' ] || exit 18
                [ "${{GOOGLE_APPLICATION_CREDENTIALS+x}}" != x ] || exit 19
                printf '%s' '{ADC}' > "$CLOUDSDK_CONFIG/{ADC_NAME}"
                ;;
            print-access-token)
                [ "$GOOGLE_APPLICATION_CREDENTIALS" = "$PWD/{ADC_NAME}" ] || exit 20
                [ ! -e "$CLOUDSDK_CONFIG/{ADC_NAME}" ] || exit 21
                [ "$(stat -f '%Lp' "$GOOGLE_APPLICATION_CREDENTIALS")" = 600 ] || exit 22
                [ "$(cat "$GOOGLE_APPLICATION_CREDENTIALS")" = '{PROJECTED_ADC}' ] || exit 23
                case "$*" in
                    '--format=value(token) --quiet')
                        [ "${{GOOGLE_CLOUD_QUOTA_PROJECT+x}}" != x ] || exit 24
                        printf '%s\n' 'test-parent-token'
                        ;;
                    '--format=value(token) --quiet --impersonate-service-account=123456789 --scopes=https://www.googleapis.com/auth/devstorage.read_only,https://www.googleapis.com/auth/run.readonly --lifetime=3600s --project=scope-test')
                        [ "$GOOGLE_CLOUD_QUOTA_PROJECT" = scope-test ] || exit 25
                        printf '%s\n' 'test-child-token'
                        ;;
                    *) exit 26 ;;
                esac
                ;;
            *) exit 27 ;;
        esac
    "#));
    let (sdk, adc) = fixture.runner.login(&fixture.sdk, &AtomicBool::new(false)).unwrap();
    assert_eq!(sdk.path, fixture.sdk.canonicalize().unwrap());
    assert_eq!(sdk.version, "582.0.0");
    fixture.assert_clean();
    assert_eq!(fixture.runner.parent_token(&sdk.path, &adc).unwrap(), "test-parent-token");
    assert_eq!(fixture.runner.child_token(&sdk.path, &adc, "scope-test", "123456789", &[
        "https://www.googleapis.com/auth/run.readonly".into(), STORAGE_SCOPE.into(), STORAGE_SCOPE.into(),
    ]).unwrap(), "test-child-token");
    fixture.assert_clean();
}

#[test]
fn rejects_invalid_authority_before_running_any_command() {
    let fixture = Fixture::with_script(r#"touch "${0%/*}/spawned"; exit 99"#);
    let adc = AuthorizedUser::parse(ADC).unwrap();
    for scopes in [
        vec![],
        vec!["".to_owned()],
        vec![format!("{STORAGE_SCOPE},https://www.googleapis.com/auth/cloud-platform")],
        vec![format!("{STORAGE_SCOPE} ")],
        vec![format!("{STORAGE_SCOPE}^" )],
        vec!["https://www.googleapis.com/auth/".into()],
        vec!["http://www.googleapis.com/auth/devstorage.read_only".into()],
    ] {
        fixture.runner.child_token(&fixture.sdk, &adc, "scope-test", "1234", &scopes).unwrap_err();
    }
    fixture.runner.child_token(&fixture.sdk, &adc, "scope-test", "1234,5678", &[STORAGE_SCOPE.into()]).unwrap_err();
    fixture.runner.child_token(&fixture.sdk, &adc, "--project=wrong", "1234", &[STORAGE_SCOPE.into()]).unwrap_err();
    assert!(!fixture.root.path().join("spawned").exists());
    fixture.assert_clean();
}

#[test]
fn refuses_untrusted_downgraded_and_malformed_installations() {
    let fixture = Fixture::with_script(r#"printf '%s\n' '{"Google Cloud SDK":"581.0.0"}'"#);
    let error = fixture.runner.check_sdk(Some(&fixture.sdk)).unwrap_err();
    assert!(error.message.contains("582.0.0"));
    let path = fixture.root.path().join("not-gcloud");
    symlink(&fixture.sdk, &path).unwrap();
    assert!(fixture.runner.check_sdk(Some(&path)).is_err());
    assert!(fixture.runner.check_sdk(Some(Path::new("gcloud"))).is_err());
    fs::set_permissions(&fixture.sdk, fs::Permissions::from_mode(0o770)).unwrap();
    assert!(fixture.runner.check_sdk(Some(&fixture.sdk)).unwrap_err().message.contains("trusted"));

    let fixture = Fixture::with_script(r#"printf '%s\n' 'non-json diagnostic marker'"#);
    assert!(!fixture.runner.check_sdk(Some(&fixture.sdk)).unwrap_err().message.contains("diagnostic"));
    fs::set_permissions(fixture.root.path(), fs::Permissions::from_mode(0o770)).unwrap();
    let error = fixture.runner.check_sdk(Some(&fixture.sdk)).unwrap_err();
    fs::set_permissions(fixture.root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(error.message.contains("trusted"));
    fixture.assert_clean();
}

#[test]
fn rejects_writable_intermediate_symlink_chain_even_with_safe_final_sdk() {
    let fixture = Fixture::new("true");
    let safe = fixture.root.path().join("sdk");
    let writable = fixture.root.path().join("redirect");
    mkdir_private(&safe, false).unwrap();
    mkdir_private(&writable, false).unwrap();
    let sdk = safe.join("gcloud");
    fs::rename(&fixture.sdk, &sdk).unwrap();
    symlink(&safe, writable.join("jump")).unwrap();
    symlink(writable.join("jump/gcloud"), &fixture.sdk).unwrap();
    assert_eq!(fixture.runner.check_sdk(Some(&fixture.sdk)).unwrap().path, sdk.canonicalize().unwrap());
    fs::set_permissions(&writable, fs::Permissions::from_mode(0o770)).unwrap();
    assert!(fixture.runner.check_sdk(Some(&fixture.sdk)).unwrap_err().message.contains("trusted"));
    assert!(fixture.runner.check_sdk(Some(&sdk)).is_ok());
}

#[test]
fn maps_python_startup_failure_without_leaking_sdk_output() {
    let fixture = Fixture::with_script("printf '%s\\n' 'Install a compatible version of Python: fixture-only detail' >&2; exit 1");
    let error = fixture.runner.check_sdk(Some(&fixture.sdk)).unwrap_err();
    assert!(error.message.contains("python.org"));
    assert!(!error.message.contains("fixture-only"));
    fixture.assert_clean();
}

#[cfg(target_os = "macos")]
#[test]
fn uv_runtime_requires_a_trusted_versioned_install_under_the_managed_root() {
    let tmp = tempfile::tempdir().unwrap();
    let uv = tmp.path().join(".local/share/uv/python");
    let arch = std::env::consts::ARCH;
    let stable = uv.join(format!("cpython-3.11-macos-{arch}-none"));
    let version = uv.join(format!("cpython-3.11.16-macos-{arch}-none"));
    let python = version.join("bin/python3.11");
    fs::create_dir_all(python.parent().unwrap()).unwrap();
    fs::write(&python, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(&python, fs::Permissions::from_mode(0o700)).unwrap();
    symlink(&version, &stable).unwrap();
    assert_eq!(uv_python(tmp.path(), 11).unwrap(), python.canonicalize().unwrap());
    fs::set_permissions(&uv, fs::Permissions::from_mode(0o770)).unwrap();
    assert!(uv_python(tmp.path(), 11).is_none());
    fs::set_permissions(&uv, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_file(&stable).unwrap();
    let unrelated = tmp.path().join("unrelated/bin");
    fs::create_dir_all(&unrelated).unwrap();
    fs::rename(&python, unrelated.join("python3.11")).unwrap();
    symlink(unrelated.parent().unwrap(), &stable).unwrap();
    assert!(uv_python(tmp.path(), 11).is_none());
}

#[cfg(target_os = "macos")]
#[test]
fn refuses_write_acl_even_when_mode_is_private() {
    let fixture = Fixture::with_script(r#"touch "${0%/*}/spawned"; exit 99"#);
    assert!(Command::new("/bin/chmod")
        .args(["+a", "everyone allow write,delete"]).arg(&fixture.sdk).status().unwrap().success());
    assert!(fixture.runner.check_sdk(Some(&fixture.sdk)).unwrap_err().message.contains("trusted"));
    assert!(!fixture.root.path().join("spawned").exists());
}

#[test]
fn refuses_missing_explicit_adc_before_spawning_token_command() {
    let fixture = Fixture::with_script(r#"touch "${0%/*}/spawned"; exit 99"#);
    let operation = fixture.runner.operation(None).unwrap();
    let workspace = operation.workspace().unwrap();
    let config = workspace.config().unwrap();
    let adc = workspace.path.join(ADC_NAME);
    let err = operation.run(
        &fixture.sdk.canonicalize().unwrap(), &workspace, &config,
        &["auth", "application-default", "print-access-token"],
        Some(TokenInput { path: &adc, project: None }), SdkCall::Token,
    ).unwrap_err();
    assert!(err.message.contains("authorized-user"));
    assert!(!fixture.root.path().join("spawned").exists());
    drop(workspace);
    fixture.assert_clean();
}

#[test]
fn token_failures_are_redacted_and_never_fall_back_to_parent() {
    let fixture = Fixture::new(r#"
        printf '%s\n' test-parent-token
        printf '%s\n' 'iam denial with private diagnostic marker' >&2
        exit 1
    "#);
    let adc = AuthorizedUser::parse(ADC).unwrap();
    let err = fixture.runner.child_token(&fixture.sdk, &adc, "scope-test", "1234", &[STORAGE_SCOPE.into()]).unwrap_err();
    assert_eq!(err.code, asm_proto::error::ErrorCode::VaultUnavailable);
    assert!(!err.message.contains("diagnostic"));
    assert!(!err.message.contains("test-parent-token"));
    fixture.assert_clean();

    let fixture = Fixture::new(r#"printf 'invalid_grant: revoked (sensitive response)\n' >&2; exit 1"#);
    let err = fixture.runner.parent_token(&fixture.sdk, &adc).unwrap_err();
    assert_eq!(err.code, asm_proto::error::ErrorCode::Unauthorized);
    assert!(!err.message.contains("sensitive response"));
    fixture.assert_clean();

    let fixture = Fixture::new(r#"printf 'not a token\nactually private\n'"#);
    assert!(!fixture.runner.parent_token(&fixture.sdk, &adc).unwrap_err().message.contains("private"));
    fixture.assert_clean();
}

#[test]
fn strictly_limits_and_rejects_untrusted_login_files() {
    for body in [
        format!(r#"ln -s "${{0%/*}}/gcloud" "$CLOUDSDK_CONFIG/{ADC_NAME}""#),
        format!(r#"printf '%s' '{ADC}' > "$CLOUDSDK_CONFIG/{ADC_NAME}"; chmod 644 "$CLOUDSDK_CONFIG/{ADC_NAME}""#),
        format!(r#"/bin/dd if=/dev/zero of="$CLOUDSDK_CONFIG/{ADC_NAME}" bs=65536 count=17 2>/dev/null"#),
        format!(r#"mkfifo "$CLOUDSDK_CONFIG/{ADC_NAME}""#),
        "true".into(),
    ] {
        let fixture = Fixture::new(&body);
        assert!(fixture.runner.login(&fixture.sdk, &AtomicBool::new(false)).is_err());
        fixture.assert_clean();
    }
}

#[test]
fn bounds_both_output_streams_and_process_deadline() {
    for redirect in ["", " >&2"] {
        let fixture = Fixture::new(&format!(r#"/bin/dd if=/dev/zero bs=65536 count=2{redirect} 2>/dev/null"#));
        let err = fixture.runner.parent_token(&fixture.sdk, &AuthorizedUser::parse(ADC).unwrap()).unwrap_err();
        assert!(err.message.contains("size limit"));
        fixture.assert_clean();
    }
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "/bin/sleep 60 & wait"])
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).process_group(0);
    let child = command.spawn().unwrap();
    let pid = child.id() as libc::pid_t;
    let err = collect_output(child, Duration::from_millis(75), || Ok(()), &GCLOUD_OUTPUT).unwrap_err();
    assert!(err.message.contains("timed out"));
    assert_reaped(pid);
}

#[test]
fn cancellation_and_shutdown_reap_process_before_removing_workspace() {
    for shutdown in [false, true] {
        let fixture = Fixture::new(r#"
            printf '%s\n' "$$" > "${0%/*}/running"
            /bin/sleep 60 & wait
        "#);
        let runner = fixture.runner.clone();
        let sdk = fixture.sdk.clone();
        let flag = Arc::new(AtomicBool::new(false));
        let cancelled = flag.clone();
        let worker = thread::spawn(move || runner.login(&sdk, &cancelled));
        let start = Instant::now();
        let pid_path = fixture.root.path().join("running");
        let pid = loop {
            if let Ok(value) = fs::read_to_string(&pid_path) && let Ok(pid) = value.trim().parse() {
                break pid;
            }
            assert!(start.elapsed() < Duration::from_secs(5), "browser fixture never started");
            thread::sleep(Duration::from_millis(10));
        };
        if shutdown {
            fixture.runner.shutdown();
            fixture.assert_clean();
            assert!(fixture.runner.check_sdk(Some(&fixture.sdk)).is_err());
        } else {
            flag.store(true, Ordering::Release);
        }
        assert!(worker.join().unwrap().unwrap_err().message.contains("cancelled"));
        assert_reaped(pid);
        fixture.assert_clean();
    }
}

fn assert_reaped(pid: libc::pid_t) {
    // SAFETY: signal 0 only probes process existence.
    assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
}

#[test]
fn startup_only_reaps_unlocked_owned_workspaces() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("operations");
    let runner = GcloudRunner::new(root.clone()).unwrap();
    let active = Workspace::new(&runner.inner.root).unwrap();
    let abandoned = runner.inner.root.join("op-00000000000000000000000000000000");
    let elsewhere = tmp.path().join("elsewhere");
    let symlinked = runner.inner.root.join("op-ffffffffffffffffffffffffffffffff");
    mkdir_private(&abandoned, false).unwrap();
    mkdir_private(&elsewhere, false).unwrap();
    symlink(&elsewhere, &symlinked).unwrap();
    fs::write(&elsewhere.join(ADC_NAME), "fixture-only").unwrap();
    assert!(abandoned.is_dir());
    GcloudRunner::new(root).unwrap();
    assert!(active.path.is_dir());
    assert!(!abandoned.exists());
    assert!(elsewhere.join(ADC_NAME).is_file());
    assert!(symlinked.is_symlink());
    assert!(GcloudRunner::new(symlinked).is_err());
}

#[test]
fn clean_environment_does_not_use_ambient_sdk_or_adc() {
    const CHILD: &str = "ASM_TEST_GCLOUD_ENV_FIXTURE";
    if let Some(root) = std::env::var_os(CHILD) {
        let root = PathBuf::from(root);
        let fixture = Fixture::new(r#"
            [ "${GOOGLE_CLOUD_QUOTA_PROJECT+x}${GOOGLE_TEST_INHERITED+x}${CLOUDSDK_AUTH_ACCESS_TOKEN+x}${PYTHONPATH+x}${DYLD_FALLBACK_LIBRARY_PATH+x}${BROWSER+x}${HTTPS_PROXY+x}" = '' ] || exit 30
            [ "$PYTHONNOUSERSITE" = 1 ] && [ "$CLOUDSDK_CORE_DISABLE_FILE_LOGGING" = true ] || exit 31
            [ "$CLOUDSDK_CORE_DISABLE_USAGE_REPORTING" = true ] && [ "$CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK" = true ] || exit 32
            [ "$GOOGLE_APPLICATION_CREDENTIALS" = "$PWD/application_default_credentials.json" ] || exit 33
            [ "$CLOUDSDK_CONFIG" = "$PWD/config" ] || exit 34
            [ "$(command -v env)" = /usr/bin/env ] || exit 35
            printf '%s\n' test-parent-token
        "#);
        let adc = AuthorizedUser::parse(ADC).unwrap();
        assert_eq!(fixture.runner.parent_token(&fixture.sdk, &adc).unwrap(), "test-parent-token");
        assert_eq!(fs::read_to_string(root.join(".config/gcloud").join(ADC_NAME)).unwrap(), "ambient-fixture-not-an-adc");
        assert!(!root.join("unexpected-exec").exists());
        fixture.assert_clean();
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path();
    let config = home.join(".config/gcloud");
    let ambient_adc = config.join(ADC_NAME);
    fs::create_dir_all(&config).unwrap();
    fs::write(&ambient_adc, "ambient-fixture-not-an-adc").unwrap();
    fs::write(home.join("env"), "#!/bin/sh\n/usr/bin/touch \"${0%/*}/unexpected-exec\"\nexit 1\n").unwrap();
    fs::set_permissions(home.join("env"), fs::Permissions::from_mode(0o700)).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "generator::gcloud_cli::tests::clean_environment_does_not_use_ambient_sdk_or_adc"])
        .env(CHILD, home)
        .env("HOME", home)
        .env("PATH", home)
        .env("GOOGLE_APPLICATION_CREDENTIALS", ambient_adc)
        .env("GOOGLE_CLOUD_QUOTA_PROJECT", "ambient")
        .env("GOOGLE_TEST_INHERITED", "ambient")
        .env("CLOUDSDK_CONFIG", config)
        .env("CLOUDSDK_AUTH_ACCESS_TOKEN", "ambient")
        .env("PYTHONPATH", home)
        .env("DYLD_FALLBACK_LIBRARY_PATH", home)
        .env("BROWSER", home.join("env"))
        .env("HTTPS_PROXY", "http://localhost:1")
        .output().unwrap();
    assert!(output.status.success(), "{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
}

#[test]
#[ignore = "requires a supported Cloud SDK on the manager Mac; version only, no network or credentials"]
fn installed_sdk_version_in_clean_environment() {
    let tmp = tempfile::tempdir().unwrap();
    let runner = GcloudRunner::new(tmp.path().join("operations")).unwrap();
    let path = std::env::var_os("ASM_TEST_GCLOUD_SDK_PATH").map(PathBuf::from);
    let sdk = runner.check_sdk(path.as_deref()).unwrap();
    eprintln!("Google Cloud CLI {} at {}", sdk.version, sdk.path.display());
}
