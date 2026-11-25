//! Executes the operator-approved Cloud SDK without inheriting its normal config or credentials.

use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, DirBuilder, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use asm_proto::generators::{validate_gcloud_project_id, validate_gcloud_scope};
use serde::{Deserialize, Serialize, de::IgnoredAny};

use crate::error::{CoreError, Result};
use crate::process::{OutputErrors, collect_output};

const SDK_PATHS: [(&str, &str); 4] = [
    ("/opt/homebrew/bin/gcloud", "/opt/homebrew"),
    ("/opt/homebrew/share/google-cloud-sdk/bin/gcloud", "/opt/homebrew"),
    ("/usr/local/bin/gcloud", "/usr/local"),
    ("/usr/local/share/google-cloud-sdk/bin/gcloud", "/usr/local"),
];
const MINIMUM_SDK: (u32, u32, u32) = (582, 0, 0);
const SDK_TIMEOUT: Duration = Duration::from_secs(30);
const LOGIN_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const GCLOUD_OUTPUT: OutputErrors = OutputErrors {
    read: "Could not read Google Cloud CLI output",
    timeout: "Google Cloud CLI timed out. Check the Mac’s connection or browser and try again",
    capture: "Could not capture Google Cloud CLI output",
    too_large: "Google Cloud CLI response exceeded the size limit",
};
const ADC_LIMIT: usize = 1024 * 1024;
const ADC_NAME: &str = "application_default_credentials.json";
const NOFOLLOW: i32 = libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;

#[derive(Debug, Clone)]
pub(crate) struct GcloudSdk {
    pub path: PathBuf,
    pub version: String,
}

/// Only the fields the SDK needs to refresh a standard authorized-user credential.
#[derive(Clone)]
pub(crate) struct AuthorizedUser {
    client_id: String,
    client_secret: String,
    refresh_token: String,
}

impl fmt::Debug for AuthorizedUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthorizedUser { [redacted] }")
    }
}

impl AuthorizedUser {
    pub(crate) fn parse(json: &str) -> Result<Self> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Adc {
            #[serde(rename = "type")]
            kind: String,
            client_id: String,
            client_secret: String,
            refresh_token: String,
            token_uri: Option<String>,
            revoke_uri: Option<String>,
            universe_domain: Option<String>,
            #[serde(rename = "account")]
            _account: Option<IgnoredAny>,
            #[serde(rename = "quota_project_id")]
            _quota_project_id: Option<IgnoredAny>,
            #[serde(rename = "rapt_token")]
            _rapt_token: Option<IgnoredAny>,
            #[serde(rename = "scopes")]
            _scopes: Option<IgnoredAny>,
            #[serde(rename = "token")]
            _token: Option<IgnoredAny>,
            #[serde(rename = "expiry")]
            _expiry: Option<IgnoredAny>,
        }

        if json.len() > ADC_LIMIT {
            return Err(invalid_adc());
        }
        let adc: Adc = serde_json::from_str(json).map_err(|_| invalid_adc())?;
        if adc.kind != "authorized_user"
            || [&adc.client_id, &adc.client_secret, &adc.refresh_token]
                .iter()
                .any(|value| value.is_empty() || value.chars().any(|c| c.is_whitespace() || c.is_control()))
            || adc.token_uri.as_deref().is_some_and(|uri| {
                !matches!(uri, "https://oauth2.googleapis.com/token" | "https://accounts.google.com/o/oauth2/token" | "https://www.googleapis.com/oauth2/v4/token")
            })
            || adc.revoke_uri.as_deref().is_some_and(|uri| uri != "https://oauth2.googleapis.com/revoke")
            || adc.universe_domain.as_deref().is_some_and(|domain| domain != "googleapis.com")
        {
            return Err(invalid_adc());
        }
        Ok(Self {
            client_id: adc.client_id,
            client_secret: adc.client_secret,
            refresh_token: adc.refresh_token,
        })
    }

    pub(crate) fn to_json(&self) -> Result<String> {
        #[derive(Serialize)]
        struct Adc<'a> {
            #[serde(rename = "type")]
            kind: &'static str,
            client_id: &'a str,
            client_secret: &'a str,
            refresh_token: &'a str,
        }
        serde_json::to_string(&Adc {
            kind: "authorized_user",
            client_id: &self.client_id,
            client_secret: &self.client_secret,
            refresh_token: &self.refresh_token,
        })
        .map_err(|_| CoreError::internal("Could not encode the private Google credential"))
    }
}

fn invalid_adc() -> CoreError {
    CoreError::invalid("Google Cloud CLI did not provide a standard authorized-user credential; sign in again with the Mac’s browser")
}

#[derive(Clone)]
pub(crate) struct GcloudRunner {
    inner: Arc<RunnerState>,
}

struct RunnerState {
    root: PathBuf,
    stopped: AtomicBool,
    active: Mutex<usize>,
    idle: Condvar,
}

struct Operation<'a> {
    runner: &'a RunnerState,
    cancelled: Option<&'a AtomicBool>,
}

impl GcloudRunner {
    /// Does not launch the SDK or touch its normal config. The root belongs to this OS user.
    pub(crate) fn new(root: PathBuf) -> Result<Self> {
        let root = prepare_root(&root).map_err(|_| workspace_error())?;
        reap_workspaces(&root).map_err(|_| workspace_error())?;
        Ok(Self {
            inner: Arc::new(RunnerState {
                root,
                stopped: AtomicBool::new(false),
                active: Mutex::new(0),
                idle: Condvar::new(),
            }),
        })
    }

    /// Prevent new commands and wait for active commands to kill/reap and remove their files.
    pub(crate) fn shutdown(&self) {
        let mut active = self.inner.active.lock().unwrap();
        self.inner.stopped.store(true, Ordering::Release);
        while *active != 0 {
            active = self.inner.idle.wait(active).unwrap();
        }
    }

    fn operation<'a>(&'a self, cancelled: Option<&'a AtomicBool>) -> Result<Operation<'a>> {
        let mut active = self.inner.active.lock().unwrap();
        if self.inner.stopped.load(Ordering::Acquire) {
            return Err(cancelled_error());
        }
        *active += 1;
        drop(active);
        let operation = Operation { runner: &self.inner, cancelled };
        operation.check_cancelled()?;
        Ok(operation)
    }

    pub(crate) fn check_sdk(&self, path: Option<&Path>) -> Result<GcloudSdk> {
        let operation = self.operation(None)?;
        if let Some(path) = path {
            return operation.check_sdk(path);
        }
        let mut first_error = None;
        let mut present = false;
        for (path, prefix) in SDK_PATHS {
            let path = Path::new(path);
            if fs::symlink_metadata(path).is_err_and(|err| err.kind() == io::ErrorKind::NotFound) {
                continue;
            }
            present = true;
            // Do not follow a package-manager alias outside its fixed installation prefix.
            let Ok(sdk) = trusted_sdk(path) else { continue };
            if !sdk.starts_with(prefix) {
                continue;
            }
            match operation.check_sdk(&sdk) {
                Ok(sdk) => return Ok(sdk),
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        Err(first_error.unwrap_or_else(|| if present {
            untrusted_sdk()
        } else {
            CoreError::not_found("Google Cloud CLI was not found. Install it on this Mac or choose Locate gcloud…")
        }))
    }

    pub(crate) fn login(&self, sdk_path: &Path, cancelled: &AtomicBool) -> Result<(GcloudSdk, AuthorizedUser)> {
        let operation = self.operation(Some(cancelled))?;
        let sdk = operation.check_sdk(sdk_path)?;
        let workspace = operation.workspace()?;
        let config = workspace.config()?;
        operation.run(&sdk.path, &workspace, &config, &[
            "auth", "application-default", "login", "--launch-browser", "--disable-quota-project",
            "--scopes=openid,https://www.googleapis.com/auth/userinfo.email,https://www.googleapis.com/auth/cloud-platform",
        ], None, SdkCall::Login)?;
        private_dir(&config).map_err(|_| invalid_adc())?;
        let path = config.join(ADC_NAME);
        let json = read_adc(&path)?;
        fs::remove_file(&path).map_err(|_| workspace_error())?;
        let credential = AuthorizedUser::parse(&json)?;
        operation.check_cancelled()?;
        Ok((sdk, credential))
    }

    pub(crate) fn parent_token(&self, sdk_path: &Path, adc: &AuthorizedUser) -> Result<String> {
        // An unscoped SDK refresh preserves the original browser consent, including
        // OpenID and email for UserInfo. This token is used only for management calls.
        self.token(sdk_path, adc, &[], None, None)
    }

    pub(crate) fn parent_token_for_session(
        &self,
        sdk_path: &Path,
        adc: &AuthorizedUser,
        cancelled: &AtomicBool,
    ) -> Result<String> {
        self.token(sdk_path, adc, &[], None, Some(cancelled))
    }

    pub(crate) fn child_token(
        &self,
        sdk_path: &Path,
        adc: &AuthorizedUser,
        project_id: &str,
        unique_id: &str,
        scopes: &[String],
    ) -> Result<String> {
        if unique_id.is_empty() || !unique_id.bytes().all(|b| b.is_ascii_digit()) {
            return Err(CoreError::invalid("Google service account must have a numeric unique ID"));
        }
        validate_gcloud_project_id(project_id)?;
        if scopes.is_empty() || scopes.iter().any(|scope| validate_gcloud_scope(scope).is_err()) {
            return Err(CoreError::invalid("Google token issuance requires explicit, valid OAuth scopes"));
        }
        let mut scopes: Vec<_> = scopes.iter().map(String::as_str).collect();
        scopes.sort_unstable();
        scopes.dedup();
        self.token(sdk_path, adc, &[
            &format!("--impersonate-service-account={unique_id}"),
            &format!("--scopes={}", scopes.join(",")),
            "--lifetime=3600s",
            &format!("--project={project_id}"),
        ], Some(project_id), None)
    }

    fn token(
        &self,
        sdk_path: &Path,
        adc: &AuthorizedUser,
        extra_args: &[&str],
        project: Option<&str>,
        cancelled: Option<&AtomicBool>,
    ) -> Result<String> {
        let operation = self.operation(cancelled)?;
        let sdk = operation.check_sdk(sdk_path)?;
        let workspace = operation.workspace()?;
        let config = workspace.config()?;
        // Keep the ADC outside CLOUDSDK_CONFIG: SDK libraries shortcut the explicit-file
        // lookup when the configured path equals the well-known ADC path.
        let path = workspace.path.join(ADC_NAME);
        let mut file = private_file(&path, true).map_err(|_| workspace_error())?;
        file.write_all(adc.to_json()?.as_bytes()).map_err(|_| workspace_error())?;
        drop(file);
        let mut args = vec!["auth", "application-default", "print-access-token", "--format=value(token)", "--quiet"];
        args.extend_from_slice(extra_args);
        let output = operation.run(&sdk.path, &workspace, &config, &args, Some(TokenInput { path: &path, project }), SdkCall::Token)?;
        fs::remove_file(path).map_err(|_| workspace_error())?;
        operation.check_cancelled()?;
        parse_token(output)
    }
}

fn parse_token(output: Vec<u8>) -> Result<String> {
    let invalid = || CoreError::vault_unavailable("Google Cloud CLI did not return a valid access token");
    let mut token = String::from_utf8(output).map_err(|_| invalid())?;
    if token.ends_with("\r\n") {
        token.truncate(token.len() - 2);
    } else if token.ends_with('\n') {
        token.pop();
    }
    let content = token.trim_end_matches('=');
    if content.is_empty() || !content.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')) {
        return Err(invalid());
    }
    Ok(token)
}

impl Drop for Operation<'_> {
    fn drop(&mut self) {
        let mut active = self.runner.active.lock().unwrap();
        *active -= 1;
        if *active == 0 {
            self.runner.idle.notify_all();
        }
    }
}

struct TokenInput<'a> {
    path: &'a Path,
    project: Option<&'a str>,
}

#[derive(Clone, Copy)]
enum SdkCall {
    Version,
    Login,
    Token,
}

impl SdkCall {
    fn timeout(self) -> Duration {
        if matches!(self, Self::Login) { LOGIN_TIMEOUT } else { SDK_TIMEOUT }
    }

    fn failed(self, stderr: &[u8]) -> CoreError {
        match self {
            Self::Version if contains(stderr, b"Install a compatible version of Python")
                || contains(stderr, b"Could not find a valid Python") => CoreError::vault_unavailable(
                    "Google Cloud CLI needs a compatible, trusted Python installation. Install Python 3.10–3.14 from python.org, then check again",
                ),
            Self::Version => CoreError::vault_unavailable(
                "Could not run Google Cloud CLI. Check its Python installation (for example, Python 3.10–3.14 from python.org) or update and locate gcloud again",
            ),
            Self::Login => CoreError::vault_unavailable(
                "Google sign-in did not complete. Use the Mac’s local browser, complete Google consent, and try again",
            ),
            Self::Token if contains(stderr, b"invalid_grant")
                || contains(stderr, b"Token has been expired or revoked")
                || contains(stderr, b"reauth is required.") => super::gcloud::sign_in_again(),
            Self::Token => CoreError::vault_unavailable(
                "Google Cloud CLI could not obtain the access token. Check the selected project, IAM Credentials API, and service-account impersonation permission, or sign in again if authorization expired",
            ),
        }
    }
}

fn contains(value: &[u8], needle: &[u8]) -> bool {
    value.windows(needle.len()).any(|window| window == needle)
}

fn cancelled_error() -> CoreError {
    CoreError::vault_unavailable("Google Cloud operation was cancelled")
}

impl Operation<'_> {
    fn check_cancelled(&self) -> Result<()> {
        if self.runner.stopped.load(Ordering::Acquire)
            || self.cancelled.is_some_and(|flag| flag.load(Ordering::Acquire))
        {
            return Err(cancelled_error());
        }
        Ok(())
    }

    fn workspace(&self) -> Result<Workspace> {
        self.check_cancelled()?;
        Workspace::new(&self.runner.root).map_err(|_| workspace_error())
    }

    fn check_sdk(&self, path: &Path) -> Result<GcloudSdk> {
        #[derive(Deserialize)]
        struct Version {
            #[serde(rename = "Google Cloud SDK")]
            version: String,
        }

        let sdk = trusted_sdk(path)?;
        let workspace = self.workspace()?;
        let config = workspace.config()?;
        let stdout = self.run(&sdk, &workspace, &config, &["version", "--format=json", "--quiet"], None, SdkCall::Version)?;
        let Version { version } = serde_json::from_slice(&stdout).map_err(|_| unsupported_sdk())?;
        let mut fields = version.split('.').map(str::parse::<u32>);
        match (fields.next(), fields.next(), fields.next(), fields.next()) {
            (Some(Ok(major)), Some(Ok(minor)), Some(Ok(patch)), None)
                if (major, minor, patch) >= MINIMUM_SDK
                    && version.bytes().all(|b| b.is_ascii_digit() || b == b'.') =>
            {
                Ok(GcloudSdk { path: sdk, version })
            }
            _ => Err(unsupported_sdk()),
        }
    }

    fn run(
        &self,
        sdk: &Path,
        workspace: &Workspace,
        config: &Path,
        args: &[&str],
        token: Option<TokenInput<'_>>,
        call: SdkCall,
    ) -> Result<Vec<u8>> {
        self.check_cancelled()?;
        // Recheck immediately before every invocation, including after the version probe.
        if trusted_sdk(sdk)? != sdk {
            return Err(untrusted_sdk());
        }
        let mut command = Command::new(sdk);
        command
            .args(args)
            .current_dir(&workspace.path)
            .env_clear()
            .env("TMPDIR", &workspace.path)
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("PATH", sdk_process_path(sdk)?)
            .env("PYTHONNOUSERSITE", "1")
            .env("CLOUDSDK_CONFIG", config)
            .env("CLOUDSDK_CORE_DISABLE_FILE_LOGGING", "true")
            .env("CLOUDSDK_CORE_DISABLE_USAGE_REPORTING", "true")
            .env("CLOUDSDK_COMPONENT_MANAGER_DISABLE_UPDATE_CHECK", "true")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(home) = std::env::var_os("HOME").filter(|p| Path::new(p).is_absolute()) {
            command.env("HOME", home);
        }
        #[cfg(target_os = "macos")]
        if let Some(python) = sdk_python(sdk)? {
            command.env("CLOUDSDK_PYTHON", python);
        }
        if let Some(token) = token {
            open_adc(token.path).map_err(|_| invalid_adc())?;
            command.env("GOOGLE_APPLICATION_CREDENTIALS", token.path);
            if let Some(project) = token.project {
                command.env("GOOGLE_CLOUD_QUOTA_PROJECT", project);
            }
        }
        command.process_group(0);
        let lock_fd = workspace.lock.as_raw_fd();
        // SAFETY: These async-signal-safe calls only modify the child. The inherited
        // flock keeps a workspace in use even if the manager unexpectedly exits.
        unsafe {
            command.pre_exec(move || {
                libc::umask(0o077);
                if libc::fcntl(lock_fd, libc::F_SETFD, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().map_err(|_| call.failed(&[]))?;
        let (status, stdout, stderr) = collect_output(child, call.timeout(), || self.check_cancelled(), &GCLOUD_OUTPUT)?;
        self.check_cancelled()?;
        if status.success() { Ok(stdout) } else { Err(call.failed(&stderr)) }
    }
}

fn workspace_error() -> CoreError {
    CoreError::internal("Could not prepare or clean up the private Google Cloud SDK workspace")
}

fn unsupported_sdk() -> CoreError {
    CoreError::invalid("Update the Google Cloud CLI to version 582.0.0 or later, then check again")
}

fn untrusted_sdk() -> CoreError {
    CoreError::invalid("Choose a trusted, executable gcloud installation at an absolute path; gcloud and its installation must not be writable by other users")
}

fn trusted_sdk(path: &Path) -> Result<PathBuf> {
    let name = Some(OsStr::new("gcloud"));
    if path.file_name() != name || path.components().any(|part| part == Component::ParentDir) {
        return Err(untrusted_sdk());
    }
    resolve_trusted(path, TrustedPath::Executable)
        .filter(|resolved| resolved.file_name() == name)
        .ok_or_else(untrusted_sdk)
}

fn sdk_process_path(sdk: &Path) -> Result<OsString> {
    let mut paths = vec![sdk.parent().unwrap().to_owned()];
    for dir in ["/usr/bin", "/bin", "/usr/sbin", "/sbin"] {
        if let Some(dir) = resolve_trusted(Path::new(dir), TrustedPath::Directory)
            && !paths.contains(&dir)
        {
            paths.push(dir);
        }
    }
    std::env::join_paths(paths).map_err(|_| untrusted_sdk())
}

#[cfg(target_os = "macos")]
fn sdk_python(sdk: &Path) -> Result<Option<PathBuf>> {
    let sdk_root = sdk.parent().and_then(Path::parent).ok_or_else(untrusted_sdk)?;
    let bundled = sdk_root.join("platform/bundledpythonunix/bin/python3");
    match fs::symlink_metadata(&bundled) {
        // Let the launcher configure its bundled interpreter and site packages.
        Ok(_) => return resolve_trusted(&bundled, TrustedPath::Executable)
            .filter(|path| path.starts_with(sdk_root)).map(|_| None).ok_or_else(untrusted_sdk),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(untrusted_sdk()),
    }
    let home = passwd_home();
    for minor in (10..=14).rev() {
        let python = format!("python3.{minor}");
        let framework = PathBuf::from(format!("/Library/Frameworks/Python.framework/Versions/3.{minor}"));
        if let Some(path) = installed_python(&framework.join("bin").join(&python), &framework) {
            return Ok(Some(path));
        }
        for prefix in [Path::new("/opt/homebrew"), Path::new("/usr/local")] {
            let keg = format!("python@3.{minor}");
            let alias = prefix.join("opt").join(&keg).join("bin").join(&python);
            if let Some(path) = installed_python(&alias, &prefix.join("Cellar").join(keg)) {
                return Ok(Some(path));
            }
        }
        if let Some(path) = home.as_deref().and_then(|home| uv_python(home, minor)) {
            return Ok(Some(path));
        }
    }
    // Allow the SDK to look for system Python using only the deterministic PATH.
    Ok(None)
}

#[cfg(target_os = "macos")]
fn installed_python(entry: &Path, root: &Path) -> Option<PathBuf> {
    if !entry.is_file() {
        return None;
    }
    let python = resolve_trusted(entry, TrustedPath::Executable)?;
    (python.starts_with(root) && python.file_name() == entry.file_name()).then_some(python)
}

#[cfg(target_os = "macos")]
fn uv_python(home: &Path, minor: u8) -> Option<PathBuf> {
    // uv's standard managed-runtime path, not its virtualenvs, cache or executable PATH.
    let root = home.join(".local/share/uv/python");
    let arch = std::env::consts::ARCH;
    let suffix = format!("-macos-{arch}-none");
    let version = format!("cpython-3.{minor}");
    let executable = format!("python3.{minor}");
    let entry = root.join(format!("{version}{suffix}")).join("bin").join(&executable);
    if !entry.is_file() {
        return None;
    }
    let root = resolve_trusted(&root, TrustedPath::Directory)?;
    let installed = installed_python(&entry, &root)?;
    let mut parts = installed.strip_prefix(&root).ok()?.components();
    let release = parts.next()?.as_os_str().to_str()?;
    let patch = release.strip_prefix(&version)?.strip_prefix('.')?.strip_suffix(&suffix)?;
    (!patch.is_empty() && patch.bytes().all(|b| b.is_ascii_digit())
        && parts.as_path() == Path::new("bin").join(executable)).then_some(installed)
}

#[cfg(target_os = "macos")]
fn passwd_home() -> Option<PathBuf> {
    use std::ffi::CStr;
    use std::os::unix::ffi::OsStrExt;
    // SAFETY: getpwuid_r fills `user` and its backing buffer; copy the home before returning.
    unsafe {
        let mut user: libc::passwd = std::mem::zeroed();
        let mut result = std::ptr::null_mut();
        let mut buf = [0 as libc::c_char; 4096];
        if libc::getpwuid_r(current_uid(), &mut user, buf.as_mut_ptr(), buf.len(), &mut result) != 0
            || result.is_null() || user.pw_dir.is_null()
        {
            return None;
        }
        let home = PathBuf::from(OsStr::from_bytes(CStr::from_ptr(user.pw_dir).to_bytes()));
        home.is_absolute().then_some(home)
    }
}

fn current_uid() -> u32 {
    // SAFETY: geteuid takes no arguments and has no preconditions.
    unsafe { libc::geteuid() }
}

fn trusted_owner(meta: &Metadata) -> bool {
    meta.uid() == 0 || meta.uid() == current_uid()
}

#[derive(Clone, Copy)]
enum TrustedPath {
    Directory,
    Executable,
}

/// Inspect every incoming component and symlink hop before accepting the canonical target.
/// A root-owned sticky ancestor (e.g. /tmp) is safe only with verified ownership on the child.
fn resolve_trusted(path: &Path, end: TrustedPath) -> Option<PathBuf> {
    fn segments(path: &Path) -> impl DoubleEndedIterator<Item = OsString> + '_ {
        path.components().filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_owned()),
            Component::ParentDir => Some(OsString::from("..")),
            _ => None,
        })
    }

    let root = Path::new("/");
    if !path.is_absolute() || !fs::symlink_metadata(root).is_ok_and(|meta| {
        meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o022 == 0
    }) || acl_allows(root, false) {
        return None;
    }
    let mut resolved = root.to_owned();
    let mut pending: VecDeque<_> = segments(path).collect();
    let mut links = 0;
    while let Some(segment) = pending.pop_front() {
        if segment == ".." {
            resolved.pop();
            continue;
        }
        resolved.push(segment);
        let meta = fs::symlink_metadata(&resolved).ok()?;
        if !trusted_owner(&meta) || acl_allows(&resolved, false) {
            return None;
        }
        if meta.is_symlink() {
            links += 1;
            if links > 40 {
                return None;
            }
            let target = fs::read_link(&resolved).ok()?;
            resolved.pop();
            if target.is_absolute() {
                resolved.clear();
                resolved.push(root);
            }
            for part in segments(&target).rev() {
                pending.push_front(part);
            }
        } else if pending.is_empty() && matches!(end, TrustedPath::Executable) {
            return (meta.is_file() && meta.mode() & 0o6022 == 0 && meta.mode() & 0o111 != 0).then_some(resolved);
        } else if !meta.is_dir() || meta.mode() & 0o022 != 0
            && (pending.is_empty() || meta.uid() != 0 || meta.mode() & 0o1000 == 0)
        {
            return None;
        }
    }
    if matches!(end, TrustedPath::Directory)
        && fs::symlink_metadata(&resolved).is_ok_and(|meta| meta.mode() & 0o022 == 0)
    {
        Some(resolved)
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn acl_allows(path: &Path, private: bool) -> bool {
    use std::ffi::{CString, c_int, c_void};
    use std::os::unix::ffi::OsStrExt;
    use std::ptr;

    // macOS sys/acl.h: ACL_TYPE_EXTENDED; ACL_EXTENDED_ALLOW; mutation permissions.
    const EXTENDED: c_int = 0x100;
    const ALLOW: c_int = 1;
    const MUTATE: u64 = (1 << 2) | (1 << 4) | (1 << 5) | (1 << 6)
        | (1 << 8) | (1 << 10) | (1 << 12) | (1 << 13);
    unsafe extern "C" {
        fn acl_get_link_np(path: *const libc::c_char, kind: c_int) -> *mut c_void;
        fn acl_get_entry(acl: *mut c_void, which: c_int, entry: *mut *mut c_void) -> c_int;
        fn acl_get_tag_type(entry: *mut c_void, tag: *mut c_int) -> c_int;
        fn acl_get_permset_mask_np(entry: *mut c_void, mask: *mut u64) -> c_int;
        fn acl_free(acl: *mut c_void) -> c_int;
    }
    let Ok(path) = CString::new(path.as_os_str().as_bytes()) else { return true };
    // SAFETY: The ACL API initializes live entries belonging to `acl`; free it after traversal.
    unsafe {
        let acl = acl_get_link_np(path.as_ptr(), EXTENDED);
        if acl.is_null() {
            // macOS returns ENOENT when an otherwise existing file has no ACL.
            return !matches!(io::Error::last_os_error().raw_os_error(), Some(libc::ENOENT | libc::ENOTSUP));
        }
        let mut which = 0; // ACL_FIRST_ENTRY
        let permits = loop {
            let mut entry = ptr::null_mut();
            if acl_get_entry(acl, which, &mut entry) != 0 {
                break io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL);
            }
            which = -1; // ACL_NEXT_ENTRY
            let mut tag = 0;
            if acl_get_tag_type(entry, &mut tag) != 0 {
                break true;
            }
            if tag == ALLOW {
                let mut mask = 0;
                let forbidden = if private { u64::MAX } else { MUTATE };
                if acl_get_permset_mask_np(entry, &mut mask) != 0 || mask & forbidden != 0 {
                    break true;
                }
            }
        };
        acl_free(acl);
        permits
    }
}

#[cfg(not(target_os = "macos"))]
fn acl_allows(_: &Path, _: bool) -> bool {
    false
}

fn permission_denied() -> io::Error {
    io::ErrorKind::PermissionDenied.into()
}

fn private_dir(path: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir() || meta.uid() != current_uid() || meta.mode() & 0o7777 != 0o700 || acl_allows(path, true) {
        return Err(permission_denied());
    }
    Ok(())
}

fn prepare_root(root: &Path) -> io::Result<PathBuf> {
    if !root.is_absolute() {
        return Err(permission_denied());
    }
    let parent = resolve_trusted(root.parent().ok_or_else(permission_denied)?, TrustedPath::Directory)
        .ok_or_else(permission_denied)?;
    let root = parent.join(root.file_name().ok_or_else(permission_denied)?);
    mkdir_private(&root, true)?;
    Ok(root)
}

fn mkdir_private(path: &Path, existing_ok: bool) -> io::Result<()> {
    match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => private_dir(path),
        Err(error) if existing_ok && error.kind() == io::ErrorKind::AlreadyExists => private_dir(path),
        Err(error) => Err(error),
    }
}

fn check_private_file(path: &Path, file: &File) -> io::Result<()> {
    let meta = file.metadata()?;
    if !meta.is_file() || meta.uid() != current_uid() || meta.nlink() != 1 || meta.mode() & 0o7777 != 0o600 || acl_allows(path, true) {
        return Err(permission_denied());
    }
    Ok(())
}

fn private_file(path: &Path, exclusive: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).mode(0o600).custom_flags(NOFOLLOW);
    if exclusive { options.create_new(true); }
    let file = options.open(path)?;
    check_private_file(path, &file)?;
    Ok(file)
}

fn open_adc(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new().read(true).custom_flags(NOFOLLOW).open(path)?;
    check_private_file(path, &file)?;
    Ok(file)
}

fn read_adc(path: &Path) -> Result<String> {
    let file = open_adc(path).map_err(|_| invalid_adc())?;
    if file.metadata().map_err(|_| invalid_adc())?.len() > ADC_LIMIT as u64 {
        return Err(invalid_adc());
    }
    let mut output = String::new();
    file.take(ADC_LIMIT as u64 + 1).read_to_string(&mut output).map_err(|_| invalid_adc())?;
    if output.len() > ADC_LIMIT {
        return Err(invalid_adc());
    }
    Ok(output)
}

fn workspace_lock(path: &Path, nonblocking: bool) -> io::Result<File> {
    let file = match private_file(path, true) {
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => private_file(path, false)?,
        result => result?,
    };
    let flags = libc::LOCK_EX | if nonblocking { libc::LOCK_NB } else { 0 };
    loop {
        // SAFETY: `file` owns the open descriptor for the lifetime of the lock.
        if unsafe { libc::flock(file.as_raw_fd(), flags) } == 0 {
            return Ok(file);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted { return Err(err); }
    }
}

fn reap_workspaces(root: &Path) -> io::Result<()> {
    let _root_lock = workspace_lock(&root.join(".workspace-lock"), false)?;
    for item in fs::read_dir(root)? {
        let entry = item?;
        if !entry.file_name().to_str().and_then(|name| name.strip_prefix("op-"))
            .is_some_and(|id| id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            continue;
        }
        let path = entry.path();
        if private_dir(&path).is_err() {
            continue;
        }
        match workspace_lock(&path.join(".active"), true) {
            Ok(_lock) => {
                if let Err(error) = fs::remove_dir_all(path)
                    && error.kind() != io::ErrorKind::NotFound
                {
                    return Err(error);
                }
            }
            Err(error) if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied) => {}
            Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

struct Workspace {
    path: PathBuf,
    lock: File,
}

impl Workspace {
    fn new(root: &Path) -> io::Result<Self> {
        private_dir(root)?;
        // Coordinate creation with startup reaping so an initializer does not look abandoned.
        let _root_lock = workspace_lock(&root.join(".workspace-lock"), false)?;
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(|_| io::Error::other("randomness unavailable"))?;
        let path = root.join(format!("op-{}", hex::encode(random)));
        mkdir_private(&path, false)?;
        match workspace_lock(&path.join(".active"), true) {
            Ok(lock) => Ok(Self { path, lock }),
            Err(error) => {
                let _ = fs::remove_dir_all(&path);
                Err(error)
            }
        }
    }

    fn config(&self) -> Result<PathBuf> {
        let config = self.path.join("config");
        mkdir_private(&config, false).map_err(|_| workspace_error())?;
        Ok(config)
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        // This runs while we still own the workspace lock, after the subprocess group is gone.
        if fs::remove_dir_all(&self.path).is_err() {
            log::warn!("Could not remove a private Google Cloud SDK workspace");
        }
    }
}

#[cfg(test)]
#[path = "gcloud_cli_tests.rs"]
mod tests;
