//! Pairing the same machine again: re-pairing with a proof of the old pairing keeps the
//! host record, a machine-hint match may replace it (revoking its leases), pairing codes
//! never replace by hint, and `asm pair` refuses to pair again while still paired. Also:
//! resolved requests (Recent in the menu bar) lead to their activity log rows.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use asm_core::ffi::{ActivityQuery, LeaseMode, RequestDetail, VaultConfig, VaultDraft};
use asm_core::manager::now;
use asm_core::settings as keys;
use asm_core::{Decision, Manager, ManagerObserver, StartOptions};
use asm_proto::crypto::{hex_encode, sha256};
use asm_proto::pairing::{client_commit, new_nonce};
use asm_proto::wire::{HostInfo, PairProof, PairRequest, PairResponse, RequestBody, RevealRequest};
use serde_json::json;

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

/// Build the CLI into its own target dir (no lock contention with this cargo run).
fn build_cli() -> PathBuf {
    let base = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace().join("target"));
    let target = base.join("e2e-cli");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let st = Command::new(cargo)
        .args(["build", "-q", "-p", "asm-cli", "--target-dir"])
        .arg(&target)
        .current_dir(workspace())
        .status()
        .expect("run cargo build -p asm-cli");
    assert!(st.success(), "cargo build -p asm-cli failed");
    target.join("debug/asm")
}

fn free_ports(n: usize) -> Vec<u16> {
    let ls: Vec<TcpListener> = (0..n)
        .map(|_| TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    ls.iter().map(|l| l.local_addr().unwrap().port()).collect()
}

struct Quiet;

impl ManagerObserver for Quiet {
    fn changed(&self, _topic: String) {}
}

struct Setup {
    m: Arc<Manager>,
    tmp: tempfile::TempDir,
}

impl Drop for Setup {
    fn drop(&mut self) {
        self.m.shutdown();
    }
}

/// A manager with a `.env` vault holding `DEMO_TOKEN`; `None` (test skipped) without
/// `dist/bin/iron-proxy`.
fn setup() -> Option<Setup> {
    let bin_dir = workspace().join("dist/bin");
    if !bin_dir.join("iron-proxy").exists() {
        eprintln!(
            "SKIPPED: {} is missing; run `just proxy` first",
            bin_dir.join("iron-proxy").display()
        );
        return None;
    }
    let tmp = tempfile::tempdir().unwrap();
    let env_file = tmp.path().join("demo.env");
    std::fs::write(&env_file, "DEMO_TOKEN=real-value-123\n").unwrap();
    let ports = free_ports(5);
    let options = StartOptions {
        values_root: Some(tmp.path().join("values")),
        settings: vec![
            (keys::API_BIND.into(), json!("127.0.0.1")),
            (keys::API_PORT.into(), json!(0)),
            (keys::PROXY_BIND.into(), json!("127.0.0.1")),
            (keys::PROXY_PORT.into(), json!(ports[0])),
            (keys::PROXY_HTTP_PORT.into(), json!(ports[1])),
            (keys::PROXY_HTTPS_PORT.into(), json!(ports[2])),
            (keys::PROXY_MGMT_PORT.into(), json!(ports[3])),
            (keys::PROXY_METRICS_PORT.into(), json!(ports[4])),
            (keys::PROXY_HINTS.into(), json!(["127.0.0.1"])),
        ],
    };
    let m = Manager::start_with(tmp.path().join("data"), bin_dir, Arc::new(Quiet), options)
        .expect("start");
    m.save_vault(VaultDraft {
        id: None,
        name: "demo".into(),
        config: VaultConfig::EnvFile {
            path: env_file.to_string_lossy().into_owned(),
        },
        client_secret: String::new(),
        master_password: String::new(),
    })
    .expect("add .env vault");
    Some(Setup { m, tmp })
}

const HINT: &str = "4242424242424242424242424242424242424242424242424242424242424242";

fn request(
    hostname: &str,
    hint: Option<&str>,
    previous: Option<(&str, &str)>,
    code: Option<&str>,
) -> (PairRequest, [u8; 16]) {
    let nonce = new_nonce();
    let req = PairRequest {
        client_commit: hex_encode(&client_commit(&nonce)),
        host_info: HostInfo {
            hostname: hostname.into(),
            os: "linux".into(),
            ..Default::default()
        },
        pairing_code: code.map(str::to_owned),
        previous: previous.map(|(host_id, token)| PairProof {
            host_id: host_id.into(),
            token: token.into(),
        }),
        machine_hint: hint.map(str::to_owned),
    };
    (req, nonce)
}

/// Pair with a fresh unattended code; returns (host_id, token).
fn pair_code(
    m: &Manager,
    hostname: &str,
    hint: Option<&str>,
    previous: Option<(&str, &str)>,
) -> (String, String) {
    let code = m
        .create_pairing_code("repair".into(), Some(3600), Some(1), vec![])
        .unwrap();
    let (req, _) = request(hostname, hint, previous, Some(&code.code));
    match m.core().pair_start(req, "10.0.0.5").unwrap() {
        PairResponse::Approved { host_id, token } => (host_id, token),
        other => panic!("unexpected {other:?}"),
    }
}

/// An interactive pairing request up to its popup; returns (pair id, poll token).
fn pair_popup(
    m: &Manager,
    hostname: &str,
    hint: Option<&str>,
    previous: Option<(&str, &str)>,
) -> (String, String) {
    let (req, nonce) = request(hostname, hint, previous, None);
    let PairResponse::AwaitingReveal {
        pair_id,
        poll_token,
        ..
    } = m.core().pair_start(req, "10.0.0.6").unwrap()
    else {
        panic!("not awaiting reveal")
    };
    m.core()
        .pair_reveal(
            &pair_id,
            RevealRequest {
                poll_token: poll_token.clone(),
                client_nonce: hex_encode(&nonce),
            },
        )
        .unwrap();
    (pair_id, poll_token)
}

/// The popup's repair info: (kind, host_id, host_name).
fn popup_repair(m: &Manager, pair_id: &str) -> Option<(String, String, String)> {
    let p = m
        .snapshot()
        .pending
        .into_iter()
        .find(|p| p.id == pair_id)
        .expect("popup shown");
    match p.detail {
        RequestDetail::Pair { repair, .. } => repair.map(|r| (r.kind, r.host_id, r.host_name)),
        other => panic!("not a pairing popup: {other:?}"),
    }
}

/// Approve the popup and collect the token; returns (host_id, token).
fn approve(m: &Manager, pair_id: &str, poll: &str, name: &str, replace: bool) -> (String, String) {
    m.resolve_request(
        pair_id.into(),
        Decision::ApprovePair {
            name: name.into(),
            replace,
        },
    )
    .unwrap();
    match m.core().pair_poll(pair_id, poll).unwrap() {
        PairResponse::Approved { host_id, token } => (host_id, token),
        other => panic!("unexpected {other:?}"),
    }
}

fn token_works(m: &Manager, token: &str) -> Option<String> {
    m.core()
        .store
        .host_by_token(&sha256(token.as_bytes()))
        .unwrap()
        .map(|h| h.id)
}

/// An approved sentinel lease on `DEMO_TOKEN` for `host_id`; returns its id.
fn lease(m: &Manager, host_id: &str) -> String {
    let host = m.core().store.get_host(host_id).unwrap().unwrap();
    let st = m
        .core()
        .create_request(
            &host,
            "10.0.0.5",
            RequestBody::Get {
                name: "DEMO_TOKEN".into(),
                raw: false,
                hosts: vec!["api.example.com".into()],
                reason: "repair test".into(),
                agent: "test".into(),
            },
        )
        .unwrap();
    m.resolve_request(
        st.request_id.clone(),
        Decision::ApproveGet {
            mode: LeaseMode::Sentinel,
            duration_secs: Some(3600),
            hosts: vec!["api.example.com".into()],
        },
    )
    .unwrap();
    let leases = m.core().store.leases_of_host(host_id).unwrap();
    assert_eq!(leases.len(), 1);
    leases[0].id.clone()
}

fn lease_active(m: &Manager, id: &str) -> bool {
    m.core()
        .store
        .get_lease(id)
        .unwrap()
        .unwrap()
        .is_active(now())
}

/// The activity log, after the background writer caught up.
fn activity(m: &Manager) -> Vec<asm_core::store::ActivityRecord> {
    m.core().activity.flush();
    m.core()
        .store
        .list_activity(&asm_core::store::ActivityFilter {
            limit: 500,
            ..Default::default()
        })
        .unwrap()
}

fn activity_kinds(m: &Manager) -> Vec<String> {
    activity(m).into_iter().map(|a| a.kind).collect()
}

#[test]
fn code_with_valid_proof_rotates_the_same_host() {
    let Some(s) = setup() else { return };
    let m = &s.m;
    let (host_id, old_token) = pair_code(m, "box", Some(HINT), None);
    m.rename_host(host_id.clone(), "Build box".into()).unwrap();
    let lease_id = lease(m, &host_id);

    let (again, new_token) = pair_code(m, "box-renamed", Some(HINT), Some((&host_id, &old_token)));
    assert_eq!(again, host_id, "same host record");
    assert_ne!(new_token, old_token);
    assert_eq!(token_works(m, &old_token), None, "old token invalidated");
    assert_eq!(
        token_works(m, &new_token).as_deref(),
        Some(host_id.as_str())
    );
    assert!(lease_active(m, &lease_id), "leases kept");
    let hosts = m.list_hosts();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].name, "Build box", "name kept");
    assert_eq!(hosts[0].info.hostname, "box-renamed", "host info refreshed");
    assert!(activity_kinds(m).iter().any(|k| k == "repaired_with_code"));
}

#[test]
fn interactive_with_valid_proof_keeps_the_record() {
    let Some(s) = setup() else { return };
    let m = &s.m;
    let (host_id, old_token) = pair_code(m, "box", Some(HINT), None);
    let lease_id = lease(m, &host_id);

    let (pair_id, poll) = pair_popup(m, "box", Some(HINT), Some((&host_id, &old_token)));
    assert_eq!(
        popup_repair(m, &pair_id),
        Some(("same_install".into(), host_id.clone(), "box".into()))
    );
    let (again, new_token) = approve(m, &pair_id, &poll, "ignored name", true);
    assert_eq!(again, host_id);
    assert_eq!(token_works(m, &old_token), None);
    assert_eq!(
        token_works(m, &new_token).as_deref(),
        Some(host_id.as_str())
    );
    assert!(lease_active(m, &lease_id));
    let hosts = m.list_hosts();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].name, "box");
    assert!(activity_kinds(m).iter().any(|k| k == "repaired"));
}

#[test]
fn hint_match_with_replace_revokes_the_old_host() {
    let Some(s) = setup() else { return };
    let m = &s.m;
    let (old_id, old_token) = pair_code(m, "box", Some(HINT), None);
    m.rename_host(old_id.clone(), "Build box".into()).unwrap();
    let lease_id = lease(m, &old_id);
    assert_eq!(m.list_hosts()[0].machine_hint_matches, 0);

    // No proof (e.g. host.json lost), same machine hint.
    let (pair_id, poll) = pair_popup(m, "box", Some(HINT), None);
    assert_eq!(
        popup_repair(m, &pair_id),
        Some(("same_machine".into(), old_id.clone(), "Build box".into()))
    );
    let (new_id, new_token) = approve(m, &pair_id, &poll, "typed name", true);
    assert_ne!(new_id, old_id);
    assert_eq!(token_works(m, &old_token), None, "old host revoked");
    assert!(!lease_active(m, &lease_id), "its leases revoked");
    assert_eq!(token_works(m, &new_token).as_deref(), Some(new_id.as_str()));
    assert!(m.core().store.leases_of_host(&new_id).unwrap().is_empty());
    let hosts = m.list_hosts();
    assert_eq!(hosts.len(), 1);
    assert_eq!(hosts[0].host_id, new_id);
    assert_eq!(hosts[0].name, "Build box", "the old name carries over");
    assert!(activity_kinds(m).iter().any(|k| k == "replaced"));
}

#[test]
fn hint_match_without_replace_adds_a_host() {
    let Some(s) = setup() else { return };
    let m = &s.m;
    let (old_id, old_token) = pair_code(m, "box", Some(HINT), None);
    let lease_id = lease(m, &old_id);

    let (pair_id, poll) = pair_popup(m, "box", Some(HINT), None);
    assert_eq!(popup_repair(m, &pair_id).unwrap().0, "same_machine");
    let (new_id, _) = approve(m, &pair_id, &poll, "second box", false);
    assert_ne!(new_id, old_id);
    assert_eq!(token_works(m, &old_token).as_deref(), Some(old_id.as_str()));
    assert!(lease_active(m, &lease_id));
    let hosts = m.list_hosts();
    assert_eq!(hosts.len(), 2);
    assert!(
        hosts.iter().all(|h| h.machine_hint_matches == 1),
        "both flagged"
    );
    assert!(hosts.iter().any(|h| h.name == "second box"));
}

#[test]
fn code_with_hint_only_adds_a_host() {
    let Some(s) = setup() else { return };
    let m = &s.m;
    let (old_id, old_token) = pair_code(m, "box", Some(HINT), None);
    let lease_id = lease(m, &old_id);

    let (new_id, _) = pair_code(m, "box", Some(HINT), None);
    assert_ne!(new_id, old_id);
    assert_eq!(token_works(m, &old_token).as_deref(), Some(old_id.as_str()));
    assert!(lease_active(m, &lease_id), "nothing revoked");
    assert_eq!(m.list_hosts().len(), 2);
    let entry = activity(m)
        .into_iter()
        .find(|a| a.kind == "paired_with_code" && a.host_id.as_deref() == Some(new_id.as_str()))
        .expect("logged");
    let detail: serde_json::Value = serde_json::from_str(entry.detail.as_deref().unwrap()).unwrap();
    assert!(
        detail["warning"].as_str().unwrap().contains("not replaced"),
        "{detail}"
    );
    assert_eq!(detail["machine_hint_matches"], json!([old_id]));
}

#[test]
fn revoked_hosts_token_is_no_proof() {
    let Some(s) = setup() else { return };
    let m = &s.m;
    let (old_id, old_token) = pair_code(m, "box", None, None);
    m.revoke_host(old_id.clone()).unwrap();

    // Interactive: a normal new pairing, no repair info.
    let (pair_id, poll) = pair_popup(m, "box", None, Some((&old_id, &old_token)));
    assert_eq!(popup_repair(m, &pair_id), None);
    let (new_id, _) = approve(m, &pair_id, &poll, "", true);
    assert_ne!(new_id, old_id);
    // Code: a new record too.
    let (code_id, _) = pair_code(m, "box", None, Some((&old_id, &old_token)));
    assert!(code_id != old_id && code_id != new_id);
    // A wrong token for an active host is no proof either.
    let (third, _) = pair_code(m, "box", None, Some((&new_id, "wrong-token")));
    assert!(third != new_id);
    assert_eq!(m.list_hosts().len(), 3);
}

#[test]
fn resolved_requests_link_to_their_activity_rows() {
    let Some(s) = setup() else { return };
    let m = &s.m;
    // Pairing approved, as a replacement (its extra `replaced` row is not the outcome).
    let (old_id, _) = pair_code(m, "box", Some(HINT), None);
    let (paired, poll) = pair_popup(m, "box", Some(HINT), None);
    let (host_id, _) = approve(m, &paired, &poll, "Box", true);
    assert_ne!(host_id, old_id);
    // Pairing denied.
    let (pair_denied, _) = pair_popup(m, "other", None, None);
    m.resolve_request(
        pair_denied.clone(),
        Decision::Deny {
            reason: String::new(),
        },
    )
    .unwrap();
    // Secret requests: approved, served from the lease, denied.
    let host = m.core().store.get_host(&host_id).unwrap().unwrap();
    let get = |raw: bool| {
        m.core()
            .create_request(
                &host,
                "10.0.0.5",
                RequestBody::Get {
                    name: "DEMO_TOKEN".into(),
                    raw,
                    hosts: vec!["api.example.com".into()],
                    reason: "recent link test".into(),
                    agent: "test".into(),
                },
            )
            .unwrap()
            .request_id
    };
    let approved = get(false);
    m.resolve_request(
        approved.clone(),
        Decision::ApproveGet {
            mode: LeaseMode::Sentinel,
            duration_secs: Some(3600),
            hosts: vec!["api.example.com".into()],
        },
    )
    .unwrap();
    let reused = get(false);
    let denied = get(true);
    m.resolve_request(
        denied.clone(),
        Decision::Deny {
            reason: "provide a better reason".into(),
        },
    )
    .unwrap();

    let recent: Vec<String> = m.snapshot().recent.into_iter().map(|r| r.id).collect();
    let rows = m.list_activity(ActivityQuery {
        categories: vec![],
        host_id: None,
        search: String::new(),
        before_id: None,
        limit: 0,
    });
    for (id, category, kind) in [
        (&paired, "pairing", "approved"),
        (&pair_denied, "pairing", "denied"),
        (&approved, "requests", "approved"),
        (&reused, "requests", "reused"),
        (&denied, "requests", "denied"),
    ] {
        assert!(recent.contains(id), "{kind} {id} is a Recent entry");
        let row_id = m
            .activity_row_for_request(id.clone())
            .unwrap_or_else(|| panic!("row for {category} {kind}"));
        let row = rows
            .iter()
            .find(|r| r.id == row_id)
            .expect("list_activity returns it");
        assert_eq!((row.category.as_str(), row.kind.as_str()), (category, kind));
        let detail: serde_json::Value =
            serde_json::from_str(row.detail.as_deref().unwrap()).unwrap();
        assert_eq!(detail["request_id"], json!(id));
    }
    assert_eq!(m.activity_row_for_request("unknown".into()), None);
}

/// Run the real CLI with its own config dir.
fn asm(cli: &Path, config: &Path, args: &[&str]) -> (i32, String, String) {
    let mut c = Command::new(cli);
    c.args(args)
        .env("XDG_CONFIG_HOME", config)
        .env("ASM_SECRETS_DIR", config.join("secrets"))
        .env_remove("XDG_RUNTIME_DIR")
        .env_remove("ASM_PAIRING_CODE")
        .env_remove("HTTPS_PROXY")
        .env_remove("HTTP_PROXY")
        .env_remove("ALL_PROXY")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let o = c.spawn().unwrap().wait_with_output().unwrap();
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

#[test]
fn cli_refuses_to_pair_again_while_paired() {
    let Some(s) = setup() else { return };
    let m = &s.m;
    let cli = build_cli();
    let config = s.tmp.path().join("config");
    let api = m.general_settings().listening_on;
    let code = || {
        m.create_pairing_code("cli".into(), Some(3600), Some(1), vec![])
            .unwrap()
            .code
    };

    let (rc, out, err) = asm(&cli, &config, &["pair", &api, &code()]);
    assert_eq!(rc, 0, "{out}{err}");
    let host_json = || -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(config.join("asm/host.json")).unwrap()).unwrap()
    };
    let first = host_json();
    let host_id = first["host_id"].as_str().unwrap().to_owned();
    let url = first["manager_url"].as_str().unwrap().to_owned();

    // Still paired: nothing happens, exit 0, the pairing code is not used.
    let unused = code();
    let (rc, out, err) = asm(&cli, &config, &["pair", &api, &unused]);
    assert_eq!(rc, 0, "{out}{err}");
    assert_eq!(
        out.trim_end(),
        format!("already paired with {url} as {host_id}; use --force to pair again")
    );
    assert_eq!(host_json(), first);
    assert_eq!(m.list_hosts().len(), 1);

    // --force re-pairs the same host record with a new token.
    let (rc, out, err) = asm(&cli, &config, &["pair", "--force", &api, &unused]);
    assert_eq!(rc, 0, "{out}{err}");
    let second = host_json();
    assert_eq!(second["host_id"], first["host_id"]);
    assert_ne!(second["token"], first["token"]);
    assert_eq!(m.list_hosts().len(), 1);
    assert_eq!(token_works(m, first["token"].as_str().unwrap()), None);

    // Revoked: the token is rejected, so pairing proceeds (a new host; the proof is ignored).
    m.revoke_host(host_id.clone()).unwrap();
    let (rc, out, err) = asm(&cli, &config, &["pair", &api, &code()]);
    assert_eq!(rc, 0, "{out}{err}");
    assert!(out.contains("paired: "), "{out}");
    let third = host_json();
    assert_ne!(third["host_id"], first["host_id"]);
    assert_eq!(m.list_hosts().len(), 1);
}
