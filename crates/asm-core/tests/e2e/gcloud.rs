use super::*;
use asm_core::generator::{GcloudConfig, GcloudScopeOption, GcloudService, GeneratorClient, gcloud::GcloudGenerator};
use asm_proto::generators::{GCLOUD_TOKEN_NAME, GcloudGrant};
use std::os::unix::fs::PermissionsExt;

pub(super) const READ_SCOPE: &str = "https://www.googleapis.com/auth/devstorage.read_only";
const WRITE_SCOPE: &str = "https://www.googleapis.com/auth/devstorage.read_write";
const ACCOUNT_ID: &str = "123456789012345678901";

#[test]
fn raw_child_only_on_get_renewal_and_exec() {
    let tmp = tempfile::tempdir().unwrap();
    let sdk_dir = tmp.path().canonicalize().unwrap().join("sdk/bin");
    std::fs::create_dir_all(&sdk_dir).unwrap();
    let sdk = sdk_dir.join("gcloud");
    // Only the exact Storage reader impersonation can produce a child credential.
    // If the adapter requests a parent token, it gets a distinct fixture value.
    std::fs::write(&sdk, r#"#!/bin/sh
set -eu
case "$1" in
version) printf '%s\n' '{"Google Cloud SDK":"582.0.0"}'; exit;;
esac
[ "$1 $2 $3" = 'auth application-default print-access-token' ]; shift 3
printf 'token request\n' >> "${0%/*}/token-requests"
[ -f "$GOOGLE_APPLICATION_CREDENTIALS" ]
target= scopes= lifetime= project= projection=
for arg in "$@"; do case "$arg" in
    --impersonate-service-account=*) target=${arg#*=};;
    --scopes=*) scopes=${arg#*=};;
    --lifetime=*) lifetime=${arg#*=};;
    --project=*) project=${arg#*=};;
    --format=*) projection=${arg#*=};;
    --quiet) ;;
    *) exit 1;;
esac; done
[ "$projection" = 'value(token)' ]
if [ -z "$target" ]; then
    : > "${0%/*}/parent-token-requested"
    echo parent-fixture-token-never-deliver
    exit
fi
[ "$target" = '123456789012345678901' ] && [ "$scopes" = 'https://www.googleapis.com/auth/devstorage.read_only' ] && [ "$lifetime" = '3600s' ] && [ "$project" = 'asm-fixture' ] || exit 1
[ "$GOOGLE_CLOUD_QUOTA_PROJECT" = "$project" ]
printf 'child-fixture-%s\n' "$(uuidgen)"
"#).unwrap();
    std::fs::set_permissions(&sdk, std::fs::Permissions::from_mode(0o700)).unwrap();
    let token_requests = sdk_dir.join("token-requests");
    let inspected = Arc::new(Mutex::new(Vec::<String>::new()));
    let seen = inspected.clone();
    let api = LocalHttp::start(move |request| {
        if request.method == "GET" && request.target == "/fixture/storage" {
            let latest = seen.lock().unwrap();
            let expected = latest.last().map(|token| format!("Bearer {token}"));
            if expected.is_none() || request.headers.get("authorization") != expected.as_ref() {
                return Err("Storage request did not use the approved child token".into());
            }
            return Ok((200, json!({"ok": true})));
        }
        if request.method != "POST" || request.target != "/oauth2/v1/tokeninfo" {
            return Err("unexpected HTTP route (including any provider revocation)".into());
        }
        let bytes = request.body.strip_prefix(b"access_token=child-fixture-").ok_or("not a child token")?;
        if bytes.is_empty() || !bytes.iter().all(|b| b.is_ascii_hexdigit() || *b == b'-') {
            return Err("invalid fixture token".into());
        }
        seen.lock().unwrap().push(format!("child-fixture-{}", std::str::from_utf8(bytes).unwrap()));
        Ok((200, json!({"scope":READ_SCOPE,"expires_in":1200})))
    });
    let config = GcloudConfig {
        sdk_path: sdk.to_str().unwrap().into(), account_subject: "1001".into(),
        account_email: "operator@example.com".into(), project_id: "asm-fixture".into(), project_number: "123456".into(),
        ceiling: GcloudGrant { service_account_unique_id: ACCOUNT_ID.into(),
            service_account_email: "reader@asm-fixture.iam.gserviceaccount.com".into(), scopes: vec![READ_SCOPE.into(), WRITE_SCOPE.into()],
            project_id: None },
        scope_catalog: [READ_SCOPE, WRITE_SCOPE].into_iter().map(|uri| GcloudScopeOption {
            uri: uri.into(), description: "Storage objects".into(), services: vec![GcloudService {
                name: "storage.googleapis.com".into(), title: "Cloud Storage API".into(), enabled: true,
            }],
        }).collect(),
    };
    let adc = r#"{"type":"authorized_user","client_id":"fixture.apps.googleusercontent.com","client_secret":"fixture-sdk-client-secret","refresh_token":"fixture-sdk-refresh-secret"}"#;
    let generator = GcloudGenerator::with_endpoint_for_tests(&config, adc, &tmp.path().join("operations"),
        reqwest::Url::parse(&api.url("/")).unwrap()).unwrap();
    let env = Env { cli: build_cli(), config: tmp.path().join("config"), secrets: tmp.path().join("secrets") };
    let (approver, running) = generated_manager(tmp.path(), &free_ports(5), workspace().join("dist/bin"));
    let manager = running.0.clone();
    manager.core().install_generator_client(GeneratorRecord { id: "00000000-0000-4000-8000-000000000001".into(),
        name: "gcloud-dev".into(), config: GeneratorConfig::Gcloud(config), revision: 1, position: 0,
        require_exact_scope_match: false,
    }, Arc::new(GeneratorClient::Gcloud(generator))).unwrap();
    let code = manager.create_pairing_code("Storage test".into(), Some(3600), Some(1), vec!["127.0.0.1/8".into()]).unwrap();
    assert_eq!(env.run(&["pair", &manager.general_settings().listening_on, &code.code], None).code, 0);

    let child_marker = tmp.path().join("sentinel-child-started");
    assert_generated_sentinel_rejected(env.run(&[
        "get", "--sentinel", "--no-reaper", "--wait", "30", "--gcloud-scope", READ_SCOPE,
        GCLOUD_TOKEN_NAME, "Try an explicitly requested sentinel",
    ], None));
    assert_generated_sentinel_rejected(env.run(&[
        "exec", "--sentinel", "--hosts", "127.0.0.1", "--wait", "30", "--gcloud-scope", READ_SCOPE,
        GCLOUD_TOKEN_NAME, "--", "/bin/sh", "-c", r#": > "$1""#, "asm-fixture", child_marker.to_str().unwrap(),
    ], None));
    assert!(!child_marker.exists(), "rejected sentinel exec must not launch the child");
    assert!(!token_requests.exists(), "rejected sentinel requests must not invoke gcloud to mint");
    assert!(inspected.lock().unwrap().is_empty());
    assert_eq!(approver.count(), 0);
    assert!(manager.list_leases().is_empty(), "rejected sentinel requests create no lease");

    let first = json_get(&env, &["--gcloud-scope", READ_SCOPE, GCLOUD_TOKEN_NAME, "Read Storage objects"]);
    assert_eq!(first["mode"], "raw");
    assert_eq!(first["files"][0]["delivery"], "raw");
    let id = first["lease_id"].as_str().unwrap();
    assert_eq!(first["generation"]["grant"]["provider"], "gcloud");
    assert_eq!(first["generation"]["grant"]["scope"]["scopes"], json!([READ_SCOPE]));
    assert_eq!(first["generation"]["grant"]["scope"]["service_account_unique_id"], ACCOUNT_ID);
    assert_eq!(first["generation"]["grant"]["scope"]["project_id"], "asm-fixture");
    let path = delivered_path(&first);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), inspected.lock().unwrap()[0]);
    let attempts_before_rejection = std::fs::metadata(&token_requests).unwrap().len();
    let rejected = env.run(&["get", "--raw", "--no-reaper", "--project", "asm-fixture", "--permissions",
        "storage=read", GCLOUD_TOKEN_NAME, "Try managed Storage access"], None);
    assert_ne!(rejected.code, 0);
    assert!(rejected.stderr.contains("no matching Google Cloud connection"), "{}", rejected.stderr);
    assert_eq!(inspected.lock().unwrap().len(), 1, "managed claims never reuse or renew the legacy lease");
    assert_eq!(std::fs::metadata(&token_requests).unwrap().len(), attempts_before_rejection,
        "rejecting managed claims must not invoke gcloud");
    let renewed = json_get(&env, &["--raw", "--refresh", "--lease", id, GCLOUD_TOKEN_NAME, "Continue reading Storage"]);
    assert_eq!(renewed["generation"], first["generation"]);
    assert_eq!(renewed["lease_id"], id);
    assert_eq!(renewed["credential_version"], 2);
    assert_eq!(approver.count(), 1);
    {
        let issued = inspected.lock().unwrap();
        assert_eq!(issued.len(), 2);
        assert_ne!(issued[0], issued[1]);
        assert_eq!(std::fs::read_to_string(path).unwrap(), issued[1]);
    }
    manager.revoke_lease(id.into()).unwrap();
    assert_eq!(env.run(&["get", "--no-reaper", "--lease", id, GCLOUD_TOKEN_NAME, "Ended lease"], None).code, 3);

    // Run a fresh exec after revoking the first authorization. The actual child
    // receives the new token in its environment and reaches the fixture directly.
    let exec_env = Env {
        cli: env.cli.clone(), config: env.config.clone(), secrets: tmp.path().join("exec-must-not-write"),
    };
    let raw_child = r#"set -eu
test "$HTTP_PROXY" = caller-network
test "$SSL_CERT_FILE" = caller-ca
test "$GOOGLE_APPLICATION_CREDENTIALS" = caller-adc
curl --noproxy '*' -fsS -o /dev/null -H "Authorization: Bearer $CLOUDSDK_AUTH_ACCESS_TOKEN" "$1"
printf 'raw-child-ok\n'"#;
    let output = exec_env.run_env(&[
        "exec", "--wait", "30", "--gcloud-scope", READ_SCOPE, GCLOUD_TOKEN_NAME, "--",
        "/bin/sh", "-c", raw_child, "asm-fixture", &api.url("/fixture/storage"),
    ], None, &[
        (GCLOUD_TOKEN_NAME, "stale-token"), ("HTTP_PROXY", "caller-network"),
        ("SSL_CERT_FILE", "caller-ca"), ("GOOGLE_APPLICATION_CREDENTIALS", "caller-adc"),
    ]);
    assert_eq!(output.code, 0, "raw exec failed: {}", output.stderr);
    assert_eq!(output.stdout, "raw-child-ok\n");
    assert!(!exec_env.secrets.exists(), "exec must not open the credential directory");
    assert_eq!(approver.count(), 2);
    assert_eq!(inspected.lock().unwrap().len(), 3);
    assert!(!sdk_dir.join("parent-token-requested").exists(),
        "legacy raw delivery must not request an unscoped parent token");
    assert_generated_leases_are_raw(&manager);
    assert!(manager.list_leases().iter().any(|lease|
        lease.lease_id != id && lease.status == asm_core::ffi::LeaseStatus::Active),
        "leave the fresh exec authorization active at shutdown");

    let query = asm_core::ffi::ActivityQuery { categories: vec![], host_id: None,
        search: String::new(), before_id: None, limit: 1000 };
    let activity = manager.list_activity(query.clone());
    assert!(activity.iter().filter(|e| e.kind == "revocation_unsupported")
        .filter(|e| e.detail.as_deref().unwrap_or_default().contains("credential_expires_at")).count() >= 2);
    for text in [format!("{activity:?} {first} {renewed}"), String::from_utf8_lossy(&std::fs::read(tmp.path().join("data/asm.db")).unwrap()).into_owned(),
        String::from_utf8_lossy(&std::fs::read(tmp.path().join("data/asm.db-wal")).unwrap_or_default()).into_owned()] {
        for secret in ["child-fixture-", "parent-fixture-token", "fixture-sdk-client-secret", "fixture-sdk-refresh-secret"] {
            assert!(!text.contains(secret), "secret fixture material in durable state or public metadata");
        }
    }
    let before_shutdown = activity.iter().filter(|entry| entry.kind == "revocation_unsupported").count();
    drop(running);
    assert_eq!(manager.list_activity(query).iter().filter(|entry| entry.kind == "revocation_unsupported").count(),
        before_shutdown, "shutdown must not attempt Google token revocation");
    api.assert_clean();
}
