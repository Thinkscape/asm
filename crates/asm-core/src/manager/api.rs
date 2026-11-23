//! HTTPS API (`/v1/...`, plan step 3). Handlers run every blocking call (store, vaults,
//! proxy) on the blocking pool.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use asm_proto::{ApiError, ErrorCode};
use asm_proto::generators::{GenerationSelection, SourceKind};
use asm_proto::wire::{
    CAPABILITY_BROADER_LEASE_REUSE_V1, CAPABILITY_LOGIN_BROKER_V1, CAPABILITY_LOGIN_GRANT_V1,
    CAPABILITY_GCLOUD_ACCESS_V1, CAPABILITY_GENERATED_CREDENTIALS_V1, CAPABILITY_GITHUB_EXPLICIT_SCOPE_V1,
    CAPABILITY_OPERATOR_SELECTED_GRANT_V1, CAPABILITY_OPERATOR_SELECTED_PROJECT_V1,
    CAPABILITY_SECRET_FIELDS_V1, HealthResponse, LeaseBrief,
    LeaseInfo, LeasesResponse, MANAGER_NAME, MAX_POLL_WAIT_SECS,
    PairPollQuery, PairRequest, PairResponse, ProxyInfo, RequestBody, RequestState, RequestStatus,
    RevealRequest, SecretsResponse, WaitQuery,
};
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use tokio::time::Instant;

use super::{Core, lock, now};
use crate::error::{CoreError, Result};
use crate::store::{HostRecord, LeaseRecord};

type Shared = State<Arc<Core>>;

pub struct ApiErr(CoreError);

impl From<CoreError> for ApiErr {
    fn from(e: CoreError) -> Self {
        ApiErr(e)
    }
}

impl IntoResponse for ApiErr {
    fn into_response(self) -> Response {
        match self.0.code {
            ErrorCode::Internal => log::error!("manager API: {}", self.0.message),
            ErrorCode::VaultUnavailable => log::warn!("manager API: {}", self.0.message),
            _ => {}
        }
        let status = StatusCode::from_u16(self.0.code.http_status())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body = ApiError::from(self.0).to_json();
        (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
    }
}

type ApiResult<T> = std::result::Result<T, ApiErr>;

fn bad_json(e: JsonRejection) -> ApiErr {
    ApiErr(CoreError::invalid(format!(
        "invalid request body: {}",
        e.body_text()
    )))
}
fn bad_query(e: QueryRejection) -> ApiErr {
    ApiErr(CoreError::invalid(format!(
        "invalid query: {}",
        e.body_text()
    )))
}

/// Run blocking core work on the blocking pool.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T> + Send + 'static,
) -> ApiResult<T> {
    match tokio::task::spawn_blocking(f).await {
        Ok(r) => r.map_err(ApiErr),
        Err(e) => Err(ApiErr(CoreError::internal(format!("task failed: {e}")))),
    }
}

pub fn router(core: Arc<Core>) -> Router {
    let v1 = Router::new()
        .route("/health", get(health))
        .route("/ca.crt", get(ca_cert))
        .route("/pair", post(pair_start))
        .route("/pair/{pair_id}/reveal", post(pair_reveal))
        .route("/pair/{pair_id}", get(pair_poll))
        .route("/secrets", get(secrets))
        .route("/requests", post(create_request))
        .route("/requests/{id}", get(get_request).delete(cancel_request))
        .route("/leases", get(leases))
        .route("/proxy-info", get(proxy_info));
    Router::new()
        .nest(asm_proto::wire::API_PREFIX, v1)
        .fallback(|| async { ApiErr(CoreError::not_found("no such endpoint")) })
        .layer(DefaultBodyLimit::max(256 * 1024))
        .with_state(core)
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = v.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim().to_string())
        .filter(|t| !t.is_empty())
}

/// Authenticate the calling host and record `last_seen`.
async fn auth(core: &Arc<Core>, headers: &HeaderMap) -> ApiResult<(HostRecord, [u8; 32])> {
    let Some(token) = bearer(headers) else {
        return Err(ApiErr(CoreError::unauthorized(
            "missing bearer token; run asm pair",
        )));
    };
    let core = core.clone();
    blocking(move || {
        let hash = asm_proto::crypto::sha256(token.as_bytes());
        let host = core
            .store
            .host_by_token(&hash)?
            .ok_or_else(|| CoreError::unauthorized("token rejected; run asm pair"))?;
        core.store.touch_host(&host.id, now())?;
        Ok((host, hash))
    })
    .await
}

fn wait_deadline(wait: Option<u64>) -> Instant {
    Instant::now() + Duration::from_secs(wait.unwrap_or(0).min(MAX_POLL_WAIT_SECS))
}

/// Re-run `check` until it reports a terminal state, the deadline passes, or the client goes away.
async fn long_poll<T: Send + 'static>(
    core: &Arc<Core>,
    wait: Option<u64>,
    check: impl Fn(&Core) -> Result<T> + Send + Sync + Clone + 'static,
    done: impl Fn(&T) -> bool,
) -> ApiResult<T> {
    let deadline = wait_deadline(wait);
    let mut rx = core.changes.subscribe();
    loop {
        let c = core.clone();
        let f = check.clone();
        let v = blocking(move || f(&c)).await?;
        if done(&v) || Instant::now() >= deadline {
            return Ok(v);
        }
        match tokio::time::timeout_at(deadline, rx.changed()).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return Ok(v),
            Err(_) => {
                // Deadline: one last check so an expiry at the deadline is reported.
                let c = core.clone();
                return blocking(move || check(&c)).await;
            }
        }
    }
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        name: MANAGER_NAME.to_string(),
        version: asm_proto::VERSION.to_string(),
        capabilities: vec![
            CAPABILITY_GENERATED_CREDENTIALS_V1.into(),
            CAPABILITY_GITHUB_EXPLICIT_SCOPE_V1.into(),
            CAPABILITY_GCLOUD_ACCESS_V1.into(),
            CAPABILITY_SECRET_FIELDS_V1.into(),
            CAPABILITY_OPERATOR_SELECTED_GRANT_V1.into(),
            CAPABILITY_OPERATOR_SELECTED_PROJECT_V1.into(),
            CAPABILITY_BROADER_LEASE_REUSE_V1.into(),
            CAPABILITY_LOGIN_GRANT_V1.into(),
            CAPABILITY_LOGIN_BROKER_V1.into(),
        ],
    })
}

async fn ca_cert(State(core): Shared) -> ApiResult<Response> {
    let pem = blocking(move || core.proxy.ca_pem()).await?;
    Ok(([(header::CONTENT_TYPE, "application/x-pem-file")], pem).into_response())
}

async fn pair_start(
    State(core): Shared,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    body: std::result::Result<Json<PairRequest>, JsonRejection>,
) -> ApiResult<Json<PairResponse>> {
    let Json(req) = body.map_err(bad_json)?;
    let ip = remote.ip().to_canonical().to_string();
    Ok(Json(blocking(move || core.pair_start(req, &ip)).await?))
}

async fn pair_reveal(
    State(core): Shared,
    Path(pair_id): Path<String>,
    body: std::result::Result<Json<RevealRequest>, JsonRejection>,
) -> ApiResult<Json<PairResponse>> {
    let Json(req) = body.map_err(bad_json)?;
    Ok(Json(
        blocking(move || core.pair_reveal(&pair_id, req)).await?,
    ))
}

async fn pair_poll(
    State(core): Shared,
    Path(pair_id): Path<String>,
    q: std::result::Result<Query<PairPollQuery>, QueryRejection>,
) -> ApiResult<Json<PairResponse>> {
    let Query(q) = q.map_err(bad_query)?;
    let token = q.poll_token.clone();
    let r = long_poll(
        &core,
        q.wait,
        move |c| c.pair_poll(&pair_id, &token),
        |r| {
            !matches!(
                r,
                PairResponse::Pending { .. } | PairResponse::AwaitingReveal { .. }
            )
        },
    )
    .await?;
    Ok(Json(r))
}

fn lease_generation(lease: &LeaseRecord) -> Option<GenerationSelection> {
    Some(GenerationSelection {
        generator_id: lease.vault_id.clone(),
        generator_revision: lease.generator_revision?,
        grant: lease.generation.clone()?,
    })
}

fn lease_brief(lease: &LeaseRecord) -> LeaseBrief {
    LeaseBrief {
        lease_id: lease.id.clone(),
        mode: lease.mode,
        expires_at: lease.expires_at.map(asm_proto::time::fmt_unix),
        generation: lease_generation(lease),
        credential_expires_at: lease.credential_expires_at.map(asm_proto::time::fmt_unix),
        credential_version: (lease.source_kind == SourceKind::Generator).then_some(lease.credential_version),
        generator_name: (lease.source_kind == SourceKind::Generator).then(|| lease.vault_name.clone()),
    }
}

async fn secrets(State(core): Shared, headers: HeaderMap) -> ApiResult<Json<SecretsResponse>> {
    let (host, _) = auth(&core, &headers).await?;
    let r = blocking(move || {
        let mut catalog = core.secret_catalog()?;
        let t = now();
        let leases = core.store.leases_of_host(&host.id)?;
        for (index, entry) in catalog.wire_entries.iter_mut().enumerate() {
            entry.lease = if entry.source_kind == SourceKind::Vault {
                let source = &catalog.static_entries[index];
                leases.iter().filter(|lease| {
                    lease.source_kind == SourceKind::Vault && lease.is_active(t)
                        && lease.vault_id == source.vault_id && lease.secret_key == source.meta.key
                }).max_by_key(|lease| (
                    lease.mode == asm_proto::wire::LeaseMode::Sentinel,
                    lease.expires_at.unwrap_or(i64::MAX),
                )).map(lease_brief)
            } else {
                // Ended latest approvals deliberately hide older active identities.
                leases.iter().filter(|lease| {
                    lease.source_kind == SourceKind::Generator
                        && entry.generators.iter().any(|g| g.generator_id == lease.vault_id)
                }).max_by_key(|lease| lease.approval_order)
                    .filter(|lease| lease.is_active(t)).map(lease_brief)
            };
        }
        Ok(SecretsResponse { secrets: catalog.wire_entries })
    }).await?;
    Ok(Json(r))
}

async fn create_request(
    State(core): Shared,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: std::result::Result<Json<RequestBody>, JsonRejection>,
) -> ApiResult<Response> {
    let (host, _) = auth(&core, &headers).await?;
    let Json(body) = body.map_err(bad_json)?;
    let address = remote.ip().to_canonical().to_string();
    let state = blocking(move || core.create_request(&host, &address, body)).await?;
    let code = if state.status == RequestStatus::Pending {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    };
    Ok((code, Json(state)).into_response())
}

async fn get_request(
    State(core): Shared,
    headers: HeaderMap,
    Path(id): Path<String>,
    q: std::result::Result<Query<WaitQuery>, QueryRejection>,
) -> ApiResult<Json<RequestState>> {
    let (host, proof) = auth(&core, &headers).await?;
    let Query(q) = q.map_err(bad_query)?;
    // Check the pending state without consuming anything, then fetch once when terminal.
    let host_id = host.id.clone();
    let id2 = id.clone();
    let _ = long_poll(
        &core,
        q.wait,
        move |c| Ok(lock(&c.book).pending_for_caller(&host_id, &id2).is_some()),
        |still_pending| !still_pending,
    )
    .await?;
    let r = blocking(move || core.request_state_with_proof(&host.id, &id, Some(&proof))).await?;
    Ok(Json(r))
}

async fn cancel_request(
    State(core): Shared,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<RequestState>> {
    let (host, proof) = auth(&core, &headers).await?;
    Ok(Json(
        blocking(move || core.cancel_request_with_proof(&host.id, &id, Some(&proof))).await?,
    ))
}

async fn leases(State(core): Shared, headers: HeaderMap) -> ApiResult<Json<LeasesResponse>> {
    let (host, _) = auth(&core, &headers).await?;
    let r = blocking(move || {
        let t = now();
        let leases = core
            .store
            .leases_of_host(&host.id)?
            .into_iter()
            .map(|l| LeaseInfo {
                source_kind: l.source_kind,
                generation: lease_generation(&l),
                credential_expires_at: l.credential_expires_at.map(asm_proto::time::fmt_unix),
                credential_version: (l.source_kind == SourceKind::Generator).then_some(l.credential_version),
                generator_name: (l.source_kind == SourceKind::Generator).then(|| l.vault_name.clone()),
                fields: l.fields.iter().map(|f| f.field.clone()).collect(),
                status: l.status(t),
                lease_id: l.id,
                name: l.name,
                mode: l.mode,
                hosts: l.hosts,
                expires_at: l.expires_at.map(asm_proto::time::fmt_unix),
                login: l.login,
            })
            .collect();
        Ok(LeasesResponse { leases })
    })
    .await?;
    Ok(Json(r))
}

/// Host part of a `Host` header (`name:port`, `[v6]:port`, `name`).
fn host_header_name(headers: &HeaderMap) -> Option<String> {
    let v = headers.get(header::HOST)?.to_str().ok()?.trim();
    let name = if let Some(rest) = v.strip_prefix('[') {
        rest.split(']').next()?
    } else {
        v.rsplit_once(':').map(|(h, _)| h).unwrap_or(v)
    };
    (!name.is_empty()).then(|| name.to_string())
}

async fn proxy_info(State(core): Shared, headers: HeaderMap) -> ApiResult<Json<ProxyInfo>> {
    let _host = auth(&core, &headers).await?;
    let fallback = host_header_name(&headers);
    let r = blocking(move || {
        let s = core.settings();
        let mut hints = s.proxy_hints.clone();
        if hints.is_empty() {
            // No hints configured: the name the agent used to reach the manager.
            hints.extend(fallback);
        }
        Ok(ProxyInfo {
            port: core.proxy.config().port,
            hints,
            ca_sha256: core.proxy.ca_sha256_hex()?,
            firewall_blocks_proxy: core.firewall_blocks_proxy(),
            proxy_auth: core.proxy.config().require_auth,
            browser_ca_pem: Some(core.proxy.browser_ca_pem()?),
        })
    })
    .await?;
    Ok(Json(r))
}
