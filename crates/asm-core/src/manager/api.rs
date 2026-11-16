//! HTTPS API (`/v1/...`, plan step 3). Handlers run every blocking call (store, vaults,
//! proxy) on the blocking pool.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use asm_proto::ApiError;
use asm_proto::wire::{
    HealthResponse, LeaseBrief, LeaseInfo, LeasesResponse, MANAGER_NAME, MAX_POLL_WAIT_SECS,
    PairPollQuery, PairRequest, PairResponse, ProxyInfo, RequestBody, RequestState, RequestStatus,
    RevealRequest, SecretEntry, SecretsResponse, WaitQuery,
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
use crate::store::HostRecord;
use crate::vault::VaultStatus;
use crate::vault::names::compute_names;

type Shared = State<Arc<Core>>;

pub struct ApiErr(CoreError);

impl From<CoreError> for ApiErr {
    fn from(e: CoreError) -> Self {
        ApiErr(e)
    }
}

impl IntoResponse for ApiErr {
    fn into_response(self) -> Response {
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
async fn auth(core: &Arc<Core>, headers: &HeaderMap) -> ApiResult<HostRecord> {
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
        Ok(host)
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

async fn secrets(State(core): Shared, headers: HeaderMap) -> ApiResult<Json<SecretsResponse>> {
    let host = auth(&core, &headers).await?;
    let r = blocking(move || {
        let (listings, mut warnings) = core.registry.listings();
        for v in core.registry.all() {
            match v.provider.status() {
                VaultStatus::Ready => {}
                VaultStatus::Locked => warnings.push(format!("{}: vault is locked", v.name)),
                VaultStatus::Error(e) => warnings.push(format!("{}: {e}", v.name)),
            }
        }
        warnings.dedup();
        let t = now();
        let leases: Vec<_> = core
            .store
            .leases_of_host(&host.id)?
            .into_iter()
            .filter(|l| l.is_active(t))
            .collect();
        let secrets = compute_names(&listings)
            .into_iter()
            .map(|n| {
                let lease = leases
                    .iter()
                    .filter(|l| l.vault_id == n.vault_id && l.secret_key == n.meta.key)
                    .max_by_key(|l| {
                        (
                            l.mode == asm_proto::wire::LeaseMode::Sentinel,
                            l.expires_at.unwrap_or(i64::MAX),
                        )
                    })
                    .map(|l| LeaseBrief {
                        lease_id: l.id.clone(),
                        mode: l.mode,
                        expires_at: l.expires_at.map(asm_proto::time::fmt_unix),
                    });
                SecretEntry {
                    name: n.display,
                    vault: n.vault_name,
                    kind: n.meta.kind,
                    fields: n.meta.fields,
                    lease,
                }
            })
            .collect();
        Ok(SecretsResponse { secrets, warnings })
    })
    .await?;
    Ok(Json(r))
}

async fn create_request(
    State(core): Shared,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: std::result::Result<Json<RequestBody>, JsonRejection>,
) -> ApiResult<Response> {
    let host = auth(&core, &headers).await?;
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
    let host = auth(&core, &headers).await?;
    let Query(q) = q.map_err(bad_query)?;
    // Check the pending state without consuming anything, then fetch once when terminal.
    let host_id = host.id.clone();
    let id2 = id.clone();
    let _ = long_poll(
        &core,
        q.wait,
        move |c| {
            let b = lock(&c.book);
            Ok(b.pending
                .iter()
                .any(|p| p.id == id2 && p.host_id.as_deref() == Some(host_id.as_str())))
        },
        |still_pending| !still_pending,
    )
    .await?;
    let r = blocking(move || core.request_state(&host.id, &id)).await?;
    Ok(Json(r))
}

async fn cancel_request(
    State(core): Shared,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<Json<RequestState>> {
    let host = auth(&core, &headers).await?;
    Ok(Json(
        blocking(move || core.cancel_request(&host.id, &id)).await?,
    ))
}

async fn leases(State(core): Shared, headers: HeaderMap) -> ApiResult<Json<LeasesResponse>> {
    let host = auth(&core, &headers).await?;
    let r = blocking(move || {
        let t = now();
        let leases = core
            .store
            .leases_of_host(&host.id)?
            .into_iter()
            .map(|l| LeaseInfo {
                status: l.status(t),
                lease_id: l.id,
                name: l.name,
                mode: l.mode,
                hosts: l.hosts,
                expires_at: l.expires_at.map(asm_proto::time::fmt_unix),
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
        })
    })
    .await?;
    Ok(Json(r))
}
