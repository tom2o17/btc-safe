//! HTTP API (DESIGN.md §5.2, v1). JSON in/out; amounts in satoshis; PSBTs as base64.
//!
//! Auth: per-user accounts with cookie sessions and CSRF tokens (`auth.rs`). Open routes are
//! `GET /health` and the login/signup/setup routes; everything else needs a session, and
//! wallet-scoped routes need membership of that wallet and a role (`roles.rs`). This includes
//! `POST /proposals/{id}/signatures`, which DESIGN.md §6.7 left open: on a public deployment it
//! is now behind login too. Rate limits in `ratelimit.rs`, security headers in `headers.rs`.

use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderValue, Method};
use axum::middleware;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use btc_safe_chain::{ChainSource, MemoryChain};
use btc_safe_core::fees::FeePolicy;
use btc_safe_store::sqlx::PgPool;
use btc_safe_watcher::WalletCache;
use serde_json::{json, Value};

pub mod auth;
mod dev;
mod error;
pub mod headers;
mod ledger;
pub mod mfa;
pub mod price;
mod proposals;
pub mod ratelimit;
pub mod roles;
pub mod signup;
mod views;
mod wallets;

pub use error::ApiError;

pub type ApiResult<T> = Result<T, ApiError>;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub cache: Arc<WalletCache>,
    pub chain: Arc<dyn ChainSource>,
    /// Set when running against the in-process simulator; enables `/dev/*`.
    pub memory: Option<MemoryChain>,
    pub fee_policy: FeePolicy,
    pub auth: Arc<auth::AuthConfig>,
    pub limits: ratelimit::RateLimits,
    /// When set, wallets may only be created/imported on this network (signet in production).
    pub pinned_network: Option<bitcoin::Network>,
    /// Browser origins allowed by CORS (credentials on). Empty: no CORS headers at all, which is
    /// right when the web app proxies /api/* through its own origin.
    pub cors_origins: Vec<String>,
    /// Mainnet BTC/USD for display only (`GET /price`); never read by validation or fees.
    pub price: Arc<price::PriceFeed>,
    /// Depth at which a confirmation is final (`CONFIRMATIONS_FINAL`). Read by the watcher run
    /// from `/sync` and shown in proposal views.
    pub confirmations_final: u32,
}

impl AppState {
    /// Defaults for tests and local runs: secure cookies, no rate limits, no network pin.
    pub fn new(pool: PgPool, cache: Arc<WalletCache>, chain: Arc<dyn ChainSource>, memory: Option<MemoryChain>) -> Self {
        AppState {
            pool,
            cache,
            chain,
            memory,
            fee_policy: FeePolicy::default(),
            auth: Arc::new(auth::AuthConfig::default()),
            limits: ratelimit::RateLimits::unlimited(),
            pinned_network: None,
            cors_origins: vec![],
            price: Arc::new(price::PriceFeed::mainnet()),
            confirmations_final: btc_safe_watcher::DEFAULT_CONFIRMATIONS_FINAL,
        }
    }
}

pub fn router(state: AppState) -> Router {
    let open = Router::new()
        .route("/health", get(health))
        .route("/auth/login", post(auth::login))
        .route("/auth/login/mfa", post(auth::login_mfa))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/me", get(auth::me))
        .route("/auth/signup", get(auth::signup_info).post(auth::signup))
        .route("/auth/setup", get(auth::setup_check).post(auth::setup));

    // Logged in, not wallet-scoped.
    let account = Router::new()
        .route("/auth/invites", post(auth::invite))
        .route("/auth/users", get(auth::users))
        .route("/auth/logout-all", post(auth::logout_all))
        .route("/auth/password", post(auth::change_password))
        .route("/auth/totp/setup", post(auth::totp_setup))
        .route("/auth/totp/enable", post(auth::totp_enable))
        .route("/auth/totp/disable", post(auth::totp_disable))
        .route("/auth/recovery-codes", post(auth::recovery_codes))
        .route("/price", get(price::get))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth::require_user));

    let mut scoped = Router::new()
        .route("/wallets", post(wallets::create).get(wallets::list))
        .route("/wallets/import", post(wallets::import))
        .route("/wallets/{id}", get(wallets::summary).patch(wallets::update).delete(wallets::delete))
        .route("/wallets/{id}/members", get(auth::members_list).post(auth::members_add))
        .route("/wallets/{id}/members/{user}", delete(auth::members_remove).patch(auth::members_update))
        .route("/wallets/{id}/backup", get(wallets::backup))
        .route("/wallets/{id}/addresses", get(wallets::address))
        .route("/wallets/{id}/addresses/{idx}/label", post(wallets::label_address))
        .route("/wallets/{id}/utxos", get(wallets::utxos))
        .route("/wallets/{id}/history", get(wallets::history))
        .route("/wallets/{id}/fees", get(wallets::fees))
        .route("/wallets/{id}/sync", post(wallets::sync))
        .route("/wallets/{id}/proposals", post(proposals::create).get(proposals::list))
        .route("/wallets/{id}/address-book", get(wallets::address_book_list).post(wallets::address_book_add))
        .route("/wallets/{id}/address-book/{entry}", delete(wallets::address_book_delete))
        .route("/wallets/{id}/ledger", get(ledger::get))
        .route("/wallets/{id}/ledger/owners/{owner}", put(ledger::register).delete(ledger::unregister))
        .route("/proposals/{id}", get(proposals::get).delete(proposals::delete))
        .route("/proposals/{id}/signatures", post(proposals::add_signatures))
        .route("/proposals/{id}/execute", post(proposals::execute));
    if state.memory.is_some() {
        scoped = scoped.route("/dev/fund", post(dev::fund)).route("/dev/mine", post(dev::mine)).route("/dev/inject", post(dev::inject)).route("/dev/reorg", post(dev::reorg));
    }
    // route_layer order: the last one added runs first (require_user, then membership).
    let scoped = scoped
        .route_layer(middleware::from_fn_with_state(state.clone(), auth::require_membership))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth::require_user));

    let mut app = open
        .merge(account)
        .merge(scoped)
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(middleware::from_fn_with_state(state.clone(), ratelimit::per_ip))
        .layer(middleware::from_fn_with_state(state.clone(), headers::security_headers));
    if !state.cors_origins.is_empty() {
        let origins: Vec<HeaderValue> = state.cors_origins.iter().filter_map(|o| HeaderValue::from_str(o).ok()).collect();
        app = app.layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(origins)
                .allow_credentials(true)
                .allow_methods([Method::GET, Method::POST, Method::PUT, Method::PATCH, Method::DELETE])
                .allow_headers([header::CONTENT_TYPE, header::HeaderName::from_static("x-csrf-token")]),
        );
    }
    app.layer(tower_http::trace::TraceLayer::new_for_http()).with_state(state)
}

async fn health(State(st): State<AppState>) -> Json<Value> {
    let tip = st.chain.tip().await.ok();
    Json(json!({ "ok": true, "chain": st.chain.describe(), "tip": tip }))
}
