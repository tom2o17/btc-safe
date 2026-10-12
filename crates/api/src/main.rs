//! btc-safe API server.
//!
//! Env:
//!   DATABASE_URL       postgres connection string (required)
//!   CHAIN              "esplora" (default) or "memory" (in-process simulator + /dev routes)
//!   ESPLORA_URL        default https://mempool.space/signet/api. Must serve signet: the genesis
//!                      hash is checked at startup and the server refuses to run otherwise.
//!   NETWORK            signet (default). Mainnet is refused. Other test networks: CHAIN=memory only.
//!   BIND               listen address; default 127.0.0.1:8080, or [::]:$PORT when PORT is set
//!   SYNC_SECS          watcher interval, default 30
//!   CONFIRMATIONS_FINAL  confirmations at which a sent proposal is final, default 2, min 1.
//!                      Below it the proposal is "soft confirmed" and re-checked for reorgs.
//!   COOKIE_SECURE      default true; set false only for local http development
//!   CLIENT_IP_HEADER   proxy header with the real client IP (e.g. x-real-ip); default: TCP peer
//!   CORS_ORIGINS       comma-separated browser origins allowed cross-origin (default none)
//!   WEB_ORIGIN         public web URL, used to print setup links
//!   RATE_IP / RATE_USER / RATE_LOGIN   "<per minute>/<burst>", defaults 300/120, 600/200, 10/5
//!   RATE_SIGNUP / RATE_SIGNUP_GLOBAL   "<per hour>/<burst>", defaults 5/3 per IP, 60/20 overall
//!   OPEN_SIGNUP        "1"/"true": anyone can create an account (default off: invite-only)
//!   MAX_USERS          signup refuses once this many accounts exist (default 1000)
//!   MAX_WALLETS_PER_USER  wallets a non-admin may create/import (default 20; 0 = no limit)
//!   SIGNUP_POW_BITS    signup proof-of-work difficulty (default 20 ≈ 1M hashes)
//!   SIGNUP_SECRET      64 hex chars: key for signup challenges, so several API processes accept
//!                      each other's (default: random per process)
//!   SESSION_HOURS / SESSION_IDLE_MINS  absolute session lifetime / idle timeout (12 / 30)
//!   LOGIN_BACKOFF      "<free failures>/<max seconds>", default 5/900: from the 5th failure in a
//!                      row an account waits 1, 2, 4 … s (capped) before another password check
//!   ADMIN_EMAIL + ADMIN_SETUP_TOKEN    bootstrap: create this admin and accept this one-time
//!                      setup token until the admin has set a password
//!
//! CLI: `btc-safe-api invite <email> [--admin]` creates/resets an account and prints a one-time
//! setup token (72 h); on an existing account that is a reset (password, 2FA and sessions go when
//! the link is used). `btc-safe-api delete-user <email>` removes an account (refused while it is
//! the only admin of a wallet). `invite --admin` refuses to promote an existing account that has a
//! password or signed itself up (anyone can sign up with the address first); after checking who
//! owns it, `btc-safe-api promote <email>` makes it a server admin (its sessions end).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::http::HeaderName;
use bitcoin::Network;
use btc_safe_api::auth::{self, AuthConfig};
use btc_safe_api::ratelimit::RateLimits;
use btc_safe_api::{router, AppState};
use btc_safe_chain::{ChainSource, Esplora, MemoryChain};
use btc_safe_core::fees::FeePolicy;
use btc_safe_watcher::WalletCache;

const SIGNET_GENESIS: &str = "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6";

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

fn rate(k: &str, default: (u32, u32)) -> anyhow::Result<(u32, u32)> {
    match env(k) {
        None => Ok(default),
        Some(v) => {
            let (a, b) = v.split_once('/').ok_or_else(|| anyhow::anyhow!("{k} must look like 300/120"))?;
            Ok((a.parse()?, b.parse()?))
        }
    }
}

fn num<T: std::str::FromStr>(k: &str, default: T) -> anyhow::Result<T>
where
    T::Err: std::fmt::Display,
{
    match env(k) {
        None => Ok(default),
        Some(v) => v.parse().map_err(|e| anyhow::anyhow!("{k}: {e}")),
    }
}

fn auth_config() -> anyhow::Result<AuthConfig> {
    let d = AuthConfig::default();
    let cookie_secure = !matches!(env("COOKIE_SECURE").as_deref(), Some("false" | "0" | "no"));
    let client_ip_header = env("CLIENT_IP_HEADER").map(|h| HeaderName::try_from(h.to_lowercase())).transpose()?;
    let pow_key = match env("SIGNUP_SECRET") {
        Some(h) => {
            let v: Vec<u8> = (0..h.len()).step_by(2).filter_map(|i| h.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok())).collect();
            anyhow::ensure!(h.len() == 64 && v.len() == 32, "SIGNUP_SECRET must be 64 hex chars");
            v.try_into().expect("32 bytes")
        }
        None => d.pow_key,
    };
    let (free, max) = rate("LOGIN_BACKOFF", (5, 900))?;
    let cfg = AuthConfig {
        cookie_secure,
        client_ip_header,
        web_origin: env("WEB_ORIGIN"),
        open_signup: matches!(env("OPEN_SIGNUP").as_deref(), Some("1" | "true" | "yes")),
        max_users: num("MAX_USERS", d.max_users)?,
        max_wallets_per_user: num("MAX_WALLETS_PER_USER", d.max_wallets_per_user)?,
        pow_bits: num("SIGNUP_POW_BITS", d.pow_bits)?,
        pow_key,
        session_ttl: Duration::from_secs(num::<u64>("SESSION_HOURS", 12)?.max(1) * 3600),
        session_idle: Duration::from_secs(num::<u64>("SESSION_IDLE_MINS", 30)?.max(1) * 60),
        backoff_free: free.max(1) as i32,
        backoff_max: Duration::from_secs(u64::from(max.max(1))),
        ..d
    };
    anyhow::ensure!(cfg.pow_bits <= 28, "SIGNUP_POW_BITS above 28 would take a browser minutes");
    Ok(cfg)
}

/// Fail closed unless the Esplora backend is on signet.
async fn check_signet_esplora(url: &str) -> anyhow::Result<()> {
    let u = format!("{}/block-height/0", url.trim_end_matches('/'));
    let got = reqwest::Client::builder().timeout(Duration::from_secs(20)).build()?.get(&u).send().await?.error_for_status()?.text().await?;
    anyhow::ensure!(got.trim() == SIGNET_GENESIS, "ESPLORA_URL {url} is not signet (genesis {}); refusing to start", got.trim());
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,sqlx=warn".into()))
        .init();
    let db = env("DATABASE_URL").ok_or_else(|| anyhow::anyhow!("DATABASE_URL is required"))?;
    let pool = btc_safe_store::connect(&db).await?;
    let cfg = auth_config()?;

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("invite") {
        let email = args.get(1).ok_or_else(|| anyhow::anyhow!("usage: btc-safe-api invite <email> [--admin]"))?;
        let admin = args.iter().any(|a| a == "--admin");
        let mut conn = pool.acquire().await?;
        let (user, token) = auth::issue_setup_token(&mut conn, email, admin, cfg.invite_ttl).await.map_err(|e| anyhow::anyhow!(e.message))?;
        let base = cfg.web_origin.clone().unwrap_or_default();
        println!("{} (admin: {}): {base}/setup?token={token}", user.email, user.is_admin);
        return Ok(());
    }

    if args.first().map(String::as_str) == Some("promote") {
        let email = args.get(1).ok_or_else(|| anyhow::anyhow!("usage: btc-safe-api promote <email>"))?.trim().to_lowercase();
        let mut conn = pool.acquire().await?;
        let u = btc_safe_store::users::user_by_email(&mut conn, &email).await?.ok_or_else(|| anyhow::anyhow!("no user {email}"))?;
        btc_safe_store::users::ensure_user(&mut conn, &email, true).await?;
        btc_safe_store::audit(&mut conn, None, "cli", "user_promoted", serde_json::json!({ "email": email })).await?;
        println!("{email} is now a server admin (created {}, self-signup: {})", u.created_at, u.self_signup);
        return Ok(());
    }

    if args.first().map(String::as_str) == Some("delete-user") {
        let email = args.get(1).ok_or_else(|| anyhow::anyhow!("usage: btc-safe-api delete-user <email>"))?.trim().to_lowercase();
        let mut conn = pool.acquire().await?;
        let user = btc_safe_store::users::user_by_email(&mut conn, &email).await?.ok_or_else(|| anyhow::anyhow!("no user {email}"))?;
        match btc_safe_store::users::delete_user(&mut conn, user.id).await? {
            Ok(()) => println!("deleted {email}"),
            Err(w) => anyhow::bail!("{email} is the only admin of wallets {w:?}; delete them or make someone else admin first"),
        }
        btc_safe_store::audit(&mut conn, None, "cli", "user_deleted", serde_json::json!({ "email": email })).await?;
        return Ok(());
    }

    if env("API_TOKEN").is_some() {
        tracing::warn!("API_TOKEN is no longer used; accounts and sessions replace it");
    }
    let net_name = env("NETWORK").unwrap_or_else(|| "signet".into());
    let network = btc_safe_store::parse_network(&net_name)
        .ok_or_else(|| anyhow::anyhow!("NETWORK={net_name} refused: this build runs on signet (mainnet is disabled)"))?;
    let (chain, memory): (Arc<dyn ChainSource>, Option<MemoryChain>) = match env("CHAIN").as_deref() {
        Some("memory") => {
            let m = MemoryChain::new(network);
            (Arc::new(m.clone()), Some(m))
        }
        Some("esplora") | None => {
            anyhow::ensure!(network == Network::Signet, "CHAIN=esplora is pinned to signet; NETWORK={net_name} refused");
            let url = env("ESPLORA_URL").unwrap_or_else(|| "https://mempool.space/signet/api".into());
            check_signet_esplora(&url).await?;
            (Arc::new(Esplora::new(&url)?), None)
        }
        Some(other) => anyhow::bail!("unknown CHAIN {other}"),
    };

    if let Some(email) = env("ADMIN_EMAIL") {
        let mut conn = pool.acquire().await?;
        match env("ADMIN_SETUP_TOKEN") {
            Some(tok) => {
                // Logged, not fatal: a refused bootstrap (e.g. someone signed up with that email)
                // must not keep the API from starting.
                match auth::bootstrap_admin(&mut conn, &email, &tok, Duration::from_secs(7 * 24 * 3600)).await {
                    Ok(pending) => tracing::info!(pending, "admin bootstrap for {email}"),
                    Err(e) => tracing::error!("admin bootstrap for {email} refused: {}", e.message),
                }
            }
            None => tracing::warn!("ADMIN_EMAIL set without ADMIN_SETUP_TOKEN; nothing bootstrapped"),
        }
    }

    let cache = Arc::new(WalletCache::new());
    let secs: u64 = env("SYNC_SECS").and_then(|s| s.parse().ok()).unwrap_or(30);
    let confirmations_final = btc_safe_watcher::parse_confirmations_final(env("CONFIRMATIONS_FINAL").as_deref()).map_err(anyhow::Error::msg)?;
    tracing::info!(confirmations_final, "final after {confirmations_final} confirmation(s)");
    tokio::spawn(btc_safe_watcher::run(pool.clone(), cache.clone(), chain.clone(), Duration::from_secs(secs.max(1)), confirmations_final));
    let purge_pool = pool.clone();
    let idle = cfg.session_idle.as_secs() as i64;
    tokio::spawn(async move {
        loop {
            if let Ok(mut c) = purge_pool.acquire().await {
                if let Err(e) = btc_safe_store::users::purge_expired(&mut c, idle).await {
                    tracing::warn!("session purge: {e}");
                }
            }
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    });

    let state = AppState {
        pool,
        cache,
        chain: chain.clone(),
        memory,
        fee_policy: FeePolicy::default(),
        auth: Arc::new(cfg),
        limits: RateLimits::shared(
            rate("RATE_IP", (300, 120))?,
            rate("RATE_USER", (600, 200))?,
            rate("RATE_LOGIN", (10, 5))?,
            rate("RATE_SIGNUP", (5, 3))?,
            rate("RATE_SIGNUP_GLOBAL", (60, 20))?,
        ),
        pinned_network: Some(network),
        cors_origins: env("CORS_ORIGINS").map(|v| v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()).unwrap_or_default(),
        price: Arc::new(btc_safe_api::price::PriceFeed::mainnet()),
        confirmations_final,
    };
    let bind = env("BIND").unwrap_or_else(|| match env("PORT") {
        Some(p) => format!("[::]:{p}"),
        None => "127.0.0.1:8080".into(),
    });
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(
        "btc-safe api on {bind} ({}, cookie_secure={}, open_signup={}, max_users={}, max_wallets_per_user={})",
        chain.describe(),
        state.auth.cookie_secure,
        state.auth.open_signup,
        state.auth.max_users,
        state.auth.max_wallets_per_user
    );
    axum::serve(listener, router(state).into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}
