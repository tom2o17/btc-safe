//! BTC/USD price for display only (`GET /price`).
//!
//! The wallet runs on signet, whose coins are worthless; the UI still shows what an amount would be
//! worth at the MAINNET price so people can reason about sizes. This number never feeds validation,
//! fees, or anything else: nothing outside this module and the handler reads it.
//!
//! Fetched server-side (the browser never calls a price API, so no CSP/CORS changes and no user IP
//! leaks to a third party). Sources in order: mempool.space mainnet, then Coinbase spot. One fetch
//! per TTL at most, success or not; on failure the last good value is served with `stale: true`,
//! and with no good value ever, the handler answers 503.

use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{json, Value};
use tokio::sync::Mutex;

use crate::AppState;

pub const MEMPOOL_URL: &str = "https://mempool.space/api/v1/prices";
pub const COINBASE_URL: &str = "https://api.coinbase.com/v2/prices/BTC-USD/spot";
pub const TTL: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceKind {
    Mempool,
    Coinbase,
}

impl SourceKind {
    fn name(self) -> &'static str {
        match self {
            SourceKind::Mempool => "mempool.space",
            SourceKind::Coinbase => "coinbase",
        }
    }

    /// Extracts a USD price from the source's JSON body. Rejects non-finite and non-positive values.
    pub fn parse(self, body: &Value) -> Option<f64> {
        let usd = match self {
            // {"time":..., "USD": 83176, "EUR": ...}
            SourceKind::Mempool => body.get("USD")?.as_f64()?,
            // {"data":{"amount":"83034.565","base":"BTC","currency":"USD"}}
            SourceKind::Coinbase => {
                let d = body.get("data")?;
                if d.get("base")?.as_str()? != "BTC" || d.get("currency")?.as_str()? != "USD" {
                    return None;
                }
                d.get("amount")?.as_str()?.parse::<f64>().ok()?
            }
        };
        (usd.is_finite() && usd > 0.0).then_some(usd)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Quote {
    pub usd: f64,
    pub source: &'static str,
    pub fetched_at: DateTime<Utc>,
    pub stale: bool,
}

struct Cache {
    /// The last good quote; `stale` is set when the latest refresh failed.
    good: Option<Quote>,
    last_attempt: Option<Instant>,
}

pub struct PriceFeed {
    client: reqwest::Client,
    sources: Vec<(SourceKind, String)>,
    ttl: Duration,
    cache: Mutex<Cache>,
}

impl PriceFeed {
    pub fn new(sources: Vec<(SourceKind, String)>, ttl: Duration) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .user_agent("btc-safe/0.1")
            .build()
            .unwrap_or_default();
        PriceFeed { client, sources, ttl, cache: Mutex::new(Cache { good: None, last_attempt: None }) }
    }

    pub fn mainnet() -> Self {
        Self::new(vec![(SourceKind::Mempool, MEMPOOL_URL.into()), (SourceKind::Coinbase, COINBASE_URL.into())], TTL)
    }

    async fn fetch(&self) -> Option<Quote> {
        for (kind, url) in &self.sources {
            let got = async {
                let res = self.client.get(url).send().await.ok()?.error_for_status().ok()?;
                kind.parse(&res.json::<Value>().await.ok()?)
            }
            .await;
            match got {
                Some(usd) => return Some(Quote { usd, source: kind.name(), fetched_at: Utc::now(), stale: false }),
                None => tracing::warn!("price source {} failed", kind.name()),
            }
        }
        None
    }

    /// The current quote: cached if younger than the TTL, else refetched. At most one fetch per
    /// TTL (the lock is held across it, so concurrent callers wait rather than stampede).
    pub async fn get(&self) -> Option<Quote> {
        let mut c = self.cache.lock().await;
        if c.last_attempt.is_none_or(|t| t.elapsed() >= self.ttl) {
            c.last_attempt = Some(Instant::now());
            match self.fetch().await {
                Some(q) => c.good = Some(q),
                None => {
                    if let Some(q) = c.good.as_mut() {
                        q.stale = true;
                    }
                }
            }
        }
        c.good.clone()
    }
}

pub async fn get(State(st): State<AppState>) -> Response {
    match st.price.get().await {
        Some(q) => Json(q).into_response(),
        None => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": "price_unavailable", "message": "BTC price unavailable" }))).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn parses_mempool() {
        let v: Value = serde_json::from_str(r#"{"time":1791424502,"USD":83176,"EUR":74226}"#).unwrap();
        assert_eq!(SourceKind::Mempool.parse(&v), Some(83176.0));
        assert_eq!(SourceKind::Mempool.parse(&json!({"USD": 0})), None);
        assert_eq!(SourceKind::Mempool.parse(&json!({"USD": -1})), None);
        assert_eq!(SourceKind::Mempool.parse(&json!({"USD": "83176"})), None);
        assert_eq!(SourceKind::Mempool.parse(&json!({"EUR": 1})), None);
    }

    #[test]
    fn parses_coinbase() {
        let v: Value = serde_json::from_str(r#"{"data":{"amount":"83034.565","base":"BTC","currency":"USD"}}"#).unwrap();
        assert_eq!(SourceKind::Coinbase.parse(&v), Some(83034.565));
        assert_eq!(SourceKind::Coinbase.parse(&json!({"data":{"amount":"1","base":"ETH","currency":"USD"}})), None);
        assert_eq!(SourceKind::Coinbase.parse(&json!({"data":{"amount":"1","base":"BTC","currency":"EUR"}})), None);
        assert_eq!(SourceKind::Coinbase.parse(&json!({"data":{"amount":"NaN","base":"BTC","currency":"USD"}})), None);
        assert_eq!(SourceKind::Coinbase.parse(&json!({"data":{"amount":83000,"base":"BTC","currency":"USD"}})), None);
    }

    /// A local HTTP server whose body/status can be swapped between requests; counts hits.
    struct Mock {
        url: String,
        hits: Arc<AtomicUsize>,
        reply: Arc<std::sync::Mutex<(u16, String)>>,
    }

    async fn mock(status: u16, body: &str) -> Mock {
        let hits = Arc::new(AtomicUsize::new(0));
        let reply = Arc::new(std::sync::Mutex::new((status, body.to_string())));
        let (h, r) = (hits.clone(), reply.clone());
        let app = axum::Router::new().route(
            "/",
            axum::routing::get(move || {
                let (h, r) = (h.clone(), r.clone());
                async move {
                    h.fetch_add(1, Ordering::SeqCst);
                    let (s, b) = r.lock().unwrap().clone();
                    (StatusCode::from_u16(s).unwrap(), [("content-type", "application/json")], b)
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Mock { url, hits, reply }
    }

    #[tokio::test]
    async fn primary_then_cache() {
        let m = mock(200, r#"{"USD":80000}"#).await;
        let feed = PriceFeed::new(vec![(SourceKind::Mempool, m.url.clone())], Duration::from_secs(60));
        let q = feed.get().await.unwrap();
        assert_eq!((q.usd, q.source, q.stale), (80000.0, "mempool.space", false));
        *m.reply.lock().unwrap() = (200, r#"{"USD":1}"#.into());
        let q2 = feed.get().await.unwrap();
        assert_eq!((q2.usd, q2.stale), (80000.0, false), "served from cache within the TTL");
        assert_eq!(m.hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn falls_back_to_coinbase() {
        let a = mock(500, "oops").await;
        let b = mock(200, r#"{"data":{"amount":"81000.5","base":"BTC","currency":"USD"}}"#).await;
        let feed = PriceFeed::new(vec![(SourceKind::Mempool, a.url.clone()), (SourceKind::Coinbase, b.url.clone())], TTL);
        let q = feed.get().await.unwrap();
        assert_eq!((q.usd, q.source, q.stale), (81000.5, "coinbase", false));
        assert_eq!((a.hits.load(Ordering::SeqCst), b.hits.load(Ordering::SeqCst)), (1, 1));
    }

    #[tokio::test]
    async fn stale_after_failure_and_none_without_history() {
        let m = mock(500, "down").await;
        let feed = PriceFeed::new(vec![(SourceKind::Mempool, m.url.clone())], Duration::ZERO);
        assert_eq!(feed.get().await, None, "never had a good value");

        *m.reply.lock().unwrap() = (200, r#"{"USD":82000}"#.into());
        assert_eq!(feed.get().await.map(|q| (q.usd, q.stale)), Some((82000.0, false)));

        *m.reply.lock().unwrap() = (200, "not json".into());
        let q = feed.get().await.unwrap();
        assert_eq!((q.usd, q.stale), (82000.0, true), "last good value, flagged stale");

        *m.reply.lock().unwrap() = (200, r#"{"USD":83000}"#.into());
        assert_eq!(feed.get().await.map(|q| (q.usd, q.stale)), Some((83000.0, false)), "recovers");
    }

    #[tokio::test]
    async fn failure_is_not_retried_within_ttl() {
        let m = mock(200, r#"{"USD":82000}"#).await;
        let feed = PriceFeed::new(vec![(SourceKind::Mempool, m.url.clone())], Duration::from_millis(300));
        feed.get().await.unwrap();
        tokio::time::sleep(Duration::from_millis(350)).await;
        *m.reply.lock().unwrap() = (503, "".into());
        assert!(feed.get().await.unwrap().stale);
        assert!(feed.get().await.unwrap().stale, "stays stale within the TTL after a failed refresh");
        assert_eq!(m.hits.load(Ordering::SeqCst), 2, "no refetch inside the TTL");
    }
}
