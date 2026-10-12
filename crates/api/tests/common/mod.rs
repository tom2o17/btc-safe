//! Shared test login: a fresh user with a live session (no password hashing, so it's fast).
#![allow(dead_code)]

use btc_safe_api::auth::{self, AuthConfig};
use btc_safe_store::sqlx::PgPool;

#[derive(Clone)]
pub struct Session {
    pub user_id: uuid::Uuid,
    pub email: String,
    /// Value for the `Cookie` header.
    pub cookie: String,
    pub csrf: String,
}

pub async fn login(pool: &PgPool, cfg: &AuthConfig) -> Session {
    let mut c = pool.acquire().await.unwrap();
    let email = format!("t-{}@example.test", uuid::Uuid::new_v4());
    let user = btc_safe_store::users::ensure_user(&mut c, &email, false).await.unwrap();
    let (token, csrf) = auth::create_session(&mut c, cfg, user.id).await.unwrap();
    Session { user_id: user.id, email, cookie: format!("{}={token}", cfg.cookie_name()), csrf }
}
