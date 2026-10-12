//! Accounts, sessions, one-time setup tokens and wallet membership (migration 0003).
//! Token columns hold SHA-256 hashes; callers hash before calling in here.

use chrono::{DateTime, Utc};
use sqlx::{PgConnection, Row};
use uuid::Uuid;

use crate::{Result, StoreError, WalletRow};

#[derive(Debug, Clone)]
pub struct UserRow {
    pub id: Uuid,
    pub email: String,
    pub password_hash: Option<String>,
    pub is_admin: bool,
    pub created_at: DateTime<Utc>,
    /// Consecutive failed logins, and the time before which password checks are refused.
    pub failed_logins: i32,
    pub locked_until: Option<DateTime<Utc>>,
    pub totp_enabled: bool,
    /// Created through public signup (email never verified).
    pub self_signup: bool,
}

fn user_from(r: &sqlx::postgres::PgRow) -> Result<UserRow> {
    Ok(UserRow {
        id: r.try_get("id")?,
        email: r.try_get("email")?,
        password_hash: r.try_get("password_hash")?,
        is_admin: r.try_get("is_admin")?,
        created_at: r.try_get("created_at")?,
        failed_logins: r.try_get("failed_logins")?,
        locked_until: r.try_get("locked_until")?,
        totp_enabled: r.try_get("totp_enabled")?,
        self_signup: r.try_get("self_signup")?,
    })
}

const USER_COLS: &str = "id, email, password_hash, is_admin, created_at, failed_logins, locked_until, totp_secret IS NOT NULL AS totp_enabled, self_signup";

pub async fn user_by_email(conn: &mut PgConnection, email: &str) -> Result<Option<UserRow>> {
    let r = sqlx::query(sqlx::AssertSqlSafe(format!("SELECT {USER_COLS} FROM users WHERE email = $1")))
        .bind(email)
        .fetch_optional(&mut *conn)
        .await?;
    r.as_ref().map(user_from).transpose()
}

pub async fn user_by_id(conn: &mut PgConnection, id: Uuid) -> Result<UserRow> {
    let r = sqlx::query(sqlx::AssertSqlSafe(format!("SELECT {USER_COLS} FROM users WHERE id = $1")))
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(StoreError::NotFound)?;
    user_from(&r)
}

/// Insert a user, or return the existing one with that email. `is_admin` only ever upgrades; an
/// upgrade is a privilege change, so the user's existing sessions end (they log in again).
pub async fn ensure_user(conn: &mut PgConnection, email: &str, is_admin: bool) -> Result<UserRow> {
    let before = user_by_email(conn, email).await?;
    let r = sqlx::query(sqlx::AssertSqlSafe(format!(
        "INSERT INTO users (id, email, is_admin) VALUES ($1, $2, $3) \
         ON CONFLICT (email) DO UPDATE SET is_admin = users.is_admin OR EXCLUDED.is_admin \
         RETURNING {USER_COLS}"
    )))
    .bind(Uuid::new_v4())
    .bind(email)
    .bind(is_admin)
    .fetch_one(&mut *conn)
    .await?;
    let user = user_from(&r)?;
    if before.is_some_and(|b| !b.is_admin && user.is_admin) {
        delete_user_sessions(conn, user.id).await?;
    }
    Ok(user)
}

/// Self-service signup: insert a brand-new user with a password. None if the email is taken
/// (whether or not that account has finished setup): signup never touches an existing account.
pub async fn insert_new_user(conn: &mut PgConnection, email: &str, password_hash: &str) -> Result<Option<UserRow>> {
    let r = sqlx::query(sqlx::AssertSqlSafe(format!(
        "INSERT INTO users (id, email, password_hash, self_signup) VALUES ($1, $2, $3, true) ON CONFLICT (email) DO NOTHING RETURNING {USER_COLS}"
    )))
    .bind(Uuid::new_v4())
    .bind(email)
    .bind(password_hash)
    .fetch_optional(&mut *conn)
    .await?;
    r.as_ref().map(user_from).transpose()
}

pub async fn count_users(conn: &mut PgConnection) -> Result<i64> {
    Ok(sqlx::query("SELECT count(*) AS n FROM users").fetch_one(&mut *conn).await?.try_get("n")?)
}

// --- login backoff ---

/// Record a failed password (or second-factor) check. From the `free`-th consecutive failure on,
/// password checks are refused for 2^(n - free) seconds, capped at `max_secs`. Returns the new
/// failure count and lock time.
pub async fn record_login_failure(conn: &mut PgConnection, user_id: Uuid, free: i32, max_secs: i64) -> Result<(i32, Option<DateTime<Utc>>)> {
    let r = sqlx::query(
        "UPDATE users SET failed_logins = failed_logins + 1, \
           locked_until = CASE WHEN failed_logins + 1 >= $2 \
             THEN now() + make_interval(secs => LEAST($3::float8, power(2::float8, LEAST(failed_logins + 1 - $2, 40)::float8))) \
             ELSE locked_until END \
         WHERE id = $1 RETURNING failed_logins, locked_until",
    )
    .bind(user_id)
    .bind(free)
    .bind(max_secs as f64)
    .fetch_one(&mut *conn)
    .await?;
    Ok((r.try_get("failed_logins")?, r.try_get("locked_until")?))
}

pub async fn reset_login_failures(conn: &mut PgConnection, user_id: Uuid) -> Result<()> {
    sqlx::query("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = $1").bind(user_id).execute(&mut *conn).await?;
    Ok(())
}

// --- known devices ---

pub async fn insert_known_device(conn: &mut PgConnection, token_hash: &[u8], user_id: Uuid) -> Result<()> {
    sqlx::query("INSERT INTO known_devices (token_hash, user_id) VALUES ($1, $2) ON CONFLICT (token_hash) DO NOTHING")
        .bind(token_hash)
        .bind(user_id)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// The user a device token belongs to, if it is younger than `max_age_days`.
pub async fn known_device_user(conn: &mut PgConnection, token_hash: &[u8], max_age_days: i32) -> Result<Option<Uuid>> {
    let r = sqlx::query(
        "UPDATE known_devices SET last_used_at = now() WHERE token_hash = $1 AND created_at > now() - make_interval(days => $2) RETURNING user_id",
    )
    .bind(token_hash)
    .bind(max_age_days)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(r.map(|r| r.try_get("user_id")).transpose()?)
}

pub async fn delete_known_devices(conn: &mut PgConnection, user_id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM known_devices WHERE user_id = $1").bind(user_id).execute(&mut *conn).await?;
    Ok(())
}

// --- second factor ---

pub async fn totp_secret(conn: &mut PgConnection, user_id: Uuid) -> Result<Option<Vec<u8>>> {
    Ok(sqlx::query("SELECT totp_secret FROM users WHERE id = $1").bind(user_id).fetch_one(&mut *conn).await?.try_get("totp_secret")?)
}

pub async fn set_totp_pending(conn: &mut PgConnection, user_id: Uuid, secret: &[u8], until: DateTime<Utc>) -> Result<()> {
    sqlx::query("UPDATE users SET totp_pending = $2, totp_pending_until = $3 WHERE id = $1")
        .bind(user_id)
        .bind(secret)
        .bind(until)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// The pending (not yet confirmed) secret, if it hasn't expired.
pub async fn totp_pending(conn: &mut PgConnection, user_id: Uuid) -> Result<Option<Vec<u8>>> {
    Ok(sqlx::query("SELECT CASE WHEN totp_pending_until > now() THEN totp_pending END AS p FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&mut *conn)
        .await?
        .try_get("p")?)
}

/// Make the pending secret the live one, with `step` as the last accepted step.
pub async fn enable_totp(conn: &mut PgConnection, user_id: Uuid, secret: &[u8], step: i64) -> Result<()> {
    sqlx::query("UPDATE users SET totp_secret = $2, totp_last_step = $3, totp_pending = NULL, totp_pending_until = NULL WHERE id = $1")
        .bind(user_id)
        .bind(secret)
        .bind(step)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Remove the second factor and every recovery code.
pub async fn disable_totp(conn: &mut PgConnection, user_id: Uuid) -> Result<()> {
    sqlx::query("UPDATE users SET totp_secret = NULL, totp_last_step = NULL, totp_pending = NULL, totp_pending_until = NULL WHERE id = $1")
        .bind(user_id)
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1").bind(user_id).execute(&mut *conn).await?;
    Ok(())
}

/// Accept a TOTP step only if it is later than the last accepted one (no replay, including
/// concurrent submissions of the same code: the conditional UPDATE lets exactly one through).
pub async fn advance_totp_step(conn: &mut PgConnection, user_id: Uuid, step: i64) -> Result<bool> {
    let n = sqlx::query("UPDATE users SET totp_last_step = $2 WHERE id = $1 AND totp_secret IS NOT NULL AND (totp_last_step IS NULL OR totp_last_step < $2)")
        .bind(user_id)
        .bind(step)
        .execute(&mut *conn)
        .await?
        .rows_affected();
    Ok(n == 1)
}

pub async fn replace_recovery_codes(conn: &mut PgConnection, user_id: Uuid, hashes: &[Vec<u8>]) -> Result<()> {
    sqlx::query("DELETE FROM recovery_codes WHERE user_id = $1").bind(user_id).execute(&mut *conn).await?;
    for h in hashes {
        sqlx::query("INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)").bind(user_id).bind(h).execute(&mut *conn).await?;
    }
    Ok(())
}

/// Spend a recovery code: true exactly once per code.
pub async fn use_recovery_code(conn: &mut PgConnection, user_id: Uuid, hash: &[u8]) -> Result<bool> {
    let n = sqlx::query("UPDATE recovery_codes SET used_at = now() WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL")
        .bind(user_id)
        .bind(hash)
        .execute(&mut *conn)
        .await?
        .rows_affected();
    Ok(n == 1)
}

pub async fn recovery_codes_left(conn: &mut PgConnection, user_id: Uuid) -> Result<i64> {
    Ok(sqlx::query("SELECT count(*) AS n FROM recovery_codes WHERE user_id = $1 AND used_at IS NULL")
        .bind(user_id)
        .fetch_one(&mut *conn)
        .await?
        .try_get("n")?)
}

// --- login challenges (password ok, second factor pending) ---

/// Issue a challenge; the user's earlier open challenges are dropped (one at a time, so
/// attempts can't be stockpiled across many challenges).
pub async fn insert_login_challenge(conn: &mut PgConnection, token_hash: &[u8], user_id: Uuid, expires_at: DateTime<Utc>) -> Result<()> {
    sqlx::query("DELETE FROM login_challenges WHERE user_id = $1").bind(user_id).execute(&mut *conn).await?;
    sqlx::query("INSERT INTO login_challenges (token_hash, user_id, expires_at) VALUES ($1, $2, $3)")
        .bind(token_hash)
        .bind(user_id)
        .bind(expires_at)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Count an attempt against a live challenge and return its user. A challenge allows
/// `max_attempts` tries; past that (or expired) it is deleted and None is returned.
pub async fn attempt_login_challenge(conn: &mut PgConnection, token_hash: &[u8], max_attempts: i32) -> Result<Option<Uuid>> {
    let r = sqlx::query(
        "UPDATE login_challenges SET attempts = attempts + 1 WHERE token_hash = $1 AND expires_at > now() AND attempts < $2 RETURNING user_id",
    )
    .bind(token_hash)
    .bind(max_attempts)
    .fetch_optional(&mut *conn)
    .await?;
    if r.is_none() {
        delete_login_challenge(conn, token_hash).await?;
    }
    Ok(r.map(|r| r.try_get("user_id")).transpose()?)
}

pub async fn delete_login_challenge(conn: &mut PgConnection, token_hash: &[u8]) -> Result<()> {
    sqlx::query("DELETE FROM login_challenges WHERE token_hash = $1").bind(token_hash).execute(&mut *conn).await?;
    Ok(())
}

pub async fn set_password_hash(conn: &mut PgConnection, user_id: Uuid, hash: &str) -> Result<()> {
    sqlx::query("UPDATE users SET password_hash = $2 WHERE id = $1").bind(user_id).bind(hash).execute(&mut *conn).await?;
    Ok(())
}

pub async fn list_users(conn: &mut PgConnection) -> Result<Vec<UserRow>> {
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!("SELECT {USER_COLS} FROM users ORDER BY created_at")))
        .fetch_all(&mut *conn)
        .await?;
    rows.iter().map(user_from).collect()
}

/// Delete an account (sessions, setup tokens and memberships cascade). Refused while the user is
/// the only admin of a wallet (which includes being its only member), so no wallet is left
/// without anyone who can manage it.
pub async fn delete_user(conn: &mut PgConnection, user_id: Uuid) -> Result<std::result::Result<(), Vec<Uuid>>> {
    let sole: Vec<Uuid> = sqlx::query(
        "SELECT m.wallet_id FROM wallet_members m WHERE m.user_id = $1 AND m.role = 'admin' \
         AND NOT EXISTS (SELECT 1 FROM wallet_members o WHERE o.wallet_id = m.wallet_id AND o.user_id <> $1 AND o.role = 'admin')",
    )
    .bind(user_id)
    .fetch_all(&mut *conn)
    .await?
    .iter()
    .map(|r| r.try_get("wallet_id"))
    .collect::<std::result::Result<_, _>>()?;
    if !sole.is_empty() {
        return Ok(Err(sole));
    }
    sqlx::query("DELETE FROM users WHERE id = $1").bind(user_id).execute(&mut *conn).await?;
    Ok(Ok(()))
}

// --- sessions ---

pub async fn insert_session(conn: &mut PgConnection, token_hash: &[u8], user_id: Uuid, csrf: &str, expires_at: DateTime<Utc>) -> Result<()> {
    sqlx::query("INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at) VALUES ($1, $2, $3, $4)")
        .bind(token_hash)
        .bind(user_id)
        .bind(csrf)
        .bind(expires_at)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// A live session as seen by a request.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub token_hash: Vec<u8>,
    pub user: UserRow,
    pub csrf: String,
    pub expires_at: DateTime<Utc>,
}

/// The live session for a token hash, touching its idle clock. Sessions past their absolute
/// expiry, or idle for `idle_secs` or more, are not returned (and are deleted).
pub async fn session_user(conn: &mut PgConnection, token_hash: &[u8], idle_secs: i64) -> Result<Option<SessionInfo>> {
    let r = sqlx::query(
        "UPDATE sessions SET last_seen_at = now() \
         WHERE token_hash = $1 AND expires_at > now() AND last_seen_at > now() - make_interval(secs => $2::float8) \
         RETURNING user_id, csrf_token, expires_at",
    )
    .bind(token_hash)
    .bind(idle_secs as f64)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(r) = r else {
        delete_session(conn, token_hash).await?;
        return Ok(None);
    };
    let user = user_by_id(conn, r.try_get("user_id")?).await?;
    Ok(Some(SessionInfo { token_hash: token_hash.to_vec(), user, csrf: r.try_get("csrf_token")?, expires_at: r.try_get("expires_at")? }))
}

/// Count a wrong password/code typed on an account page in this session. Returns the new count.
pub async fn session_reauth_failure(conn: &mut PgConnection, token_hash: &[u8]) -> Result<i32> {
    let r = sqlx::query("UPDATE sessions SET reauth_failures = reauth_failures + 1 WHERE token_hash = $1 RETURNING reauth_failures")
        .bind(token_hash)
        .fetch_optional(&mut *conn)
        .await?;
    Ok(r.map(|r| r.try_get("reauth_failures")).transpose()?.unwrap_or(i32::MAX))
}

/// Revoke the user's unused setup (invite/reset) links.
pub async fn revoke_setup_tokens(conn: &mut PgConnection, user_id: Uuid) -> Result<()> {
    sqlx::query("UPDATE setup_tokens SET used_at = now() WHERE user_id = $1 AND used_at IS NULL").bind(user_id).execute(&mut *conn).await?;
    Ok(())
}

pub async fn delete_session(conn: &mut PgConnection, token_hash: &[u8]) -> Result<()> {
    sqlx::query("DELETE FROM sessions WHERE token_hash = $1").bind(token_hash).execute(&mut *conn).await?;
    Ok(())
}

/// Log a user out everywhere (password set/changed, "log out everywhere", admin upgrade).
pub async fn delete_user_sessions(conn: &mut PgConnection, user_id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM sessions WHERE user_id = $1").bind(user_id).execute(&mut *conn).await?;
    sqlx::query("DELETE FROM login_challenges WHERE user_id = $1").bind(user_id).execute(&mut *conn).await?;
    Ok(())
}

/// Sessions older than `idle_secs` since their last request, or past expiry, plus stale
/// challenges, devices, setup tokens and rate-limit buckets.
pub async fn purge_expired(conn: &mut PgConnection, idle_secs: i64) -> Result<()> {
    sqlx::query("DELETE FROM sessions WHERE expires_at <= now() OR last_seen_at <= now() - make_interval(secs => $1::float8)")
        .bind(idle_secs as f64)
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM setup_tokens WHERE expires_at <= now() - interval '7 days'").execute(&mut *conn).await?;
    sqlx::query("DELETE FROM login_challenges WHERE expires_at <= now()").execute(&mut *conn).await?;
    sqlx::query("DELETE FROM known_devices WHERE created_at <= now() - interval '400 days'").execute(&mut *conn).await?;
    crate::limits::purge(conn).await?;
    Ok(())
}

// --- setup tokens ---

/// Issue a setup token; the user's other unused tokens are revoked. Re-inserting an existing
/// token is a no-op (it keeps its expiry and used state), so the startup bootstrap is idempotent
/// and can't revive a redeemed token.
pub async fn insert_setup_token(conn: &mut PgConnection, token_hash: &[u8], user_id: Uuid, expires_at: DateTime<Utc>) -> Result<()> {
    sqlx::query("UPDATE setup_tokens SET used_at = now() WHERE user_id = $1 AND used_at IS NULL AND token_hash <> $2")
        .bind(user_id)
        .bind(token_hash)
        .execute(&mut *conn)
        .await?;
    sqlx::query("INSERT INTO setup_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3) ON CONFLICT (token_hash) DO NOTHING")
        .bind(token_hash)
        .bind(user_id)
        .bind(expires_at)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Atomically redeem a setup token: marks it used and returns its user, or None if the token
/// is unknown, used or expired.
pub async fn redeem_setup_token(conn: &mut PgConnection, token_hash: &[u8]) -> Result<Option<Uuid>> {
    let r = sqlx::query(
        "UPDATE setup_tokens SET used_at = now() WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now() RETURNING user_id",
    )
    .bind(token_hash)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(r.map(|r| r.try_get("user_id")).transpose()?)
}

/// True if this setup token exists and is still redeemable (does not consume it).
pub async fn setup_token_valid(conn: &mut PgConnection, token_hash: &[u8]) -> Result<Option<String>> {
    let r = sqlx::query(
        "SELECT u.email FROM setup_tokens t JOIN users u ON u.id = t.user_id \
         WHERE t.token_hash = $1 AND t.used_at IS NULL AND t.expires_at > now()",
    )
    .bind(token_hash)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(r.map(|r| r.try_get("email")).transpose()?)
}

// --- wallet membership ---

/// Add a member with `role` ("admin" | "proposer" | "viewer"). An existing member keeps their
/// role (use [`set_role`] to change it); returns false in that case.
pub async fn add_member(conn: &mut PgConnection, wallet_id: Uuid, user_id: Uuid, role: &str) -> Result<bool> {
    let n = sqlx::query("INSERT INTO wallet_members (wallet_id, user_id, role) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING")
        .bind(wallet_id)
        .bind(user_id)
        .bind(role)
        .execute(&mut *conn)
        .await?
        .rows_affected();
    Ok(n == 1)
}

pub async fn set_role(conn: &mut PgConnection, wallet_id: Uuid, user_id: Uuid, role: &str) -> Result<()> {
    let n = sqlx::query("UPDATE wallet_members SET role = $3 WHERE wallet_id = $1 AND user_id = $2")
        .bind(wallet_id)
        .bind(user_id)
        .bind(role)
        .execute(&mut *conn)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(StoreError::NotFound);
    }
    Ok(())
}

/// The caller's role in a wallet, or None for non-members.
pub async fn member_role(conn: &mut PgConnection, wallet_id: Uuid, user_id: Uuid) -> Result<Option<String>> {
    let r = sqlx::query("SELECT role FROM wallet_members WHERE wallet_id = $1 AND user_id = $2")
        .bind(wallet_id)
        .bind(user_id)
        .fetch_optional(&mut *conn)
        .await?;
    Ok(r.map(|r| r.try_get("role")).transpose()?)
}

/// Lock the wallet's membership rows (member changes serialize on this) and count its admins.
pub async fn lock_members_count_admins(conn: &mut PgConnection, wallet_id: Uuid) -> Result<i64> {
    let rows = sqlx::query("SELECT role FROM wallet_members WHERE wallet_id = $1 FOR UPDATE").bind(wallet_id).fetch_all(&mut *conn).await?;
    Ok(rows.iter().filter(|r| r.try_get::<String, _>("role").is_ok_and(|x| x == "admin")).count() as i64)
}

pub async fn set_wallet_creator(conn: &mut PgConnection, wallet_id: Uuid, user_id: Uuid) -> Result<()> {
    sqlx::query("UPDATE wallets SET created_by = $2 WHERE id = $1").bind(wallet_id).bind(user_id).execute(&mut *conn).await?;
    Ok(())
}

/// Wallets this user has created (for the per-user cap). Locks the user row first so two
/// concurrent creates can't both pass the cap.
pub async fn lock_user_count_created(conn: &mut PgConnection, user_id: Uuid) -> Result<i64> {
    sqlx::query("SELECT 1 AS x FROM users WHERE id = $1 FOR UPDATE").bind(user_id).fetch_optional(&mut *conn).await?;
    Ok(sqlx::query("SELECT count(*) AS n FROM wallets WHERE created_by = $1").bind(user_id).fetch_one(&mut *conn).await?.try_get("n")?)
}

pub async fn remove_member(conn: &mut PgConnection, wallet_id: Uuid, user_id: Uuid) -> Result<()> {
    let n = sqlx::query("DELETE FROM wallet_members WHERE wallet_id = $1 AND user_id = $2")
        .bind(wallet_id)
        .bind(user_id)
        .execute(&mut *conn)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(StoreError::NotFound);
    }
    Ok(())
}

pub async fn is_member(conn: &mut PgConnection, wallet_id: Uuid, user_id: Uuid) -> Result<bool> {
    Ok(member_role(conn, wallet_id, user_id).await?.is_some())
}

#[derive(Debug, Clone)]
pub struct MemberRow {
    pub user_id: Uuid,
    pub email: String,
    pub self_signup: bool,
    pub role: String,
    pub added_at: DateTime<Utc>,
}

pub async fn members(conn: &mut PgConnection, wallet_id: Uuid) -> Result<Vec<MemberRow>> {
    let rows = sqlx::query(
        "SELECT u.id, u.email, u.self_signup, m.role, m.added_at FROM wallet_members m JOIN users u ON u.id = m.user_id \
         WHERE m.wallet_id = $1 ORDER BY m.added_at",
    )
    .bind(wallet_id)
    .fetch_all(&mut *conn)
    .await?;
    rows.iter()
        .map(|r| Ok(MemberRow { user_id: r.try_get("id")?, email: r.try_get("email")?, self_signup: r.try_get("self_signup")?, role: r.try_get("role")?, added_at: r.try_get("added_at")? }))
        .collect()
}

/// The wallet a proposal belongs to, for membership checks on `/proposals/{id}` routes.
pub async fn proposal_wallet(conn: &mut PgConnection, proposal_id: i64) -> Result<Option<Uuid>> {
    let r = sqlx::query("SELECT wallet_id FROM proposals WHERE id = $1").bind(proposal_id).fetch_optional(&mut *conn).await?;
    Ok(r.map(|r| r.try_get("wallet_id")).transpose()?)
}

/// Wallets this user is a member of, with the user's role in each.
pub async fn list_wallets_for_user(conn: &mut PgConnection, user_id: Uuid) -> Result<Vec<(WalletRow, String)>> {
    let ids: Vec<(Uuid, String)> = sqlx::query(
        "SELECT w.id, m.role FROM wallets w JOIN wallet_members m ON m.wallet_id = w.id WHERE m.user_id = $1 ORDER BY w.created_at",
    )
    .bind(user_id)
    .fetch_all(&mut *conn)
    .await?
    .iter()
    .map(|r| Ok((r.try_get("id")?, r.try_get("role")?)))
    .collect::<std::result::Result<_, sqlx::Error>>()?;
    let mut out = vec![];
    for (id, role) in ids {
        out.push((crate::get_wallet(conn, id).await?, role));
    }
    Ok(out)
}
