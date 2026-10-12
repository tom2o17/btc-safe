//! Rate-limit token buckets and spent signup challenges, shared by every API process.

use sqlx::{PgConnection, Row};

use crate::Result;

/// Take one token from bucket `key` (refilling at `per_sec`, holding at most `burst`). Returns
/// `Ok(None)` if a token was taken, else `Ok(Some(seconds until one is available))`. A refused
/// request does not spend anything. One statement, so concurrent callers in any process
/// serialize on the row.
pub async fn take(conn: &mut PgConnection, key: &str, per_sec: f64, burst: f64) -> Result<Option<f64>> {
    let r = sqlx::query(
        "WITH b AS (SELECT LEAST($3::float8, COALESCE((SELECT tokens + GREATEST(EXTRACT(EPOCH FROM clock_timestamp() - at)::float8, 0) * $2::float8 \
                    FROM rate_limits WHERE key = $1), $3::float8)) AS avail) \
         INSERT INTO rate_limits (key, tokens, at, last_ok) \
         SELECT $1, CASE WHEN avail >= 1 THEN avail - 1 ELSE avail END, clock_timestamp(), avail >= 1 FROM b \
         ON CONFLICT (key) DO UPDATE SET \
           tokens = CASE WHEN LEAST($3::float8, rate_limits.tokens + GREATEST(EXTRACT(EPOCH FROM clock_timestamp() - rate_limits.at)::float8, 0) * $2::float8) >= 1 \
                    THEN LEAST($3::float8, rate_limits.tokens + GREATEST(EXTRACT(EPOCH FROM clock_timestamp() - rate_limits.at)::float8, 0) * $2::float8) - 1 \
                    ELSE LEAST($3::float8, rate_limits.tokens + GREATEST(EXTRACT(EPOCH FROM clock_timestamp() - rate_limits.at)::float8, 0) * $2::float8) END, \
           last_ok = LEAST($3::float8, rate_limits.tokens + GREATEST(EXTRACT(EPOCH FROM clock_timestamp() - rate_limits.at)::float8, 0) * $2::float8) >= 1, \
           at = clock_timestamp() \
         RETURNING tokens, last_ok",
    )
    .bind(key)
    .bind(per_sec)
    .bind(burst)
    .fetch_one(&mut *conn)
    .await?;
    let ok: bool = r.try_get("last_ok")?;
    let tokens: f64 = r.try_get("tokens")?;
    Ok(if ok { None } else { Some((1.0 - tokens) / per_sec) })
}

/// Drop buckets untouched for a day (any bucket that refills within a day is full by then).
pub async fn purge(conn: &mut PgConnection) -> Result<()> {
    sqlx::query("DELETE FROM rate_limits WHERE at < now() - interval '1 day'").execute(&mut *conn).await?;
    sqlx::query("DELETE FROM pow_spent WHERE at < now() - interval '1 day'").execute(&mut *conn).await?;
    Ok(())
}

/// Mark a signup challenge spent: true the first time only.
pub async fn spend_challenge(conn: &mut PgConnection, hash: &[u8]) -> Result<bool> {
    let n = sqlx::query("INSERT INTO pow_spent (challenge_hash) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(hash)
        .execute(&mut *conn)
        .await?
        .rows_affected();
    Ok(n == 1)
}
