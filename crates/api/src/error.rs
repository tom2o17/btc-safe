use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use btc_safe_chain::ChainError;
use btc_safe_core::fees::FeeError;
use btc_safe_core::import::ImportError;
use btc_safe_core::policy::PolicyError;
use btc_safe_core::validate::ValidationError;
use btc_safe_store::StoreError;
use btc_safe_wallet::WalletError;
use btc_safe_watcher::WatchError;
use serde_json::{json, Value};

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub details: Option<Value>,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        ApiError { status, code, message: message.into(), details: None }
    }
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", message)
    }
    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, code, message)
    }
    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", "not found")
    }
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", message)
    }
    pub fn with_details(mut self, d: Value) -> Self {
        self.details = Some(d);
        self
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if self.status.is_server_error() {
            tracing::error!(code = self.code, "{}", self.message);
        }
        let mut body = json!({ "error": self.code, "message": self.message });
        if let Some(d) = self.details {
            body["details"] = d;
        }
        (self.status, Json(body)).into_response()
    }
}

impl From<StoreError> for ApiError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::NotFound => ApiError::not_found(),
            StoreError::ReservationConflict => ApiError::conflict("reserved", e.to_string()),
            StoreError::StaleStatus { .. } => ApiError::conflict("stale_status", e.to_string()),
            e => ApiError::internal(e.to_string()),
        }
    }
}

impl From<btc_safe_store::sqlx::Error> for ApiError {
    fn from(e: btc_safe_store::sqlx::Error) -> Self {
        StoreError::from(e).into()
    }
}

impl From<ValidationError> for ApiError {
    fn from(e: ValidationError) -> Self {
        ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid_psbt", e.to_string())
    }
}

impl From<PolicyError> for ApiError {
    fn from(e: PolicyError) -> Self {
        ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid_policy", e.to_string())
    }
}

impl From<ImportError> for ApiError {
    fn from(e: ImportError) -> Self {
        ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "invalid_import", e.to_string())
    }
}

impl From<FeeError> for ApiError {
    fn from(e: FeeError) -> Self {
        ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "fee_cap", format!("{e}; resubmit with fee_override=true to proceed"))
    }
}

impl From<ChainError> for ApiError {
    fn from(e: ChainError) -> Self {
        match e {
            ChainError::BroadcastRejected(m) => ApiError::new(StatusCode::BAD_GATEWAY, "broadcast_rejected", m),
            ChainError::Backend(m) => ApiError::new(StatusCode::BAD_GATEWAY, "chain_unavailable", m),
        }
    }
}

impl From<WalletError> for ApiError {
    fn from(e: WalletError) -> Self {
        match e {
            WalletError::InsufficientFunds { needed, available, reserved } => {
                ApiError::conflict("insufficient_funds", e.to_string()).with_details(json!({
                    "needed_sats": needed.to_sat(),
                    "available_sats": available.to_sat(),
                    "reserved_sats": reserved.to_sat(),
                    "hint": if reserved.to_sat() > 0 { "coins are reserved by queued proposals; replace one instead" } else { "" },
                }))
            }
            WalletError::Reserved(_) => ApiError::conflict("reserved", e.to_string()),
            WalletError::UnknownUtxo(_) | WalletError::BadChainInput(_) | WalletError::Build(_) => {
                ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, "cannot_build", e.to_string())
            }
            WalletError::Validation(v) => v.into(),
            e => ApiError::internal(e.to_string()),
        }
    }
}

impl From<WatchError> for ApiError {
    fn from(e: WatchError) -> Self {
        match e {
            WatchError::Store(s) => s.into(),
            WatchError::Wallet(w) => w.into(),
            WatchError::Chain(c) => c.into(),
            WatchError::State(m) => ApiError::conflict("bad_transition", m),
        }
    }
}
