//! Fee sanity checks (DESIGN.md §6.2).

use bitcoin::{Amount, FeeRate, Transaction, Weight};
use serde::{Deserialize, Serialize};

use crate::policy::WalletPolicy;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeePolicy {
    /// Hard cap on the absolute fee. Default 0.01 BTC.
    pub max_fee: Amount,
    /// Hard cap on the fee rate as a multiple of the current "fast" estimate. Default 10.
    pub max_rate_multiple_of_fast: u64,
    /// Warn when fee > this many basis points of the amount sent to recipients. Default 500 (5%).
    pub warn_fee_bps_of_sent: u64,
}

impl Default for FeePolicy {
    fn default() -> Self {
        FeePolicy {
            max_fee: Amount::from_sat(1_000_000),
            max_rate_multiple_of_fast: 10,
            warn_fee_bps_of_sent: 500,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FeeWarning {
    /// Fee is a large share of what's being sent.
    HighShareOfSent { fee_sats: u64, sent_sats: u64, bps: u64 },
    /// No fee estimate was available, so the rate cap couldn't be checked.
    NoFastEstimate,
    /// A hard cap was exceeded but the caller typed the override.
    CapOverridden { reason: String },
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FeeError {
    #[error("fee {fee} exceeds the absolute cap {cap}")]
    AbsoluteCap { fee: Amount, cap: Amount },
    #[error("fee rate {rate_sat_vb} sat/vB exceeds {multiple}x the fast estimate ({fast_sat_vb} sat/vB)")]
    RateCap { rate_sat_vb: u64, fast_sat_vb: u64, multiple: u64 },
}

/// Upper bound on the virtual size once every input carries an M-of-N witness.
/// Assumes 73-byte signatures (the same bound BDK's coin selection uses).
pub fn estimate_weight(policy: &WalletPolicy, unsigned: &Transaction) -> Weight {
    let per_input = policy.max_satisfaction_weight();
    // An unsigned tx with no witnesses serializes without marker/flag; a signed one adds
    // 2 WU of marker+flag and 1 WU per input for the witness item count.
    let base = unsigned.weight();
    base + Weight::from_wu(2) + Weight::from_wu(unsigned.input.len() as u64) + per_input * unsigned.input.len() as u64
}

pub fn estimate_vsize(policy: &WalletPolicy, unsigned: &Transaction) -> u64 {
    estimate_weight(policy, unsigned).to_vbytes_ceil()
}

/// Fee rate in sat/kwu from a fee and an estimated weight (rounded down).
pub fn fee_rate(fee: Amount, weight: Weight) -> FeeRate {
    FeeRate::from_sat_per_kwu(fee.to_sat().saturating_mul(1000) / weight.to_wu().max(1))
}

/// `sent` is the sum of recipient (non-change) outputs.
/// `fast` is the current "fast" fee estimate if the chain source has one.
/// With `override_caps`, cap violations become warnings instead of errors.
pub fn check_fee(
    fee: Amount,
    weight: Weight,
    sent: Amount,
    policy: &FeePolicy,
    fast: Option<FeeRate>,
    override_caps: bool,
) -> Result<Vec<FeeWarning>, FeeError> {
    let mut warnings = vec![];
    let hard = |e: FeeError, warnings: &mut Vec<FeeWarning>| {
        if override_caps {
            warnings.push(FeeWarning::CapOverridden { reason: e.to_string() });
            Ok(())
        } else {
            Err(e)
        }
    };
    if fee > policy.max_fee {
        hard(FeeError::AbsoluteCap { fee, cap: policy.max_fee }, &mut warnings)?;
    }
    let rate = fee_rate(fee, weight);
    match fast {
        Some(fast) => {
            let cap = fast.to_sat_per_kwu().saturating_mul(policy.max_rate_multiple_of_fast);
            if rate.to_sat_per_kwu() > cap {
                hard(
                    FeeError::RateCap {
                        rate_sat_vb: rate.to_sat_per_vb_ceil(),
                        fast_sat_vb: fast.to_sat_per_vb_ceil(),
                        multiple: policy.max_rate_multiple_of_fast,
                    },
                    &mut warnings,
                )?;
            }
        }
        None => warnings.push(FeeWarning::NoFastEstimate),
    }
    // fee * 10_000 > sent * bps  <=>  fee/sent > bps/10_000
    let lhs = (fee.to_sat() as u128) * 10_000;
    let rhs = (sent.to_sat() as u128) * (policy.warn_fee_bps_of_sent as u128);
    if lhs > rhs {
        let bps = if sent.to_sat() == 0 { u64::MAX } else { (lhs / sent.to_sat() as u128).min(u64::MAX as u128) as u64 };
        warnings.push(FeeWarning::HighShareOfSent { fee_sats: fee.to_sat(), sent_sats: sent.to_sat(), bps });
    }
    Ok(warnings)
}
