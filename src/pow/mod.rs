//! Proof of Work algorithm
//!
//! The PoW is required to prevent grinding on nonces
//! when looking for a proof. Without it a malicious actor
//! with a powerful enough computer could try many nonces
//! at the same time. In effect a proof could be found
//! without actually holding the whole POST data.

pub mod randomx;
use mockall::*;
use primitive_types::U256;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("proof of work not found")]
    PoWNotFound,
    #[error("proof of work is invalid")]
    InvalidPoW,
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync>),
}

#[allow(clippy::needless_lifetimes)] // lifetime is needed for automock
#[automock]
pub trait Prover {
    fn prove<'a>(
        &self,
        nonce_group: u8,
        challenge: &[u8; 8],
        difficulty: &[u8; 32],
        miner_id: Option<&'a [u8; 32]>,
    ) -> Result<u64, Error>;
}

#[allow(clippy::needless_lifetimes)] // lifetime is needed for automock
#[automock]
pub trait PowVerifier {
    fn verify<'a>(
        &self,
        pow: u64,
        nonce_group: u8,
        challenge: &[u8; 8],
        difficulty: &[u8; 32],
        miner_id: Option<&'a [u8; 32]>,
    ) -> Result<(), Error>;
}

pub fn scale_difficulty(difficulty: &[u8; 32], num_units: u32) -> eyre::Result<[u8; 32]> {
    let mut pow_difficulty = [0u8; 32];

    let difficulty_scaled = U256::from_big_endian(difficulty)
        .checked_div(num_units.into())
        .ok_or_else(|| eyre::eyre!("division by zero"))?;

    difficulty_scaled.to_big_endian(&mut pow_difficulty);
    Ok(pow_difficulty)
}
