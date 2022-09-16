//! Trust models and associated machinery.

pub mod db;
pub mod model;

/// The default value for the --marginals-needed option.
pub const DEFAULT_MARGINALS_NEEDED: u8 = 3;

/// The default value for the --completes-needed option.
pub const DEFAULT_COMPLETES_NEEDED: u8 = 1;

/// The default value for the --max-cert-depth option.
pub const DEFAULT_MAX_CERT_DEPTH: u8 = 5;

pub use crate::common::{
    cert,
    OwnerTrust,
    OwnerTrustLevel,
    Query,
    TrustModel,
    Validity,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TofuPolicy {
    Auto,
    Good,
    Unknown,
    Bad,
    Ask,
}

impl Default for TofuPolicy {
    fn default() -> Self {
        TofuPolicy::Auto // XXX
    }
}

impl std::str::FromStr for TofuPolicy {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "auto" => Ok(TofuPolicy::Auto),
            "good" => Ok(TofuPolicy::Good),
            "unknown" => Ok(TofuPolicy::Unknown),
            "bad" => Ok(TofuPolicy::Bad),
            "ask" => Ok(TofuPolicy::Ask),
            _ => Err(anyhow::anyhow!("Unknown TOFU policy {:?}", s)),
        }
    }
}
