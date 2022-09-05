//! Trust models and associated machinery.

use std::{
    fmt,
};

pub mod db;

/// The default value for the --marginals-needed option.
pub const DEFAULT_MARGINALS_NEEDED: u8 = 3;

/// The default value for the --completes-needed option.
pub const DEFAULT_COMPLETES_NEEDED: u8 = 1;

/// The default value for the --max-cert-depth option.
pub const DEFAULT_MAX_CERT_DEPTH: u8 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustModel {
    PGP,
    Classic,
    Always,
    Direct,
    Tofu,
    TofuPGP,
    Auto,
    Unknown(u8),
}

impl From<u8> for TrustModel {
    fn from(v: u8) -> Self {
        // See enum trust_model in g10/options.h.
        use TrustModel::*;
        match v {
            0 => Classic,
            1 => PGP,
            3 => Always,
            4 => Direct,
            5 => Auto,
            6 => Tofu,
            7 => TofuPGP,
            n => Unknown(n),
        }
    }
}

impl Default for TrustModel {
    fn default() -> Self {
        TrustModel::PGP // XXX
    }
}

impl std::str::FromStr for TrustModel {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pgp" => Ok(TrustModel::PGP),
            "classic" => Ok(TrustModel::Classic),
            "direct" => Ok(TrustModel::Direct),
            "tofu" => Ok(TrustModel::Tofu),
            "tofu+pgp" => Ok(TrustModel::TofuPGP),
            "auto" => Ok(TrustModel::Auto),
            _ => Err(anyhow::anyhow!("Unknown trust model {:?}", s)),
        }
    }
}

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

#[derive(Copy, Clone, Debug)]
pub enum Validity {
    Unknown,
    Expired,
    Undefined,
    Never,
    Marginal,
    Fully,
    Ultimate,
}

impl fmt::Display for Validity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Validity::*;
        match self {
            Unknown => f.write_str("-"),
            Expired => f.write_str("e"),
            Undefined => f.write_str("q"),
            Never => f.write_str("n"),
            Marginal => f.write_str("m"),
            Fully => f.write_str("f"),
            Ultimate => f.write_str("u"),
        }
    }
}

impl fmt::Display for crate::babel::Fish<Validity> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Validity::*;
        match self.0 {
            Unknown => f.write_str("unknown"),
            Expired => f.write_str("expired"),
            Undefined => f.write_str("undefined"),
            Never => f.write_str("never"),
            Marginal => f.write_str("marginal"),
            Fully => f.write_str("full"),
            Ultimate => f.write_str("ultimate"),
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum OwnerTrust {
    Unknown,
}

impl fmt::Display for OwnerTrust {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use OwnerTrust::*;
        match self {
            Unknown => f.write_str("-"),
        }
    }
}
