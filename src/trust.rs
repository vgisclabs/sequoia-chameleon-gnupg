//! Trust models and associated machinery.

use std::{
    fmt,
};

pub enum TrustModel {
    PGP,
    Classic,
    Always,
    Direct,
    Tofu,
    TofuPGP,
    Auto,
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
    Ultimate,
}

impl fmt::Display for Validity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Validity::*;
        match self {
            Unknown => f.write_str("q"),
            Ultimate => f.write_str("u"),
        }
    }
}

impl fmt::Display for crate::babel::Fish<Validity> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Validity::*;
        match self.0 {
            Unknown => f.write_str("unknown"),
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
