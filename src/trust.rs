//! Trust models and associated machinery.

use std::{
    fmt,
};

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
