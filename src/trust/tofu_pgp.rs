//! Implements the Tofu+PGP model.

use std::{
    time::SystemTime,
};

use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    Cert,
    Fingerprint,
    packet::UserID,
    policy::Policy,
};

use crate::{
    Config,
    trust::{
        Model,
        ModelViewAt,
        Query,
        TrustModel,
        Validity,
        pgp,
    },
};

/// The Tofu+PGP model.
pub struct TofuPGP {
    pgp: Box<dyn Model>,
}

impl TofuPGP {
    pub fn new(config: &Config) -> Result<Box<dyn Model>> {
        Ok(Box::new(TofuPGP {
            pgp: pgp::WoT::new(config)?,
        }))
    }
}

impl Model for TofuPGP {
    fn with_policy<'a>(&'a self, config: &'a Config, time: Option<SystemTime>)
                      -> Result<Box<dyn ModelViewAt + 'a>>
    {
        Ok(Box::new(TofuPGPViewAt {
            pgp: self.pgp.with_policy(config, time)?,
        }))
    }
}

struct TofuPGPViewAt<'a> {
    pgp: Box<dyn ModelViewAt<'a> + 'a>,
}

impl<'a> ModelViewAt<'a> for TofuPGPViewAt<'a> {
    fn kind(&self) -> TrustModel {
        TrustModel::TofuPGP
    }

    fn time(&self) -> SystemTime {
        self.pgp.time()
    }

    fn policy(&self) -> &dyn Policy {
        self.pgp.policy()
    }

    fn validity(&self, userid: &UserID, fingerprint: &Fingerprint)
                -> Result<Validity> {
        self.pgp.validity(userid, fingerprint)
    }

    fn lookup(&self, query: &Query) -> Result<Vec<&'a Cert>> {
        self.pgp.lookup(query)
    }
}
