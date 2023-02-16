//! Implements the Tofu+PGP model.

use std::{
    borrow::Cow,
    time::SystemTime,
};

use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    Fingerprint,
    packet::UserID,
    policy::Policy,
};

use sequoia_cert_store as cert_store;
use cert_store::LazyCert;

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
    fn with_policy<'a, 'store>(&self, config: &'a Config<'store>,
                               time: Option<SystemTime>)
        -> Result<Box<dyn ModelViewAt<'a, 'store> + 'a>>
    where 'store: 'a
    {
        Ok(Box::new(TofuPGPViewAt {
            pgp: self.pgp.with_policy(config, time)?,
        }))
    }
}

struct TofuPGPViewAt<'a, 'store> {
    pgp: Box<dyn ModelViewAt<'a, 'store> + 'a>,
}

impl<'a, 'store> ModelViewAt<'a, 'store> for TofuPGPViewAt<'a, 'store> {
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

    fn lookup(&self, query: &Query)
        -> Result<Vec<(Validity, Cow<'a, LazyCert<'store>>)>>
    {
        self.pgp.lookup(query)
    }
}
