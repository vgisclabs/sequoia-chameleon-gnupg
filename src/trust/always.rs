//! Implements the "always trust" model.

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
    common::Common,
    trust::{
        Model,
        ModelViewAt,
        Query,
        TrustModel,
        Validity,
    },
};

/// The "always trust" model.
#[derive(Default)]
pub struct Always(());

impl Model for Always {
    fn with_policy<'a>(&self, config: &'a Config, time: Option<SystemTime>)
                      -> Result<Box<dyn ModelViewAt<'a> + 'a>>
    {
        Ok(Box::new(AlwaysViewAt {
            config,
            time: time.unwrap_or_else(move || config.now()),
        }))
    }
}

struct AlwaysViewAt<'a> {
    config: &'a Config,
    time: SystemTime,
}

impl<'a> ModelViewAt<'a> for AlwaysViewAt<'a> {
    fn kind(&self) -> TrustModel {
        TrustModel::Always
    }

    fn time(&self) -> SystemTime {
        self.time
    }

    fn policy(&self) -> &dyn Policy {
        self.config.policy()
    }

    fn validity(&self, _: &UserID, _: &Fingerprint)
                -> Result<Validity> {
        // Always unknown validity, see tdb_get_ownertrust.
        Ok(Validity::Unknown)
    }

    fn lookup(&self, query: &Query) -> Result<Vec<(Validity, &'a Cert)>> {
        Ok(self.config.keydb.lookup_candidates(query)?
           .into_iter()
           .map(|c| (Validity::Unknown, c))
           .collect())
    }
}
