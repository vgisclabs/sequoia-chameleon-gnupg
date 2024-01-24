//! Implements the "always trust" model.

use std::{
    time::SystemTime,
    sync::Arc,
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
    common::Common,
    trust::{
        Model,
        ModelViewAt,
        Query,
        TrustModel,
        Validity,
        ValidityLevel,
    },
};

/// The "always trust" model.
#[derive(Default)]
pub struct Always(());

impl Model for Always {
    fn with_policy<'a, 'store>(&self, config: &'a Config<'store>,
                               time: Option<SystemTime>)
        -> Result<Box<dyn ModelViewAt<'a, 'store> + 'a>>
    where 'store: 'a
    {
        Ok(Box::new(AlwaysViewAt {
            config,
            time: time.unwrap_or_else(move || config.now()),
        }))
    }
}

struct AlwaysViewAt<'a, 'store> {
    config: &'a Config<'store>,
    time: SystemTime,
}

impl<'a, 'store> ModelViewAt<'a, 'store> for AlwaysViewAt<'a, 'store> {
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
        Ok(ValidityLevel::Unknown.into())
    }

    fn lookup(&self, query: &Query) -> Result<Vec<(Validity, Arc<LazyCert<'store>>)>> {
        Ok(self.config.keydb.lookup_candidates(query)?
           .into_iter()
           .map(|c| (ValidityLevel::Unknown.into(), c))
           .collect())
    }
}
