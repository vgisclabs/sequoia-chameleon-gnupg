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
use sequoia_wot as wot;

use crate::{
    Config,
    common::Common,
    trust::{
        Query,
        TrustModel,
        Validity,
    },
};

pub use crate::common::Model;
pub use crate::common::ModelViewAt;

impl TrustModel {
    pub fn build(&self, config: &Config) -> Result<Box<dyn Model>> {
        use TrustModel::*;
        match self {
            PGP | TofuPGP | Auto => WoT::new(config),
            Always => self::Always::new(config),
            _ => Err(anyhow::anyhow!("Trust model {:?} not implemented", self))
        }
    }
}

struct WoT {
}

impl WoT {
    fn new(_config: &Config) -> Result<Box<dyn Model>> {
        Ok(Box::new(WoT {}))
    }
}

impl Model for WoT {
    fn with_policy<'a>(&'a self, config: &'a Config, at: Option<SystemTime>)
                      -> Result<Box<dyn ModelViewAt + 'a>>
    {
        // Start with the roots from the trust database.
        let mut roots = config.trustdb.ultimately_trusted_keys()
            .cloned()
            .collect::<Vec<_>>();

        // Now we add any roots from the configuration and command line.
        roots.extend_from_slice(&config.trusted_keys);

        roots.sort_unstable();
        roots.dedup();

        Ok(Box::new(WoTViewAt {
            config,
            roots,
            network: wot::Network::from_certs(
                config.keydb().iter().map(|c| c.as_ref().clone()),
                config.policy(), at)?,
        }))
    }
}

struct WoTViewAt<'a> {
    config: &'a Config,
    roots: Vec<Fingerprint>,
    network: wot::Network,
}

impl<'a> ModelViewAt<'a> for WoTViewAt<'a> {
    fn kind(&self) -> TrustModel {
        TrustModel::PGP
    }

    fn time(&self) -> SystemTime {
        self.network.reference_time()
    }
    fn policy(&self) -> &dyn Policy {
        self.config.policy()
    }

    fn validity(&self, userid: &UserID, fingerprint: &Fingerprint)
                -> Result<Validity> {
        let r = wot::RootedNetwork::new(&self.network, &*self.roots);

        let paths =
            r.authenticate(userid, fingerprint.clone(), wot::FULLY_TRUSTED);

        let amount = paths.amount();
        if amount >= wot::FULLY_TRUSTED {
            if self.roots.binary_search(fingerprint).is_ok() {
                Ok(Validity::Ultimate)
            } else {
                Ok(Validity::Fully)
            }
        } else if amount >= 60 { // XXX magic number
            Ok(Validity::Marginal)
        } else {
            Ok(Validity::Unknown)
        }
    }

    fn lookup(&self, query: &Query) -> Result<Vec<&'a Cert>> {
        let mut certs = self.config.keydb.candidates_by_userid(&query)?;
        certs.retain(|c| {
            let fp = c.fingerprint();
            let validity = c.userids()
                .filter(|uid| query.matches_userid(uid))
                .map(|uid| self.validity(&uid, &fp)
                     .unwrap_or(Validity::Unknown))
                .max()
                .unwrap_or(Validity::Unknown);

            validity >= Validity::Fully // XXX what is the threshold?
        });
        Ok(certs)
    }
}

/// The "always trust" model.
struct Always(());

impl Always {
    fn new(_: &Config) -> Result<Box<dyn Model>> {
        Ok(Box::new(Always(())))
    }
}

impl Model for Always {
    fn with_policy<'a>(&'a self, config: &'a Config, time: Option<SystemTime>)
                      -> Result<Box<dyn ModelViewAt + 'a>>
    {
        Ok(Box::new(AlwaysViewAt {
            config,
            time: time.unwrap_or_else(SystemTime::now),
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

    fn lookup(&self, query: &Query) -> Result<Vec<&'a Cert>> {
        self.config.keydb.candidates_by_userid(query)
    }
}
