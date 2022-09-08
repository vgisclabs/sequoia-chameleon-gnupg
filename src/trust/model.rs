use std::{
    rc::Rc,
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
    control::Common,
    trust::{
        TrustModel,
        Validity,
    },
};

pub use crate::control::Model;
pub use crate::control::ModelViewAt;

impl TrustModel {
    pub fn build(&self, config: &Config) -> Result<Box<dyn Model>> {
        use TrustModel::*;
        match self {
            PGP | TofuPGP | Auto => WoT::new(config),
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
        let mut roots = config.trustdb.ultimately_trusted_keys(config)
            .unwrap_or_default(); // XXX nastily ignoring non-existent db here

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

impl ModelViewAt for WoTViewAt<'_> {
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

    fn lookup(&self, _userid: &UserID)
              -> Result<Option<Rc<Cert>>> {
        unimplemented!()
    }
}
