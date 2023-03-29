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
use sequoia_wot as wot;

use sequoia_cert_store as cert_store;
use cert_store::LazyCert;

use crate::{
    Config,
    keydb::KeyDB,
    trust::{
        Query,
        TrustModel,
        Validity,
    },
};

pub use crate::common::Model;
pub use crate::common::ModelViewAt;

pub struct WoT {
}

impl WoT {
    pub fn new(_config: &Config) -> Result<Box<dyn Model>> {
        Ok(Box::new(WoT {}))
    }
}

impl Model for WoT {
    fn with_policy<'a, 'store>(&self, config: &'a Config<'store>,
                               at: Option<SystemTime>)
        -> Result<Box<dyn ModelViewAt<'a, 'store> + 'a>>
        where 'store: 'a
    {
        // Start with the roots from the trust database.
        let mut roots = config.trustdb.ultimately_trusted_keys();

        // Now we add any roots from the configuration and command line.
        roots.extend_from_slice(&config.trusted_keys);

        // And the local trust root, if any.
        if let Ok(overlay) = config.keydb.get_certd_overlay() {
            if let Ok(trust_root) = overlay.trust_root() {
                roots.push(trust_root.fingerprint());
            }
        }

        roots.sort_unstable();
        roots.dedup();

        let store = wot::store::CertStore::from_store(
            &config.keydb, &config.policy, at.unwrap_or_else(SystemTime::now));
        let n = wot::Network::new(store)?;

        Ok(Box::new(WoTViewAt {
            roots,
            network: n,
        }))
    }
}

struct WoTViewAt<'a, 'store> {
    roots: Vec<Fingerprint>,
    network: wot::Network<wot::store::CertStore<'store, 'a, &'a KeyDB<'store>>>,
}

impl<'a, 'store> ModelViewAt<'a, 'store> for WoTViewAt<'a, 'store> {
    fn kind(&self) -> TrustModel {
        TrustModel::PGP
    }

    fn time(&self) -> SystemTime {
        self.network.reference_time()
    }
    fn policy(&self) -> &dyn Policy {
        self.network.policy()
    }

    fn validity(&self, userid: &UserID, fingerprint: &Fingerprint)
                -> Result<Validity> {
        let mut q = wot::QueryBuilder::new(&self.network);
        q.roots(&*self.roots);
        let q = q.build();

        let paths =
            q.authenticate(userid, fingerprint.clone(), wot::FULLY_TRUSTED);

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

    fn lookup(&self, query: &Query) -> Result<Vec<(Validity, Cow<'a, LazyCert<'store>>)>> {
        let certs = self.network.backend().store().lookup_candidates(&query)?;
        Ok(certs.into_iter()
           .map(|c| {
               let validity = match query {
                   Query::Key(_) | Query::ExactKey(_) => {
                       // GnuPG computes the maximum validity of all user
                       // ids.
                       let fp = c.fingerprint();
                       c.userids()
                           .map(|uid| self.validity(&uid, &fp)
                                .unwrap_or(Validity::Unknown))
                           .max()
                           .unwrap_or(Validity::Unknown)
                   },
                   Query::Email(_) | Query::UserIDFragment(_) => {
                       // GnuPG only matches on one userid, but a
                       // query could match more than one.  Computes
                       // the maximum validity of all matching user
                       // ids.
                       let fp = c.fingerprint();
                       c.userids()
                           .filter(|uid| query.matches_userid(uid))
                           .map(|uid| self.validity(&uid, &fp)
                                .unwrap_or(Validity::Unknown))
                           .max()
                           .unwrap_or(Validity::Unknown)
                   },
               };
               (validity, c)
           })
           .collect())
    }
}
