use std::{
    cell::RefCell,
    collections::HashMap,
    time::SystemTime,
};

use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    Cert,
    Fingerprint,
    KeyHandle,
    packet::UserID,
    policy::Policy,
};
use sequoia_wot as wot;
use wot::{
    CertSynopsis,
    CertificationSet,
    store::Backend,
    store::CertObject,
    store::Store,
    store::StoreError,
};

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

pub struct WoT {
}

impl WoT {
    pub fn new(_config: &Config) -> Result<Box<dyn Model>> {
        Ok(Box::new(WoT {}))
    }
}

impl Model for WoT {
    fn with_policy<'a>(&self, config: &'a Config, at: Option<SystemTime>)
                      -> Result<Box<dyn ModelViewAt<'a> + 'a>>
    {
        // Start with the roots from the trust database.
        let mut roots = config.trustdb.ultimately_trusted_keys();

        // Now we add any roots from the configuration and command line.
        roots.extend_from_slice(&config.trusted_keys);

        roots.sort_unstable();
        roots.dedup();

        Ok(Box::new(WoTViewAt {
            roots,
            network: wot::Network::new(WoTData {
                config,
                time: at.unwrap_or_else(SystemTime::now),
                redge_cache: RefCell::new(HashMap::new()),
            })?,
        }))
    }
}

struct WoTData<'a> {
    config: &'a Config,
    time: SystemTime,
    redge_cache: RefCell<HashMap<Fingerprint, Vec<CertificationSet>>>,
}

struct WoTViewAt<'a> {
    roots: Vec<Fingerprint>,
    network: wot::Network<WoTData<'a>>,
}

impl<'a> ModelViewAt<'a> for WoTViewAt<'a> {
    fn kind(&self) -> TrustModel {
        TrustModel::PGP
    }

    fn time(&self) -> SystemTime {
        self.network.reference_time()
    }
    fn policy(&self) -> &dyn Policy {
        self.network.config.policy()
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

    fn lookup(&self, query: &Query) -> Result<Vec<(Validity, &'a Cert)>> {
        let certs = self.network.config.keydb.lookup_candidates(&query)?;
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

impl wot::store::Backend for WoTData<'_> {
    /// Returns the certificates matching the handle.
    ///
    /// Returns [`StoreError::NotFound`] if the certificate is not found.
    ///
    /// The caller may assume that looking up a fingerprint returns at
    /// most one certificate.
    fn cert_object<'a>(&'a self, kh: &KeyHandle) -> Result<Vec<CertObject<'a>>>
    {
        let certs = self.config.keydb.by_primaries(std::iter::once(kh))?
            .into_iter()
            .map(|c| {
                CertObject::CertRef(&c)
            })
            .collect::<Vec<_>>();
        if certs.is_empty() {
            Err(wot::store::StoreError::NotFound(kh.clone()).into())
        } else {
            Ok(certs)
        }
    }

    /// Lists all of the certificates.
    fn list_cert_objects<'a>(&'a self)
        -> Box<dyn Iterator<Item=Fingerprint> + 'a>
    {
        Box::new(self.config.keydb.iter().map(|c| c.fingerprint()))
    }
}

impl<'wot> wot::store::Store for WoTData<'wot> {
    /// Returns the reference time.
    fn reference_time(&self) -> SystemTime {
        self.time
    }

    /// Lists all of the certificates.
    fn list<'a>(&'a self) -> Box<dyn Iterator<Item=Fingerprint> + 'a> {
        self.list_cert_objects()
    }

    /// Returns the certificates matching the handle.
    ///
    /// Returns [`StoreError::NotFound`] if the certificate is not
    /// found.  This function SHOULD NOT return an empty vector if the
    /// certificate is not found.
    ///
    /// The caller may assume that looking up a fingerprint returns at
    /// most one certificate.
    fn cert(&self, kh: &KeyHandle) -> Result<Vec<CertSynopsis>>
    {
        let certs: Vec<CertSynopsis>
            = self.config.keydb.by_primaries(std::iter::once(kh))?
            .into_iter()
            .filter_map(|c| {
                // Silently skip invalid certificates.
               let vc = c.with_policy(&self.config.policy, self.time).ok()?;
               Some(CertSynopsis::from(vc))
           })
            .collect();
        if certs.is_empty() {
            Err(wot::store::StoreError::NotFound(kh.clone()).into())
        } else {
            Ok(certs)
        }
    }

    fn certifications_of(&self, target: &Fingerprint, _min_depth: wot::Depth)
        -> Result<Vec<CertificationSet>>
    {
        if let Some(redges) = self.redge_cache.borrow().get(target) {
            return Ok(redges.clone());
        }

        let redges = self.certifications_of_uncached(target)?;

        self.redge_cache.borrow_mut()
            .insert(target.clone(), redges.clone());

        Ok(redges)
    }
}

impl<'a> WoTData<'a> {
    /// Returns a certification set for the specified certificate.
    ///
    /// A `CertificateSet` is returned for the certificate itself as
    /// well as for each User ID (self signed or not) that has a
    /// cryptographically valid certification.
    ///
    /// Returns [`StoreError::NotFound`] if the certificate is not
    /// found.  This function SHOULD NOT return an empty vector if the
    /// certificate is not found.
    fn certifications_of_uncached(&self, target: &Fingerprint)
        -> Result<Vec<CertificationSet>>
    {
        let target = KeyHandle::from(target);

        let cert = self.config.keydb.by_primary(&target)
            .ok_or_else(|| StoreError::NotFound(target.clone()))?;

        // Turn invalid certificate errors into NotFound errors.
        let vc = cert.with_policy(self.config.policy(), self.time)
            .map_err(|_| StoreError::NotFound(target))?;

        let redges = self.redges(vc, 0.into());

        Ok(redges)
    }
}
