use std::{
    collections::BTreeSet,
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
use sequoia_wot as wot;
use wot::store::{Backend, Store};

use sequoia_cert_store as cert_store;
use cert_store::LazyCert;

use crate::{
    Config,
    common::OwnerTrustLevel,
    keydb::KeyDB,
    trust::{
        Query,
        TrustModel,
        Validity,
        ValidityLevel,
    },
};

pub use crate::common::Model;
pub use crate::common::ModelViewAt;

trace_module!(TRACE);

/// A flexible Web-of-Trust implementation.
///
/// We support both Sequoia-style and the GnuPG-style Web-of-Trust
/// computations.
#[derive(Debug, Clone)]
pub struct WoT {
    gnupg_roots: bool,
    sequoia_roots: bool,
    marginals_needed: u8,
    completes_needed: u8,
}

impl WoT {
    /// Configures the Web-of-Trust implementation.
    ///
    /// By default, only ultimately-trusted trust roots are used.
    pub fn new() -> Self {
        WoT {
            gnupg_roots: false,
            sequoia_roots: false,
            marginals_needed: 0,
            completes_needed: 0,
        }
    }

    /// Enables Sequoia's trust roots.
    ///
    /// Currently, this is the `trust-root` in the cert-d.
    pub fn with_sequoia_roots(mut self) -> Self {
        self.sequoia_roots = true;
        self
    }

    /// Enables GnuPG's non-ultimately trusted roots.
    ///
    /// For GnuPG to consider a non-ultimately trusted root as valid,
    /// there must be a path from an ultimately trusted root to the
    /// non-ultimately trusted root.  If this is the case, add those
    /// roots.
    pub fn with_gnupg_roots(mut self,
                            marginals_needed: u8,
                            completes_needed: u8)
                            -> Self {
        self.gnupg_roots = true;
        self.marginals_needed = marginals_needed;
        self.completes_needed = completes_needed;
        self
    }

    /// Returns the trust model.
    pub fn build(self) -> Result<Box<dyn Model>> {
        Ok(Box::new(self))
    }
}

impl Model for WoT {
    fn with_policy_and_precompute<'a, 'store>(
        &self, config: &'a Config<'store>,
        at: Option<SystemTime>,
        precompute: bool)
        -> Result<Box<dyn ModelViewAt<'a, 'store> + 'a>>
    where 'store: 'a
    {
        tracer!(TRACE, "WoT::with_policy_and_precompute");
        use wot::Root;

        let at = at.unwrap_or_else(SystemTime::now);

        // Start with the roots from the trust database.
        let mut trust_roots = Vec::<Root>::new();

        // Now we add any roots from the configuration and command line.
        config.trusted_keys.iter()
            .for_each(|f| trust_roots.push(Root::new(f.clone(), wot::FULLY_TRUSTED)));
        let mut ultimate_roots: BTreeSet<Fingerprint> =
            config.trusted_keys.iter().cloned().collect();

        if self.sequoia_roots {
            // And the local trust root, if any.
            if let Ok(overlay) = config.keydb.get_certd_overlay() {
                if let Ok(trust_root) = overlay.trust_root() {
                    trust_roots.push(Root::new(trust_root.fingerprint(), wot::FULLY_TRUSTED));
                }
            }
        }

        let store = wot::store::CertStore::from_store(
            &config.keydb, &config.policy, at);
        if precompute {
            store.precompute();
        }
        let roots = wot::Roots::new(trust_roots.clone());
        let mut n = wot::Network::new(store, roots)?;

        if self.gnupg_roots {
            let mut possible_roots: Vec<Root> = Vec::new();

            for (f, ownertrust) in config.trustdb.ownertrust().iter()
                .map(|(f, ot)| (f, ot.level()))
            {
                /// Returns `ceil(x / y)`.
                fn checked_div_ceil(x: usize, y: usize) -> Option<usize> {
                    if y == 0 {
                        None
                    } else if x == 0 {
                        Some(0)
                    } else {
                        Some(1 + (x - 1) / y)
                    }
                }

                match ownertrust {
                    OwnerTrustLevel::Ultimate => {
                        ultimate_roots.insert(f.clone());
                        trust_roots.push(
                            Root::new(f.clone(), wot::FULLY_TRUSTED));
                    },
                    OwnerTrustLevel::Fully =>
                        possible_roots.push(Root::new(
                            f.clone(),
                            checked_div_ceil(wot::FULLY_TRUSTED,
                                             self.completes_needed as _)
                                .unwrap_or(wot::FULLY_TRUSTED))),
                    OwnerTrustLevel::Marginal =>
                        possible_roots.push(Root::new(
                            f.clone(),
                            checked_div_ceil(wot::FULLY_TRUSTED,
                                             self.marginals_needed as _)
                                .unwrap_or(wot::FULLY_TRUSTED / 3))),
                    _ => (),
                }
            }

            t!("trust_roots: {:?}", trust_roots);
            t!("ultimate_roots: {:?}", ultimate_roots);
            t!("possible_roots: {:?}", possible_roots);

            let mut found_one = true;
            while found_one && ! possible_roots.is_empty() {
                // For GnuPG to consider a non-ultimately trusted root as
                // valid, there must be a path from an ultimately trusted root
                // to the non-ultimately trusted root.  If this is the case,
                // add those roots.

                t!("Checking if any of {} are reachable from the current {} roots",
                   possible_roots.iter()
                   .fold(String::new(), |mut s, r| {
                       if ! s.is_empty() {
                           s.push_str(", ");
                       }
                       s.push_str(&r.fingerprint().to_hex());
                       s
                   }),
                   trust_roots.len());

                found_one = false;
                let pr = possible_roots;
                possible_roots = Vec::new();

                'root: for other_root in pr.into_iter() {
                    let cert = match n.lookup_synopsis_by_fpr(other_root.fingerprint()) {
                        Err(_err) => {
                            t!("Ignoring root {}: not in network.",
                               other_root.fingerprint());
                            continue;
                        }
                        Ok(cert) => cert,
                    };

                    for u in cert.userids() {
                        if u.revocation_status().in_effect(at) {
                            t!("Ignoring root {}'s User ID {:?}: revoked.",
                               other_root.fingerprint(),
                               String::from_utf8_lossy(u.value()));
                            continue;
                        }

                        let authenticated_amount
                            = n.authenticate(
                                u.userid(), other_root.fingerprint(),
                                wot::FULLY_TRUSTED)
                            .amount();

                        if authenticated_amount >= wot::FULLY_TRUSTED {
                            // Authenticated!  We'll keep it.
                            t!("Non-ultimately trusted root <{}, {}> reachable, \
                                keeping at {}",
                               other_root.fingerprint(),
                               String::from_utf8_lossy(u.userid().value()),
                               other_root.amount());
                            found_one = true;

                            trust_roots.push(other_root);
                            let store = wot::store::CertStore::from_store(
                                &config.keydb, &config.policy, at);
                            let roots = wot::Roots::new(trust_roots.clone());
                            n = wot::Network::new(store, roots)?;

                            continue 'root;
                        } else {
                            t!("Non-ultimately trusted binding <{}, {}> \
                                NOT fully trusted (amount: {})",
                               other_root.fingerprint(),
                               String::from_utf8_lossy(u.userid().value()),
                               authenticated_amount);
                        }
                    }

                    t!("Non-ultimately trusted root {} NOT fully trusted. Ignoring.",
                       other_root.fingerprint());
                    possible_roots.push(other_root);
                }
            }
        }

        t!("computed trust_roots: {:?}", trust_roots);

        Ok(Box::new(WoTViewAt {
            wot: self.clone(),
            config,
            ultimate_roots,
            network: n,
        }))
    }
}

struct WoTViewAt<'a, 'store> {
    /// WoT configuration for reference.
    wot: WoT,

    config: &'a Config<'store>,

    /// The set of keys for which we report `ValidityLevel::Ultimate`.
    ultimate_roots: BTreeSet<Fingerprint>,

    network: wot::Network<wot::store::CertStore<'store, 'a, &'a KeyDB<'store>>>,
}

impl<'a, 'store> ModelViewAt<'a, 'store> for WoTViewAt<'a, 'store> {
    fn kind(&self) -> TrustModel {
        match (self.wot.sequoia_roots, self.wot.gnupg_roots) {
            (false, false) => TrustModel::PGP,
            (false, true) => TrustModel::GnuPG,
            (true, false) => TrustModel::Sequoia,
            (true, true) => if crate::gnupg_interface::STRICT_OUTPUT {
                TrustModel::PGP
            } else {
                TrustModel::SequoiaGnuPG
            }
        }
    }

    fn time(&self) -> SystemTime {
        self.network.reference_time()
    }
    fn policy(&self) -> &dyn Policy {
        self.network.policy()
    }

    fn validity(&self, userid: &UserID, fingerprint: &Fingerprint)
                -> Result<Validity> {
        tracer!(TRACE, "WoT::validity");

        if self.ultimate_roots.contains(fingerprint) {
            t!("{} is an ultimate root", fingerprint);
            return Ok(ValidityLevel::Ultimate.into());
        }

        let paths = self.network.authenticate(
            userid, fingerprint.clone(), wot::FULLY_TRUSTED);

        let amount = paths.amount();
        t!("authenticate({:?}, {}) => {}", userid, fingerprint, amount);
        t!("paths: {:?}", paths);

        if amount >= wot::FULLY_TRUSTED {
            Ok(ValidityLevel::Fully.into())
        } else if amount >= 60 { // XXX magic number
            Ok(ValidityLevel::Marginal.into())
        } else {
            Ok(ValidityLevel::Unknown.into())
        }
    }

    fn lookup(&self, query: &Query) -> Result<Vec<(Validity, Arc<LazyCert<'store>>)>> {
        tracer!(TRACE, "WoT::lookup");
        t!("query {:?}", query);

        let certs = self.network.backend().store().lookup_candidates(self.config, &query)?;
        Ok(certs.into_iter()
           .map(|c| {
               let validity = match query {
                   Query::Key(_) | Query::ExactKey(_) => {
                       // GnuPG computes the maximum validity of all user
                       // ids.
                       let fp = c.fingerprint();
                       c.userids()
                           .map(|uid| self.validity(&uid, &fp)
                                .unwrap_or(ValidityLevel::Unknown.into()))
                           .max()
                           .unwrap_or(ValidityLevel::Unknown.into())
                   },
                   Query::Email(_) | Query::UserIDFragment(_)
                       | Query::ExactUserID(_) =>
                   {
                       // GnuPG only matches on one userid, but a
                       // query could match more than one.  Computes
                       // the maximum validity of all matching user
                       // ids.
                       let fp = c.fingerprint();
                       c.userids()
                           .filter(|uid| query.matches_userid(uid))
                           .map(|uid| self.validity(&uid, &fp)
                                .unwrap_or(ValidityLevel::Unknown.into()))
                           .max()
                           .unwrap_or(ValidityLevel::Unknown.into())
                   },
               };
               (validity, c)
           })
           .collect())
    }
}
