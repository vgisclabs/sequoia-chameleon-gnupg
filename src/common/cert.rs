use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::{
        Cert,
        amalgamation::{
            UserIDAmalgamation,
            ValidAmalgamation,
            ValidateAmalgamation,
            key::SubordinateKeyAmalgamation,
        },
    },
    packet::key::{
        PublicParts,
    },
    types::RevocationStatus,
};

use crate::{
    common::{
        Validity,
        ModelViewAt,
    },
};

/// A certificate authenticated using a trust model.
///
/// This is a view on an `openpgp::Cert` that is augmented using a
/// given trust model.  It is similar to how `openpgp::ValidCert` is a
/// view on an `openpgp::Cert` augmented using a policy and time.
pub struct AuthenticatedCert<'a> {
    cert: &'a Cert,

    /// Validity of primary key and subkeys.
    ///
    /// In GnuPG, this is the maximum of the user id validities.
    cert_validity: Validity,

    /// User id validities, in the same order as returned by
    /// `cert.userids()`.
    uid_validities: Vec<Validity>,

    /// Subkey validities, in the same order as returned by
    /// `cert.keys().subkeys()`.
    subkey_validities: Vec<Validity>,
}

impl<'a> AuthenticatedCert<'a> {
    /// Authenticates a cert using the given trust model.
    pub fn new(vtm: &dyn ModelViewAt, cert: &'a Cert) -> Result<Self> {
        let cert_fp = cert.fingerprint();

        let uid_validities: Vec<_> = cert.userids()
            .map(|uid| {
                if let Ok(vuid) = uid.with_policy(vtm.policy(), vtm.time()) {
                    if let RevocationStatus::Revoked(_) = vuid.revocation_status() {
                        Validity::Revoked
                    } else {
                        vtm.validity(vuid.userid(), &cert_fp)
                            .unwrap_or(Validity::Unknown)
                    }
                } else {
                    Validity::Expired
                }
            })
            .collect();

        let cert_validity =
            uid_validities.iter().max().cloned().unwrap_or(Validity::Unknown);

        let subkey_validities: Vec<_> = cert.keys().subkeys()
            .map(|skb| if let Some(RevocationStatus::Revoked(_)) = skb
                 .with_policy(vtm.policy(), vtm.time()).ok()
                 .map(|vskb| vskb.revocation_status())
                 {
                     Validity::Revoked
                 } else {
                     cert_validity
                 })
            .collect();

        Ok(AuthenticatedCert {
            cert,
            cert_validity,
            uid_validities,
            subkey_validities,
        })
    }

    /// Returns the cert's validity.
    ///
    /// In GnuPG, this is the maximum of the user id validities.
    pub fn cert_validity(&self) -> Validity {
        self.cert_validity
    }

    /// Returns the user ids with their validities.
    pub fn userids(&self)
                   -> impl Iterator<Item = (Validity,
                                            UserIDAmalgamation<'a>)> + 'a
    {
        self.uid_validities.clone().into_iter()
            .zip(self.cert.userids())
    }

    /// Returns the subkeys with their validities.
    pub fn subkeys(&self)
                   -> impl Iterator<Item = (Validity,
                                            SubordinateKeyAmalgamation<'a, PublicParts>)> + 'a
    {
        self.subkey_validities.clone().into_iter()
            .zip(self.cert.keys().subkeys())
    }
}
