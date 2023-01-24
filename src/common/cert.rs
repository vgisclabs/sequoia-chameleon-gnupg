use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::{
        Cert,
        amalgamation::{
            UserIDAmalgamation,
            ValidAmalgamation,
            ValidateAmalgamation,
            key::{
                PrimaryKeyAmalgamation,
                SubordinateKeyAmalgamation,
            },
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

    /// (Sub)key validities, in the same order as returned by
    /// `cert.keys()`.
    key_validities: Vec<Validity>,
}

impl<'a> AuthenticatedCert<'a> {
    /// Authenticates a cert using the given trust model.
    pub fn new(vtm: &dyn ModelViewAt, cert: &'a Cert) -> Result<Self> {
        let cert_fp = cert.fingerprint();

        // A cert's validity is either revoked, expired, or the max
        // over the validity of the user ids.  Further, if the cert is
        // revoked or expired, so are the UserIDs.  Hence, we
        // partially compute cert_validity here.
        let cert_validity = {
            if let Ok(vcert) = cert.with_policy(vtm.policy(), vtm.time()) {
                if let RevocationStatus::Revoked(_) = vcert.revocation_status()
                {
                    Some(Validity::Revoked)
                } else if vcert.alive().is_err() {
                    Some(Validity::Expired)
                } else {
                    None
                }
            } else {
                Some(Validity::Expired) // All binding signatures expired.
            }
        };

        let uid_validities: Vec<_> = cert.userids()
            .map(|uid| {
                // If the cert is revoked or expired, so are the UserIDs.
                if let Some(v) = cert_validity {
                    v
                } else if let Ok(vuid) = uid.with_policy(vtm.policy(), vtm.time()) {
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

        // A cert's validity is either revoked, expired, or the max
        // over the validity of the user ids.
        let cert_validity = cert_validity.unwrap_or_else(
            || uid_validities.iter().max().cloned().unwrap_or(Validity::Unknown));

        let key_validities: Vec<_> = cert.keys()
            .map(|skb| {
                if let Ok(vskb) = skb.with_policy(vtm.policy(), vtm.time()) {
                    if let RevocationStatus::Revoked(_) = vskb.revocation_status() {
                        Validity::Revoked
                    } else if vskb.alive().is_err() {
                        Validity::Expired
                    } else {
                        cert_validity
                    }
                } else {
                    Validity::Expired
                }
            })
            .collect();

        Ok(AuthenticatedCert {
            cert,
            cert_validity,
            uid_validities,
            key_validities,
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

    /// Returns the primary key and its validity.
    pub fn primary_key(&self)
                       -> (Validity, PrimaryKeyAmalgamation<'a, PublicParts>)
    {
        (self.key_validities[0].clone(), self.cert.primary_key())
    }

    /// Returns the subkeys with their validities.
    pub fn subkeys(&self)
                   -> impl Iterator<Item = (Validity,
                                            SubordinateKeyAmalgamation<'a, PublicParts>)> + 'a
    {
        self.key_validities.clone().into_iter().skip(1)
            .zip(self.cert.keys().subkeys())
    }
}
