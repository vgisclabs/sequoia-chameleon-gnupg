//! Filters certificates.

use std::{
    borrow::Cow,
    collections::HashSet,
};

use anyhow::Result;

use sequoia_openpgp::{
    Cert,
    KeyID,
    Packet,
    cert::amalgamation::ValidAmalgamation,
    types::{KeyFlags, RevocationStatus},
};

use crate::{
    Config,
    common::Common,
};

/// Removes all but the latest revocation or signature from each
/// signer, removes unusable encryption and authentication keys.
///
/// This implements `--export-filter=clean`.
pub fn clean<'a>(config: &Config, cert: Cow<'a, Cert>) -> Result<Cow<'a, Cert>>
{
    filter(config, cert, false)
}

/// Removes all but the latest self revocation or signature, removes
/// all unusable keys.
///
/// This implements `--export-filter=minimal`.
pub fn minimal<'a>(config: &Config, cert: Cow<'a, Cert>) -> Result<Cow<'a, Cert>>
{
    filter(config, cert, true)
}

fn filter<'a>(config: &Config, cert: Cow<'a, Cert>, minimal: bool)
          -> Result<Cow<'a, Cert>>
{
    let mut acc: Vec<Packet> = Vec::new();
    let vcert = cert.with_policy(&config.policy, config.now())?;

    // Keep the primary key.
    acc.push(vcert.primary_key().key().clone().into());

    // Keep the current revocation or binding signature.
    if let Some(rev) = vcert.primary_key().self_revocations().next() {
        acc.push(rev.clone().into());
    } else {
        acc.push(vcert.primary_key().binding_signature().clone().into());

        // Maybe keep the most recent revocation or certification from
        // third parties.
        if ! minimal {
            let mut seen = HashSet::new();

            for rev in vcert.primary_key().other_revocations() {
                let issuers = rev.get_issuers().into_iter().map(KeyID::from)
                    .collect::<HashSet<_>>();
                if issuers.is_disjoint(&seen) {
                    acc.push(rev.clone().into());
                    issuers.into_iter().for_each(|i| { seen.insert(i); });
                }
            }

            for sig in vcert.primary_key().certifications() {
                let issuers = sig.get_issuers().into_iter().map(KeyID::from)
                    .collect::<HashSet<_>>();
                if issuers.is_disjoint(&seen) {
                    acc.push(sig.clone().into());
                    issuers.into_iter().for_each(|i| { seen.insert(i); });
                }
            }
        }
    }

    for skb in vcert.keys().subkeys() {
        // Drop unusable keys unless they are revoked.
        if skb.revocation_status() == RevocationStatus::NotAsFarAsWeKnow
            && skb.alive().is_err()
        {
            if minimal {
                // Keep only keys that are alive.
                continue;
            }

            // Keep keys with use flags other than encryption and
            // authentication.
            if skb.key_flags()
                .unwrap_or_else(|| KeyFlags::empty())
                .clear_transport_encryption()
                .clear_storage_encryption()
                .clear_authentication()
                .is_empty()
            {
                continue;
            }
        }

        // Keep the subkey.
        acc.push(skb.key().clone().into());

        // Keep the current revocation or binding signature.
        if let Some(rev) = skb.self_revocations().next() {
            acc.push(rev.clone().into());
        } else {
            acc.push(skb.binding_signature().clone().into());

            // Maybe keep the most recent revocation or certification from
            // third parties.
            if ! minimal {
                let mut seen = HashSet::new();

                for rev in skb.other_revocations() {
                    let issuers = rev.get_issuers().into_iter().map(KeyID::from)
                        .collect::<HashSet<_>>();
                    if issuers.is_disjoint(&seen) {
                        acc.push(rev.clone().into());
                        issuers.into_iter().for_each(|i| { seen.insert(i); });
                    }
                }

                for sig in skb.certifications() {
                    let issuers = sig.get_issuers().into_iter().map(KeyID::from)
                        .collect::<HashSet<_>>();
                    if issuers.is_disjoint(&seen) {
                        acc.push(sig.clone().into());
                        issuers.into_iter().for_each(|i| { seen.insert(i); });
                    }
                }
            }
        }
    }

    for uidb in vcert.userids() {
        // Keep the user id.
        acc.push(uidb.userid().clone().into());

        // Keep the current revocation or binding signature.
        if let Some(rev) = uidb.self_revocations().next() {
            acc.push(rev.clone().into());
        } else {
            acc.push(uidb.binding_signature().clone().into());

            // Maybe keep the most recent revocation or certification from
            // third parties.
            if ! minimal {
                let mut seen = HashSet::new();

                for rev in uidb.other_revocations() {
                    let issuers = rev.get_issuers().into_iter().map(KeyID::from)
                        .collect::<HashSet<_>>();
                    if issuers.is_disjoint(&seen) {
                        acc.push(rev.clone().into());
                        issuers.into_iter().for_each(|i| { seen.insert(i); });
                    }
                }

                for sig in uidb.certifications() {
                    let issuers = sig.get_issuers().into_iter().map(KeyID::from)
                        .collect::<HashSet<_>>();
                    if issuers.is_disjoint(&seen) {
                        acc.push(sig.clone().into());
                        issuers.into_iter().for_each(|i| { seen.insert(i); });
                    }
                }
            }
        }
    }

    // Note: we don't keep any bad components or signatures, nor do we
    // keep user attributes.

    Ok(Cow::Owned(Cert::from_packets(acc.into_iter())?))
}
