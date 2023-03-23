use std::{
    borrow::Cow,
    collections::BTreeMap,
    io::{self, Write},
};

use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::amalgamation::{ValidateAmalgamation, ValidAmalgamation},
    crypto::mpi::PublicKey,
    types::*,
};
use sequoia_ipc as ipc;
use ipc::Keygrip;

use sequoia_cert_store as cert_store;
use cert_store::LazyCert;
use cert_store::Store;
use cert_store::store::StoreError;

use crate::{
    common::{Common, Query},
    compliance::KeyCompliance,
    colons::*,
    trust::{*, cert::*},
};

/// Dispatches the --list-keys command (and similar ones).
pub fn cmd_list_keys(config: &crate::Config, args: &[String], list_secret: bool)
                     -> Result<()>
{
    let mut sink = io::stdout(); // XXX

    // First, emit a header on --list-keys --with-colons.
    if config.with_colons && ! list_secret {
        let v = config.trustdb.version(config);
        Record::TrustDBInformation {
            old: false,
            changed_model: false,
            model: v.model,
            creation_time: v.creation_time,
            expiration_time: v.expiration_time,
            marginals_needed: v.marginals_needed,
            completes_needed: v.completes_needed,
            max_cert_depth: v.max_cert_depth,
        }.emit(config, &mut sink)?;
    }

    let certs = if args.is_empty() {
        config.keydb().certs()
    } else {
        let mut certs = BTreeMap::new();
        for query in args.iter().map(|a| Query::from(&a[..])) {
            let r = match query {
                Query::Key(h) | Query::ExactKey(h) =>
                    config.keydb().lookup_by_key(&h),
                Query::Email(e) =>
                    config.keydb().lookup_by_email(&e),
                Query::UserIDFragment(f) =>
                    config.keydb().grep_userid(&f),
            };

            let r = match r {
                Ok(certs) => certs,
                Err(err) => {
                    match err.downcast_ref::<StoreError>() {
                        Some(&StoreError::NotFound(_)) => vec![],
                        Some(&StoreError::NoMatches(_)) => vec![],
                        _ => return Err(err),
                    }
                }
            };
            r.into_iter().for_each(|c| {
                certs.insert(c.fingerprint(), c);
            });
        }

        if certs.is_empty() {
            return Err(anyhow::anyhow!(
                "error reading key: No public key"));
        }

        Box::new(certs.into_values())
    };

    list_keys(config, certs, list_secret,
              args.is_empty(), // Only print header if no query is given.
              sink)
}

pub fn list_keys<'a, 'store: 'a, S>(config: &'a crate::Config,
                                    certs: impl Iterator<Item = Cow<'a, LazyCert<'store>>> + 'a,
                                    list_secret: bool,
                                    emit_header: bool,
                                    mut sink: S)
    -> Result<()>
where
    S: Write,
{
    let vtm = config.trust_model_impl.with_policy(config, Some(config.now()))?;
    let p = vtm.policy();

    let rt = tokio::runtime::Runtime::new()?;
    let mut agent =
        if list_secret || (config.with_secret && config.with_colons) {
            rt.block_on(config.connect_agent()).ok()
        } else {
            None
        };

    // We emit the location header for humans only if we actually list
    // at least one key.
    let mut emitted_header = false;

    for cert in certs {
        let has_secret = agent.as_mut()
            .map(|a| rt.block_on(crate::agent::has_keys(a, &cert))).transpose()?
            .unwrap_or_default();

        if list_secret && has_secret.is_empty() {
            // No secret (sub)key, don't list this key in --list-secret-keys.
            continue;
        }

        let cert = if let Ok(cert) = cert.to_cert() {
            cert
        } else {
            continue;
        };

        // For humans, we print the location of the store if we list
        // at least one key.
        if emit_header && ! emitted_header && ! config.with_colons {
            emitted_header = true;

            let path =
                config.keydb().get_certd_overlay()?.path().display().to_string();
            writeln!(&mut sink, "{}", path)?;
            sink.write_all(crate::utils::undeline_for(&path))?;
            writeln!(&mut sink)?;
        }

        let acert = AuthenticatedCert::new(vtm.as_ref(), &cert)?;
        let vcert = cert.with_policy(p, config.now()).ok();
        let cert_fp = cert.fingerprint();
        let have_secret = has_secret.contains(&cert_fp);
        let ownertrust = config.trustdb.get_ownertrust(&cert_fp)
            .unwrap_or_else(|| OwnerTrustLevel::Undefined.into());

        Record::Key {
            have_secret: have_secret && list_secret,
            validity: acert.cert_validity(),
            key_length: cert.primary_key().mpis().bits().unwrap_or_default(),
            pk_algo: cert.primary_key().pk_algo(),
            keyid: cert.keyid(),
            creation_date: cert.primary_key().creation_time(),
            expiration_date:  vcert.as_ref()
                .and_then(|v| v.keys().next().expect("primary key")
                          .key_expiration_time()),
            revocation_date: vcert.as_ref()
                .and_then(|v| if let RevocationStatus::Revoked(sigs)
                          = v.primary_key().revocation_status()
                          {
                              sigs[0].signature_creation_time()
                          } else {
                              None
                          }),
            ownertrust,
            primary_key_flags: vcert.as_ref()
                .and_then(|v| v.keys().next().expect("primary key").key_flags())
                .unwrap_or_else(|| KeyFlags::empty()),
            sum_key_flags: {
                let mut kf = KeyFlags::empty();
                if acert.cert_validity() == Validity::Expired {
                    // Expired certs don't list their subkeys' flags.
                } else if acert.cert_validity() == Validity::Revoked {
                    // Revoked certs don't list their subkeys' flags.
                } else if let Some(vcert) = vcert.as_ref() {
                    if vcert.keys().alive().for_signing().next().is_some() {
                        kf = kf.set_signing();
                    }
                    if vcert.keys().alive().for_certification().next().is_some() {
                        kf = kf.set_certification();
                    }
                    if vcert.keys().alive().for_authentication().next().is_some() {
                        kf = kf.set_authentication();
                    }
                    if vcert.keys().alive().for_transport_encryption().next().is_some() {
                        kf = kf.set_transport_encryption();
                    }
                    if vcert.keys().alive().for_storage_encryption().next().is_some() {
                        kf = kf.set_storage_encryption();
                    }
                }
                kf
            },
            token_sn: have_secret.then(|| TokenSN::SecretAvaliable),
            curve: get_curve(cert.primary_key().mpis()),
            compliance: cert.primary_key().compliance(config),
        }.emit(config, &mut sink)?;

        Record::Fingerprint(cert_fp)
            .emit(config, &mut sink)?;
        if config.with_keygrip
            || (config.with_colons && (list_secret || have_secret))
        {
            if let Ok(grip) = Keygrip::of(cert.primary_key().mpis()) {
                Record::Keygrip(grip).emit(config, &mut sink)?;
            }
        }

        // Sort the userids so that the primary user id is first.
        let mut userids: Vec<_> = acert.userids().collect();
        let primary_userid = vcert
            .and_then(|vcert| {
                vcert.primary_userid().ok().map(|u| u.userid())
            });
        userids.sort_by_key(|(_validity, userid)| {
            Some(userid.userid()) != primary_userid
        });
        for (validity, uid) in userids.into_iter() {
            let vuid = uid.clone().with_policy(p, config.now()).ok();

            Record::UserID {
                validity,
                creation_date: vuid.as_ref()
                    .and_then(|v| v.binding_signature().signature_creation_time())
                    .unwrap_or_else(|| {
                        uid.self_signatures().next()
                            .and_then(|s| s.signature_creation_time())
                            .unwrap_or(std::time::UNIX_EPOCH)
                    }),
                expiration_date:  vuid.as_ref()
                    .and_then(|v| v.binding_signature().signature_expiration_time()),
                userid: uid.userid().clone(),
            }.emit(config, &mut sink)?;
        }

        for (validity, subkey) in acert.subkeys() {
            // Don't display expired or revoked subkeys.
            if ! config.with_colons
                && (validity == Validity::Expired
                    || validity == Validity::Revoked) {
                continue;
            }

            let vsubkey = subkey.clone().with_policy(p, config.now()).ok();
            let subkey_fp = subkey.fingerprint();
            let have_secret = has_secret.contains(&subkey_fp);

            Record::Subkey {
                have_secret: have_secret && list_secret,
                validity: validity,
                key_length: subkey.mpis().bits().unwrap_or_default(),
                pk_algo: subkey.pk_algo(),
                keyid: subkey.keyid(),
                creation_date: subkey.creation_time(),
                expiration_date:  vsubkey.as_ref()
                    .and_then(|v| v.key_expiration_time()),
                revocation_date: vsubkey.as_ref()
                    .and_then(|v| if let RevocationStatus::Revoked(sigs)
                              = v.revocation_status()
                              {
                                  sigs[0].signature_creation_time()
                              } else {
                                  None
                              }),
                key_flags: vsubkey.as_ref()
                    .and_then(|v| v.key_flags())
                    .unwrap_or_else(|| KeyFlags::empty()),
                token_sn: have_secret.then(|| TokenSN::SecretAvaliable),
                curve: get_curve(subkey.mpis()),
                compliance: subkey.compliance(config),
            }.emit(config, &mut sink)?;

            if config.with_colons || config.with_subkey_fingerprint {
                Record::Fingerprint(subkey_fp)
                    .emit(config, &mut sink)?;
            }
            if config.with_keygrip
                || (config.with_colons && (list_secret || have_secret))
            {
                if let Ok(grip) = Keygrip::of(subkey.mpis()) {
                    Record::Keygrip(grip).emit(config, &mut sink)?;
                }
            }
        }

        // Print a separating newline for humans.
        if ! config.with_colons {
            writeln!(sink)?;
        }
    }

    Ok(())
}

/// Returns the elliptic curve of the given key, if any.
pub fn get_curve(mpis: &PublicKey) -> Option<Curve> {
    match mpis {
        PublicKey::EdDSA { curve, .. }
        | PublicKey::ECDSA { curve, .. }
        | PublicKey::ECDH { curve, .. } => Some(curve.clone()),
        _ => None,
    }
}
