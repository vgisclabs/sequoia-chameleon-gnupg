use std::{
    collections::BTreeMap,
    io::{self, Write},
};

use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::amalgamation::{ValidateAmalgamation, ValidAmalgamation},
    crypto::mpi::PublicKey,
    Fingerprint,
    types::*,
};
use sequoia_ipc as ipc;
use ipc::Keygrip;

use crate::{
    common::Common,
    colons::*,
    trust::{*, cert::*},
};

/// Dispatches the --list-keys command (and similar ones).
pub fn cmd_list_keys(config: &crate::Config, args: &[String], list_secret: bool)
                     -> Result<()>
{
    let mut sink = io::stdout(); // XXX
    let vtm = config.trust_model_impl.with_policy(config, None)?;
    let p = vtm.policy();

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
        }.emit(&mut sink, config.with_colons)?;
    }

    let filter: Vec<Query> = args.iter()
        .map(|a| Query::from(&a[..]))
        .collect::<Vec<_>>();

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

    for cert in config.keydb().iter() {
        // Filter out certs that the user is not interested in.
        if ! filter.is_empty() && ! filter.iter().any(|q| q.matches(&cert)) {
            continue;
        }

        let mut has_secret: BTreeMap<Fingerprint, bool> = Default::default();
        if let Some(agent) = &mut agent {
            // Check for which keys we have a secret.
            for k in cert.keys().filter(|k| {
                rt.block_on(crate::agent::has_key(agent, &k))
                    .unwrap_or(false)
            }) {
                has_secret.insert(k.fingerprint(), true);
            }
        }

        if list_secret && has_secret.is_empty() {
            // No secret (sub)key, don't list this key in --list-secret-keys.
            continue;
        }

        // For humans, we print the location of the store if we list
        // at least one key.
        if ! emitted_header && ! config.with_colons {
            emitted_header = true;

            let path =
                config.keydb().get_certd_overlay()?.path().display().to_string();
            writeln!(&mut sink, "{}", path)?;
            sink.write_all(crate::utils::undeline_for(&path))?;
            writeln!(&mut sink)?;
        }

        let acert = AuthenticatedCert::new(vtm.as_ref(), &cert)?;
        let vcert = cert.with_policy(p, None).ok();
        let cert_fp = cert.fingerprint();
        let have_secret = has_secret.get(&cert_fp).cloned().unwrap_or(false);

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
            ownertrust: OwnerTrust::Undefined,
            primary_key_flags: vcert.as_ref()
                .and_then(|v| v.keys().next().expect("primary key").key_flags())
                .unwrap_or_else(|| KeyFlags::empty()),
            sum_key_flags: {
                let mut kf = KeyFlags::empty();
                if let Some(vcert) = vcert.as_ref() {
                    if vcert.keys().for_signing().next().is_some() {
                        kf = kf.set_signing();
                    }
                    if vcert.keys().for_certification().next().is_some() {
                        kf = kf.set_certification();
                    }
                    if vcert.keys().for_authentication().next().is_some() {
                        kf = kf.set_authentication();
                    }
                    if vcert.keys().for_transport_encryption().next().is_some() {
                        kf = kf.set_transport_encryption();
                    }
                    if vcert.keys().for_storage_encryption().next().is_some() {
                        kf = kf.set_storage_encryption();
                    }
                }
                kf
            },
            token_sn: have_secret.then(|| TokenSN::SecretAvaliable),
            curve: get_curve(cert.primary_key().mpis()),
        }.emit(&mut sink, config.with_colons)?;

        Record::Fingerprint(cert_fp)
            .emit(&mut sink, config.with_colons)?;
        if config.with_keygrip
            || (config.with_colons && (list_secret || have_secret))
        {
            if let Ok(grip) = Keygrip::of(cert.primary_key().mpis()) {
                Record::Keygrip(grip).emit(&mut sink, config.with_colons)?;
            }
        }

        for (validity, uid) in acert.userids() {
            let vuid = uid.clone().with_policy(p, None).ok();

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
            }.emit(&mut sink, config.with_colons)?;
        }

        for (validity, subkey) in acert.subkeys() {
            let vsubkey = subkey.clone().with_policy(p, None).ok();
            let subkey_fp =subkey.fingerprint();
            let have_secret =
                has_secret.get(&subkey_fp).cloned().unwrap_or(false);

            Record::Subkey {
                have_secret: have_secret && list_secret,
                validity: validity,
                key_length: subkey.mpis().bits().unwrap_or_default(),
                pk_algo: subkey.pk_algo(),
                keyid: subkey.keyid(),
                creation_date: subkey.creation_time(),
                expiration_date:  vsubkey.as_ref()
                    .and_then(|v| v.key_expiration_time()),
                key_flags: vsubkey.as_ref()
                    .and_then(|v| v.key_flags())
                    .unwrap_or_else(|| KeyFlags::empty()),
                token_sn: have_secret.then(|| TokenSN::SecretAvaliable),
                curve: get_curve(subkey.mpis()),
            }.emit(&mut sink, config.with_colons)?;

            if config.with_colons || config.with_subkey_fingerprint {
                Record::Fingerprint(subkey_fp)
                    .emit(&mut sink, config.with_colons)?;
            }
            if config.with_keygrip
                || (config.with_colons && (list_secret || have_secret))
            {
                if let Ok(grip) = Keygrip::of(subkey.mpis()) {
                    Record::Keygrip(grip).emit(&mut sink, config.with_colons)?;
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

pub fn get_curve(mpis: &PublicKey) -> Option<Curve> {
    match mpis {
        PublicKey::EdDSA { curve, .. }
        | PublicKey::ECDSA { curve, .. }
        | PublicKey::ECDH { curve, .. } => Some(curve.clone()),
        _ => None,
    }
}
