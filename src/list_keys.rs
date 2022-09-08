use std::{
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

use crate::{
    common::Common,
    colons::*,
    trust::{*, cert::*},
    Query,
};

/// Dispatches the --list-keys command (and similar ones).
pub fn cmd_list_keys(config: &crate::Config, args: &[String])
                     -> Result<()>
{
    let mut sink = io::stdout(); // XXX
    let vtm = config.trust_model_impl.with_policy(config, None)?;
    let p = vtm.policy();

    // First, emit a header.
    if config.with_colons {
        // For our robot friends, we emit a TrustDB record.
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
    } else {
        // For humans, we print the location of the store.
        let path =
            config.keydb().get_certd_overlay()?.path().display().to_string();
        writeln!(&mut sink, "{}", path)?;
        sink.write_all(crate::utils::undeline_for(&path))?;
        writeln!(&mut sink)?;
    }

    let filter: Vec<Query> = args.iter()
        .map(|a| Query::from(&a[..]))
        .collect::<Vec<_>>();

    for cert in config.keydb().iter() {
        // Filter out certs that the user is not interested in.
        if ! filter.is_empty() && ! filter.iter().any(|q| q.matches(&cert)) {
            continue;
        }

        let acert = AuthenticatedCert::new(vtm.as_ref(), &cert)?;
        let vcert = cert.with_policy(p, None).ok();

        Record::PublicKey {
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
            curve: get_curve(cert.primary_key().mpis()),
        }.emit(&mut sink, config.with_colons)?;

        Record::Fingerprint(cert.fingerprint())
            .emit(&mut sink, config.with_colons)?;
        if config.with_keygrip {
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

            Record::Subkey {
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
                curve: get_curve(subkey.mpis()),
            }.emit(&mut sink, config.with_colons)?;

            if config.with_colons || config.with_subkey_fingerprint {
                Record::Fingerprint(subkey.fingerprint())
                    .emit(&mut sink, config.with_colons)?;
            }
            if config.with_keygrip {
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

fn get_curve(mpis: &PublicKey) -> Option<Curve> {
    match mpis {
        PublicKey::EdDSA { curve, .. }
        | PublicKey::ECDSA { curve, .. }
        | PublicKey::ECDH { curve, .. } => Some(curve.clone()),
        _ => None,
    }
}
