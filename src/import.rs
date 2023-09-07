use std::borrow::Cow;

use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::{
        Cert,
        raw::RawCertParser,
    },
    packet::prelude::*,
    types::*,
    parse::{
        Parse,
        PacketParser,
        PacketParserResult,
        buffered_reader::{self, BufferedReader},
    },
};

use sequoia_cert_store as cert_store;
use cert_store::Store;
use cert_store::StoreUpdate;

use crate::{
    common::Common,
    utils,
};

/// Dispatches the --import command.
///
/// Imports provided key material.
pub fn cmd_import(config: &mut crate::Config, args: &[String])
                  -> Result<()>
{
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(real_cmd_import(config, args))
}

async fn real_cmd_import(config: &mut crate::Config<'_>, args: &[String])
                         -> Result<()>
{
    // We collect stats for the final IMPORT_RES status line.
    let mut s = crate::status::ImportResult::default();

    // If the list of arguments is empty, stdin is implied.
    let stdin: Vec<String> = vec!["-".to_string()];
    let filenames = if args.is_empty() {
        &stdin
    } else {
        args
    };

    // Parse every cert from every file.
    for filename in filenames {
        let mut saw_failures = false;

        // XXX: Would be nice to mmap the file.
        let reader = match utils::open(config, &filename)
            .map(|f| buffered_reader::Generic::new(f, None))
        {
            Ok(c) => c,
            Err(e) => {
                config.warn(format_args!("can't open '{}': {}", filename, e));
                continue;
            },
        };
        let mut dup = buffered_reader::Dup::new(reader);
        for cert in RawCertParser::from_reader(&mut dup)? {
            s.count += 1;

            // Ignore corrupt and invalid certificates.
            match cert.and_then(TryInto::try_into) {
                Ok(c) => do_import_cert(config, &mut s, c).await?,
                Err(e) => {
                    // XXX: This is awkward.  It'd be nice if we'd get
                    // the vector of packets that failed to parse into
                    // a cert here.
                    saw_failures = true;
                    do_import_failed(config, &mut s, e, vec![]).await?;
                },
            }
        }

        if saw_failures {
            // Try again, this time comb only for revocations.  This
            // is not ideal, because we don't handle concatenated
            // armored revocations this way.
            let reader = Box::new(dup).into_inner()
                .expect("it's the Dup reader");
            let mut ppr = PacketParser::from_reader(reader)?;
            let mut packets = vec![];
            while let PacketParserResult::Some(pp) = ppr {
                let (packet, next_ppr) = pp.next()?;
                packets.push(packet);
                ppr = next_ppr;
            }
            do_import_failed(
                config, &mut s,
                // Fake error that selects revocation handling.
                openpgp::Error::MalformedCert("".into()).into(),
                packets).await?;
        }
    }

    s.print_results(config)?;
    Ok(())
}

pub async fn do_import_cert(config: &mut crate::Config<'_>,
                            s: &mut crate::status::ImportResult,
                            cert: openpgp::Cert) -> Result<()> {
    // We collect stats for the IMPORT_OK status line.
    use crate::status::*;
    let mut flags = crate::status::ImportOkFlags::default();

    // Considering the cert.
    config.status().emit(
        Status::KeyConsidered {
            fingerprint: cert.fingerprint(),
            not_selected: false,
            all_expired_or_revoked: false,
        })?;

    // We import the cert first, if this is a key, we'll deal
    // with the secrets later.
    let (cert, key) = if cert.is_tsk() {
        (cert.clone().strip_secret_key_material(), Some(cert))
    } else {
        (cert, None)
    };

    // Get a best-effort primary user id for display and
    // status-fd purposes.
    let primary_uid =
        utils::best_effort_primary_uid(config.policy(), &cert);

    // See if we know the cert.
    if let Ok(existing) =
        config.keydb().lookup_by_cert_fpr(&cert.fingerprint())
    {
        let mut _existing;
        let existing = if let Ok(c) = existing.to_cert() {
            c
        } else {
            // We failed to turn a RawCert into a Cert.  Now it's time
            // for some insanity: we clone the new certificate's
            // primary key and turn it into a Cert.  This will cause
            // the existing entry to be overwritten, which is the best we
            // can do in this case.
            _existing = Cert::from_packets(
                std::iter::once(
                    Packet::from(cert.primary_key().key().clone())))
                .expect("valid");
            &_existing
        };

        // We do, this is an update.
        if &cert == existing {
            s.unchanged += 1;
            config.status().emit(
                Status::ImportOk {
                    flags,
                    fingerprint: Some(cert.fingerprint()),
                })?;
            config.warn(format_args!("key {:X}: {:?} not changed",
                                     cert.keyid(), primary_uid));
        } else {
            // Clone stats so that we can summarize the changes.
            let s_before = s.clone();
            let (merged, changed) = existing.clone().insert_packets_merge(
                cert.into_packets(),
                |old, new| {
                    match (&old, &new) {
                        (None, Packet::UserID(_))
                            | (None, Packet::UserAttribute(_)) =>
                        {
                            flags.set(IMPORT_OK_NEW_UIDS);
                            s.n_uids += 1;
                        },
                        (None, Packet::PublicSubkey(_)) => {
                            flags.set(IMPORT_OK_NEW_SUBKEYS);
                            s.n_subk += 1;
                        },
                        (None, Packet::Signature(sig)) => {
                            flags.set(IMPORT_OK_NEW_SIGS);
                            match sig.typ() {
                                SignatureType::KeyRevocation
                                    | SignatureType::SubkeyRevocation
                                    | SignatureType::CertificationRevocation =>
                                    s.n_revoc += 1,
                                _ => s.n_sigs += 1,
                            }
                        },
                        _ => (),
                    }
                    Ok(new)
                })?;

            // Redo the computation, maybe the imported key had
            // incomplete information.
            let primary_uid =
                utils::best_effort_primary_uid(config.policy(), &merged);

            if ! changed {
                // I think this should not happen because it
                // is handled above, but better be safe than
                // sorry.
                s.unchanged += 1;
                config.warn(format_args!("key {:X}: {:?} not changed",
                                         existing.keyid(), primary_uid));
            } else {
                let pluralize = |what, count| -> String {
                    format!("{} {}{}", count, what,
                            if count == 1 { "" } else { "s" })
                };
                // Summarize what changed.
                let d = s.changed_since(s_before);

                if d.n_uids > 0 {
                    config.warn(format_args!(
                        "key {:X}: {:?} {}",
                        existing.keyid(), primary_uid,
                        pluralize("new user ID",  d.n_uids)));
                }

                if d.n_sigs > 0 {
                    config.warn(format_args!(
                        "key {:X}: {:?} {}",
                        existing.keyid(), primary_uid,
                        pluralize("new signature",  d.n_sigs)));
                }

                if d.n_revoc > 0 {
                    config.warn(format_args!(
                        "key {:X}: {:?} {}",
                        existing.keyid(), primary_uid,
                        pluralize("new revocation",  d.n_revoc)));
                }

                if d.n_subk > 0 {
                    config.warn(format_args!(
                        "key {:X}: {:?} {}",
                        existing.keyid(), primary_uid,
                        pluralize("new subkey",  d.n_subk)));
                }
            }

            config.status().emit(
                Status::ImportOk {
                    flags,
                    fingerprint: Some(merged.fingerprint()),
                })?;

            // Actually store the cert.
            config.mut_keydb().update(Cow::Owned(merged.into()))?;
        }
    } else {
        flags.set(IMPORT_OK_NEW_KEY);
        s.imported += 1;
        config.warn(format_args!("key {:X}: public key {:?} imported",
                                 cert.keyid(), primary_uid));
        config.status().emit(
            Status::Imported {
                keyid: cert.keyid(),
                username: primary_uid,
            })?;
        config.status().emit(
            Status::ImportOk {
                flags,
                fingerprint: Some(cert.fingerprint()),
            })?;

        // Actually store the cert.
        config.mut_keydb().update(Cow::Owned(cert.into()))?;
    }

    if let Some(key) = key {
        let mut agent = config.connect_agent().await?;

        // We collect stats for the IMPORT_OK status line.
        let mut flags = crate::status::ImportOkFlags::default();
        flags.set(IMPORT_OK_HAS_SECRET);
        s.sec_read += 1;

        // GnuPG summarizes changes on a TSK-granularity.  If
        // we see a new subkey in a known TSK, that TSK is
        // imported and unchanged at the same time.
        let mut changed = false;
        let mut unchanged = false;

        for subkey in key.keys().secret() {
            // See if we import a new key or subkey.
            let c = crate::agent::import(&mut agent,
                                         config.policy(),
                                         &key, &subkey,
                                         config.batch).await?;

            changed |= c;
            unchanged |= !c;
        }

        if changed {
            flags.set(IMPORT_OK_NEW_KEY);
            s.sec_imported += 1;
        }
        if unchanged {
            s.sec_dups += 1;
        }

        config.warn(format_args!("key {:X}: secret key imported",
                                 key.keyid()));
        config.status().emit(
            Status::ImportOk {
                flags,
                fingerprint: Some(key.fingerprint()),
            })?;
    }

    Ok(())
}

pub async fn do_import_failed(config: &mut crate::Config<'_>,
                              s: &mut crate::status::ImportResult,
                              e: anyhow::Error,
                              packets: Vec<openpgp::Packet>) -> Result<()>
{
    match e.downcast_ref::<openpgp::Error>() {
        Some(openpgp::Error::UnsupportedCert2(_, _)) => {
            s.skipped_v3_keys += 1; // XXX: not very sharp
        },
        Some(openpgp::Error::MalformedCert(_)) => {
            let mut revocations = Vec::new();
            for p in packets {
                use SignatureType::*;
                match p {
                    Packet::Signature(s) => {
                        if s.typ() == KeyRevocation
                            || s.typ() == SubkeyRevocation
                            || s.typ() == CertificationRevocation
                        {
                            revocations.push(s);
                        } else {
                            config.warn(format_args!(
                                "Ignoring non-revocation signature: {}",
                                s.typ()));
                        }
                    },
                    _ => (),
                }
            }

            for revocation in revocations {
                // See if we have the revokee.
                // XXX: Support 3rd-party revocations.
                let issuers = revocation.get_issuers();
                if let Some(cert) = issuers.iter()
                    .flat_map(|i| {
                        config.keydb().lookup_by_cert(i).unwrap_or(Vec::new())
                    })
                    .next()
                {
                    // Good.  Now, construct a minimal cert to import.
                    let min = openpgp::Cert::from_packets(vec![
                        cert.primary_key().clone().into(),
                        Packet::from(revocation.clone()),
                    ].into_iter())?;
                    do_import_cert(config, s, min).await?;
                } else {
                    // XXX: Would be nice to save unknown
                    //      revocations somewhere.
                    config.warn(format_args!(
                        "Ignoring revocation for unknown key{}",
                        issuers.first().map(|i| format!(" {:X}", i))
                            .unwrap_or_default()));
                }
            }
        },
        _ => (),
    }

    use crate::net;
    match e.downcast_ref::<net::Error>() {
        Some(net::Error::NotFound) => return Ok(()),
        _ => (),
    }

    Err(e)
}
