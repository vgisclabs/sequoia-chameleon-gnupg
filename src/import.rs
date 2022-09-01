use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::{
        CertParser,
    },
    packet::prelude::*,
    types::*,
    parse::{
        Parse,
    },
};

use crate::{
    control::Common,
    status::Status,
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

async fn real_cmd_import(config: &mut crate::Config, args: &[String])
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
        let parser = match
            CertParser::from_reader(utils::open(config, &filename)?)
        {
            Ok(c) => c,
            Err(e) => {
                config.warn(format_args!("can't open '{}': {}", filename, e));
                continue;
            },
        };
        for cert in parser {
            // We collect stats for the IMPORT_OK status line.
            use crate::status::*;
            let mut flags = crate::status::ImportOkFlags::default();

            s.count += 1;
            let cert = match cert {
                Ok(c) => c,
                Err(e) => {
                    // XXX: check for v3 key
                    // XXX: we also need to support revocation certificates
                    config.warn(format_args!("{}", e));
                    continue;
                },
            };

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
            if let Some(existing) =
                config.keydb().by_primary(&cert.key_handle())
            {
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
                    config.mut_keydb().insert(merged)?;
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
                config.mut_keydb().insert(cert)?;
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
                                                 &key, &subkey).await?;

                    changed |= c;
                    unchanged |= !c;
                }

                if changed {
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
        }
    }

    config.warn(format_args!("Total number processed: {}",
                             s.count + s.skipped_v3_keys));
    if s.skipped_v3_keys > 0 {
        config.warn(format_args!("    skipped PGP-2 keys: {}", s.skipped_v3_keys));
    }
    if s.skipped_new_keys  > 0 {
        config.warn(format_args!("      skipped new keys: {}",
                                 s.skipped_new_keys ));
    }
    if s.imported > 0 {
        config.warn(format_args!("              imported: {}", s.imported));
    }
    if s.unchanged  > 0 {
        config.warn(format_args!("             unchanged: {}", s.unchanged ));
    }
    if s.n_uids  > 0 {
        config.warn(format_args!("          new user IDs: {}", s.n_uids ));
    }
    if s.n_subk  > 0 {
        config.warn(format_args!("           new subkeys: {}", s.n_subk ));
    }
    if s.n_sigs  > 0 {
        config.warn(format_args!("        new signatures: {}", s.n_sigs ));
    }
    if s.n_revoc  > 0 {
        config.warn(format_args!("   new key revocations: {}", s.n_revoc ));
    }
    if s.sec_read  > 0 {
        config.warn(format_args!("      secret keys read: {}", s.sec_read ));
    }
    if s.sec_imported  > 0 {
        config.warn(format_args!("  secret keys imported: {}", s.sec_imported ));
    }
    if s.sec_dups  > 0 {
        config.warn(format_args!(" secret keys unchanged: {}", s.sec_dups ));
    }
    if s.not_imported  > 0 {
        config.warn(format_args!("          not imported: {}", s.not_imported ));
    }
    //if s.n_sigs_cleaned > 0 {
    //    config.warn(format_args!("    signatures cleaned: {}", s.n_sigs_cleaned));
    //}
    //if s.n_uids_cleaned > 0 {
    //    config.warn(format_args!("      user IDs cleaned: {}", s.n_uids_cleaned));
    //}
    config.status().emit(Status::ImportRes(s))?;

    drop(args);
    Ok(())
}
