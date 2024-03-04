use std::sync::Arc;

use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    KeyID,
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
use cert_store::{
    LazyCert,
    Store,
    StoreUpdate,
};

use crate::{
    argparse,
    argparse::options::Opt,
    common::Common,
    list_keys,
    utils,
};

/// Controls import operations.
#[derive(Default)]
pub struct ImportOptions {
    /// Import signatures that are marked as local-only.
    pub local_sigs: bool,

    /// Show key during import.
    pub show: bool,

    /// Do not clear the ownertrust values during import.
    pub keep_ownertrust: bool,

    /// Only accept updates to existing keys.
    pub merge_only: bool,

    /// Remove unusable parts from key after import.
    pub clean: bool,

    /// Remove as much as possible from key after import.
    pub minimal: bool,

    /// Ignore key-signatures which are not self-signatures.
    pub self_sigs_only: bool,

    /// Run import filters and export key immediately.
    pub export: bool,

    /// Assume the GnuPG key backup format.
    pub restore: bool,

    /// Do not actually import the keys.
    pub dry_run: bool,
}

impl ImportOptions {
    const OPTS: [Opt<ImportOptions>; 20] = [
        opt! {
            "import-local-sigs",
            |o, s, _| Ok({ o.local_sigs = s; }),
            "import signatures that are marked as local-only",
        },

        opt_todo! {
            "keep-ownertrust",
            |o, s, _| Ok({ o.keep_ownertrust = s; }),
            "do not clear the ownertrust values during import",
        },

        opt! {
            "import-show",
            |o, s, _| Ok({ o.show = s; }),
            "show key during import",
        },

        opt_todo! {
            "merge-only",
            |o, s, _| Ok({ o.merge_only = s; }),
            "only accept updates to existing keys",
        },

        opt_todo! {
            "import-clean",
            |o, s, _| Ok({ o.clean = s; }),
            "remove unusable parts from key after import",
        },

        opt_todo! {
            "import-minimal",
            |o, s, _| Ok({ o.minimal = s; o.clean = s; }),
            "remove as much as possible from key after import",
        },

        opt_todo! {
            "self-sigs-only",
            |o, s, _| Ok({ o.self_sigs_only = s; }),
            "ignore key-signatures which are not self-signatures",
        },

        opt_todo! {
            "import-export",
            |o, s, _| Ok({ o.export = s; }),
            "run import filters and export key immediately",
        },

        opt_todo! {
            "restore",
            |o, s, _| Ok({ o.restore = s; }),
            "assume the GnuPG key backup format",
        },
        opt_todo! {
            "import-restore",
            |o, s, _| Ok({ o.restore = s; }),
            "",
        },

        /* No description to avoid string change: Fixme for 2.3 */
        opt_todo! {
            "show-only",
            |o, s, _| Ok({ o.show = s; o.dry_run = s; }),
            "",
        },

        /* Aliases for backward compatibility */
        opt! {
            "allow-local-sigs",
            |o, s, _| Ok({ o.local_sigs = s; }),
            "",
        },

        // The following options are NOPs in the Chameleon.
        opt_nop!("repair-pks-subkey-bug"),
        opt_nop!("fast-import"),
        opt_nop!("repair-keys"),
        opt_nop!("repair-hkp-subkey-bug"),

        // The following options are NOPs in GnuPG.
        opt_nop!("import-unusable-sigs"),
        opt_nop!("import-clean-sigs"),
        opt_nop!("import-clean-uids"),
        opt_nop!("convert-sk-to-pk"),
    ];

    /// Prints the list of import options if requested.
    ///
    /// If `s == "help"`, prints all supported options and returns
    /// `true`.  The caller should then exit the process gracefully.
    pub fn maybe_print_help(s: &str) -> Result<bool> {
        argparse::options::maybe_print_help(&Self::OPTS, s)
    }

    /// Parses the import options.
    pub fn parse(&mut self, s: &str) -> Result<()> {
        argparse::options::parse(&Self::OPTS, s, self)
    }
}

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
                Ok(c) => do_import_cert(config, &mut s, c, false).await?,
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
                            cert: openpgp::Cert,
                            for_migration: bool) -> Result<()> {
    // We collect stats for the IMPORT_OK status line.
    use crate::status::*;
    let mut flags = crate::status::ImportOkFlags::default();

    // Maybe strip out local signatures.
    let cert = if config.import_options.local_sigs {
        cert
    } else {
        let mut p = cert.into_tsk().into_packets().collect::<Vec<_>>();
        p.retain(|p| match p {
            Packet::Signature(s) =>
                s.exportable_certification().unwrap_or(true),
            _ => true,
        });
        Cert::from_packets(p.into_iter())?
    };

    // We import the cert first, if this is a key, we'll deal
    // with the secrets later.
    let (cert, key) =
        (cert.clone().strip_secret_key_material(),
         Arc::new(LazyCert::from(cert)));

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
            // Considering the cert.
            if ! config.import_options.show {
                config.status().emit(
                    Status::KeyConsidered {
                        fingerprint: cert.fingerprint(),
                        not_selected: false,
                        all_expired_or_revoked: false,
                    })?;
            }
            if config.import_options.show {
                list_keys::async_list_keys(
                    config,
                    vec![key.clone()].into_iter(),
                    true, false, false, false,
                    std::io::stdout()).await?;
            } else if for_migration {
                // Be quiet when migrating.
            } else {
                config.warn(format_args!("key {:X}: {:?} not changed",
                                         cert.keyid(), primary_uid));
            }
        } else {
            // Clone stats so that we can summarize the changes.
            let s_before = s.clone();
            let (merged, changed) = existing.clone().insert_packets_merge(
                cert.into_packets2(),
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

            if for_migration {
                // Be quiet when migrating.
            } else if ! changed {
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

            // Considering the cert.
            if ! config.import_options.show {
                config.status().emit(
                    Status::KeyConsidered {
                        fingerprint: merged.fingerprint(),
                        not_selected: false,
                        all_expired_or_revoked: false,
                    })?;
            }

            // Actually store the cert.
            config.mut_keydb().update(Arc::new(merged.into()))?;
        }
    } else {
        let cert = Arc::new(LazyCert::from(cert));
        flags.set(IMPORT_OK_NEW_KEY);
        s.imported += 1;
        if config.import_options.show {
            list_keys::async_list_keys(
                config, vec![key.clone()].into_iter(),
                true, false, false, false,
                std::io::stdout()).await?;
        } else if for_migration {
            // Be quiet when migrating.
        } else {
            config.warn(format_args!("key {:X}: public key {:?} imported",
                                     cert.keyid(), primary_uid));
        }

        config.status().emit(
            Status::KeyConsidered {
                fingerprint: cert.fingerprint(),
                not_selected: false,
                all_expired_or_revoked: false,
            })?;
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
        config.mut_keydb().update(cert)?;
    }

    if key.is_tsk() {
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

        for subkey in key.to_cert()?.keys().secret() {
            // See if we import a new key or subkey.
            let c = crate::gpg_agent::import(&mut agent,
                                             config.policy(),
                                             key.to_cert()?, &subkey,
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
    use crate::status::*;

    match e.downcast_ref::<openpgp::Error>() {
        Some(openpgp::Error::UnsupportedCert2(_, _)) => {
            s.skipped_v3_keys += 1; // XXX: not very sharp
            return Ok(());
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

                    let primary_uid = utils::best_effort_primary_uid(
                        config.policy(), cert.to_cert()?);
                    config.warn(format_args!(
                        "key {:X}: {:?} revocation certificate imported",
                        cert.keyid(), primary_uid));

                    config.status().emit(
                        Status::KeyConsidered {
                            fingerprint: cert.fingerprint(),
                            not_selected: false,
                            all_expired_or_revoked: false,
                        })?;

                    // Actually store the cert.
                    config.mut_keydb().update(Arc::new(min.into()))?;
                    s.n_revoc += 1;
                } else {
                    // XXX: Would be nice to save unknown
                    //      revocations somewhere.
                    config.error(format_args!(
                        "key {}: no public key - \
                         can't apply revocation certificate",
                        issuers.first().map(KeyID::from)
                            .unwrap_or(KeyID::wildcard())));
                }
            }
            return Ok(());
        },
        _ => (),
    }

    use sequoia_net as net;
    match e.downcast_ref::<net::Error>() {
        Some(net::Error::NotFound) => return Ok(()),
        _ => (),
    }

    Err(e)
}
