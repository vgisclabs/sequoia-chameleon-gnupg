use std::{
    borrow::Cow,
    io::Write,
};

use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    Cert,
    serialize::{Serialize, stream::*},
};

use sequoia_cert_store as cert_store;
use cert_store::Store;
use sequoia_net::dane;

use crate::{
    argparse,
    argparse::options::Opt,
    common::{Common, Query},
    filter,
    status::{Status, ExportResult},
    utils,
};

/// Controls export operations.
pub struct ExportOptions {
    /// Export signatures that are marked as local-only.
    pub local_sigs: bool,

    /// Export attribute user IDs (generally photo IDs).
    pub attributes: bool,

    /// Export revocation keys marked as "sensitive".
    pub sensitive: bool,

    /// Remove unusable parts from key during export.
    pub clean: bool,

    /// Remove as much as possible from key during export.
    pub minimal: bool,

    /// XXX.
    pub pka: bool,

    /// Export OpenPGP DANE records to put into DNS zone files.
    pub dane: bool,

    /// XXX.
    pub backup: bool,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            local_sigs: false,
            attributes: true,
            sensitive: false,
            clean: false,
            minimal: false,
            pka: false,
            dane: false,
            backup: false,
        }
    }
}

impl ExportOptions {
    const OPTS: [Opt<ExportOptions>; 15] = [
        opt! {
            "export-local-sigs",
            |o, s, _| Ok({ o.local_sigs = s; }),
            "export signatures that are marked as local-only",
        },

        opt_todo! {
            "export-attributes",
            |o, s, _| Ok({ o.attributes = s; }),
            "export attribute user IDs (generally photo IDs)",
        },

        opt_todo! {
            "export-sensitive-revkeys",
            |o, s, _| Ok({ o.sensitive = s; }),
            "export revocation keys marked as \"sensitive\"",
        },

        opt! {
            "export-clean",
            |o, s, _| Ok({ o.clean = s; }),
            "remove unusable parts from key during export",
        },

        opt! {
            "export-minimal",
            |o, s, _| Ok({ o.minimal = s; o.clean = s; }),
            "remove as much as possible from key during export",
        },

        opt_todo! {
            "export-pka",
            |o, s, _| Ok({ o.pka = s; }),
            "",
        },

        opt! {
            "export-dane",
            |o, s, _| Ok({ o.dane = s; }),
            "export OpenPGP DANE records to put into DNS zone files",
        },

        opt_todo! {
            "backup",
            |o, s, _| Ok({ o.backup = s; }),
            "use the GnuPG key backup format",
        },

        // Aliases for backward compatibility.
        opt_todo! {
            "export-backup",
            |o, s, _| Ok({ o.backup = s; }),
            "",
        },
        opt! {
            "include-local-sigs",
            |o, s, _| Ok({ o.local_sigs = s; }),
            "",
        },
        opt_todo! {
            "include-attributes",
            |o, s, _| Ok({ o.attributes = s; }),
            "",
        },
        opt_todo! {
            "include-sensitive-revkeys",
            |o, s, _| Ok({ o.sensitive = s; }),
            "",
        },

        // The following options are NOPs in GnuPG.
        opt_nop!("export-unusable-sigs"),
        opt_nop!("export-clean-sigs"),
        opt_nop!("export-clean-uids"),
    ];

    /// Prints the list of export options if requested.
    ///
    /// If `s == "help"`, prints all supported options and returns
    /// `true`.  The caller should then exit the process gracefully.
    pub fn maybe_print_help(s: &str) -> Result<bool> {
        argparse::options::maybe_print_help(&Self::OPTS, s)
    }

    /// Parses the export options.
    pub fn parse(&mut self, s: &str) -> Result<()> {
        argparse::options::parse(&Self::OPTS, s, self)
    }
}

/// Dispatches the --export command.
///
/// Exports the requested key material.
pub fn cmd_export(config: &mut crate::Config, args: &[String],
                  export_secret: bool)
                  -> Result<()>
{
    // We collect stats for the final EXPORT_RES status line.
    let mut s = ExportResult::default();

    let mut sink = if let Some(name) = config.outfile() {
        utils::create(config, name)?
    } else {
        Box::new(std::io::stdout())
    };

    let mut message = Message::new(&mut sink);
    if config.armor && ! config.export_options.dane {
        message = Armorer::new(message)
            .kind(if export_secret {
                openpgp::armor::Kind::SecretKey
            } else {
                openpgp::armor::Kind::PublicKey
            })
            .build()?;
    }

    let filter: Vec<Query> = args.iter()
        .map(|a| Query::from(&a[..]))
        .collect::<Vec<_>>();

    for cert in config.keydb().certs() {
        // Filter out non-exportable certs, like the trust root.
        if ! cert.to_cert().map(Cert::exportable).unwrap_or(false) {
            continue;
        }

        // This count doesn't include non-exportable certs to match
        // GnuPG's expectations of not having those.
        s.count += 1;

        // Only export keys with secret if so desired.
        if export_secret {
            // XXX: We need to ask the agent, and then coordinate the
            // export with the agent.
            if cert.to_cert().map(|c| c.is_tsk()).unwrap_or(false) { // XXX
                s.secret_count += 1;
            } else {
                continue; // No secrets, skip this cert.
            }
        }

        // Filter out certs that the user is not interested in.
        if ! filter.is_empty() && ! filter.iter().any(|q| q.matches(&cert)) {
            continue;
        }

        let vcert = cert.with_policy(config.policy(), config.now()).ok();

        // For some output options, we skip the cert if it isn't valid.
        if config.export_options.dane && vcert.is_none() {
            continue;
        }

        config.status().emit(Status::Exported {
            fingerprint: cert.fingerprint(),
        })?;
        s.exported += 1;

        if config.export_options.dane {
            let vcert = vcert.as_ref().expect("checked above");
            for (fqdn, uid) in vcert.userids()
                .filter_map(|u| if let Ok(Some(email)) = u.email2() {
                    email.split('@').nth(1).map(ToString::to_string)
                        .map(|fqdn| (fqdn, u.userid().clone()))
                } else {
                    None
                })
            {
                // First, we create a minimized cert that contains
                // only this one user ID.
                let cert = cert.to_cert()?.clone()
                    .retain_userids(|u| u.userid() == &uid);
                let vcert = cert.with_policy(config.policy(), config.now())?;

                // Then, emit the origin and comments.
                writeln!(message, "$ORIGIN _openpgpkey.{}.", fqdn)?;
                writeln!(message, "; {}", cert.fingerprint())?;
                writeln!(message, "; {}", String::from_utf8_lossy(uid.value()))?;

                // Finally, emit the record.  We need to doctor it to
                // look like what GnuPG emits.
                let entries = dane::generate_generic(&vcert, fqdn, None, None)?;
                assert_eq!(entries.len(), 1);
                let entry = entries.into_iter().next().unwrap();

                // It starts with a comment, which we ignore.
                assert!(entry.starts_with(";"));
                let mut lines = entry.split('\n');

                // The entry we split into components.
                let mut p = lines.nth(1).unwrap().split(' ');
                let domain = p.next().unwrap();
                let _ttl = p.next().unwrap();
                let _in = p.next().unwrap();
                let _type61 = p.next().unwrap();
                let _hash = p.next().unwrap();
                let length = p.next().unwrap();
                let value = p.next().unwrap();

                writeln!(message, "{} TYPE61 \\# {} (",
                         domain.split('.').next().unwrap().to_ascii_lowercase(),
                         length)?;
                for chunk in value.as_bytes().chunks(64) {
                    writeln!(message, "\t{}",
                             std::str::from_utf8(chunk)?.to_ascii_lowercase())?;
                }
                writeln!(message, "\t)")?;
                writeln!(message)?;
            }
        } else {
            // XXX: secrets from the agent.
            let mut cert = Cow::Borrowed(cert.to_cert()?);

            if config.export_options.minimal {
                cert = filter::minimal(config, cert)?;
            } else if config.export_options.clean {
                cert = filter::clean(config, cert)?;
            }

            if config.export_options.local_sigs {
                cert.serialize(&mut message)?;
            } else {
                cert.export(&mut message)?;
            }
        }
    }

    message.finalize()?;
    config.status().emit(Status::ExportRes(s))?;

    Ok(())
}
