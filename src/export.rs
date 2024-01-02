use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    serialize::stream::*,
};

use sequoia_cert_store as cert_store;
use cert_store::Store;

use crate::{
    argparse,
    argparse::options::Opt,
    common::{Common, Query},
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

    /// XXX.
    pub minimal: bool,

    /// XXX.
    pub pka: bool,

    /// XXX.
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
        opt_todo! {
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

        opt_todo! {
            "export-clean",
            |o, s, _| Ok({ o.clean = s; }),
            "remove unusable parts from key during export",
        },

        opt_todo! {
            "export-minimal",
            |o, s, _| Ok({ o.minimal = s; o.clean = s; }),
            "remove as much as possible from key during export",
        },

        opt_todo! {
            "export-pka",
            |o, s, _| Ok({ o.pka = s; }),
            "",
        },

        opt_todo! {
            "export-dane",
            |o, s, _| Ok({ o.dane = s; }),
            "",
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
        opt_todo! {
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
    if config.armor {
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

        config.status().emit(Status::Exported {
            fingerprint: cert.fingerprint(),
        })?;
        s.exported += 1;

        // XXX: secrets from the agent.
        cert.export(&mut message)?;
    }

    message.finalize()?;
    config.status().emit(Status::ExportRes(s))?;

    Ok(())
}
