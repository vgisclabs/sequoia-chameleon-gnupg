use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    serialize::{Serialize, stream::*},
};

use crate::{
    common::{Common, Query},
    status::{Status, ExportResult},
    utils,
};

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

    for cert in config.keydb().iter() {
        s.count += 1;

        // Only export keys with secret if so desired.
        if export_secret {
            // XXX: We need to ask the agent, and then coordinate the
            // export with the agent.
            if cert.is_tsk() { // XXX
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
