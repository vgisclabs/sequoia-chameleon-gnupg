use anyhow::Result;

use sequoia_openpgp as openpgp;
use openpgp::{
    KeyHandle,
};
use sequoia_ipc::{
    gnupg::Agent,
};

use crate::{
    common::{Common, Query},
};

/// Dispatches the --delete-keys command.
pub fn cmd_delete_keys(config: &mut crate::Config, args: &[String],
                       secret: bool, allow_both: bool)
                       -> Result<()>
{
    if args.is_empty() {
        config.warn(format_args!("Note: No key"));
        return Ok(());
    }

    // Force allows us to delete a public key even if a secret key
    // exists.
    let force = !allow_both && !secret && config.expert;

    let rt = tokio::runtime::Runtime::new()?;
    let mut agent = rt.block_on(config.connect_agent())?;

    for arg in args {
        let query = Query::from(arg.as_str());

        if let Err(e) = rt.block_on(
            delete_key(config, &mut agent, &query, secret, force))
        {
            config.error(format_args!("{}: delete key failed: {}", query, e));
            return Err(e);
        }
    }

    Ok(())
}

async fn delete_key(config: &mut crate::Config<'_>, agent: &mut Agent,
                    query: &Query, delete_secret_keys: bool, force: bool)
                    -> Result<()>
{
    let (by_fingerprint, this_key_only) = match query {
        Query::Key(KeyHandle::KeyID(_)) => (false, false),
        Query::ExactKey(KeyHandle::KeyID(_)) => (false, true),
        Query::Key(KeyHandle::Fingerprint(_)) => (true, false),
        Query::ExactKey(KeyHandle::Fingerprint(_)) => (true, true),
        _ => (false, false),
    };

    let certs = config.lookup_certs(query).map_err(|e| {
        config.error(format_args!("key \"{}\" not found: {}", query, e));
        e
    })?;

    // Cowardly refuse to operate on more than one key at once.
    if certs.len() > 1 {
        return Err(anyhow::anyhow!("The query {} matched more than one key, \
                                    consider giving a fingerprint.", query));
    }

    let secrets = crate::agent::has_keys(agent, &certs[0].1).await?;

    // XXX: delete subkeys, delete secret keys...
    if ! secrets.is_empty() || force {
        config.mut_keydb().remove(certs[0].1.fingerprint())?;
    }

    Ok(())
}
