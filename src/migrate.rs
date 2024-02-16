//! Handles migration from GnuPG < 2.1-style secrings.

use std::{
    fs,
};

use anyhow::Result;

use sequoia_openpgp::{
    cert::CertParser,
    parse::Parse,
};

use crate::common::Common;

#[cfg(unix)]
const V21_MIGRATION_FNAME: &'static str = ".gpg-v21-migrated";
#[cfg(windows)]
const V21_MIGRATION_FNAME: &'static str = "gpg-v21-migrated";

pub fn secring(config: &mut crate::Config) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(real_secring(config))
}

pub async fn real_secring(config: &mut crate::Config<'_>) -> Result<()> {
    let secring_name = config.homedir.join("secring.gpg");
    let mut secring = match fs::File::open(&secring_name) {
        Ok(f) => f,
        Err(_) => {
            // Doesn't exist or is not accessible.
            return Ok(());
        },
    };

    let flagfile_name = config.homedir.join(V21_MIGRATION_FNAME);
    if flagfile_name.exists() {
        // Migration done.
        return Ok(());
    }

    config.info(format_args!(
        "starting migration from earlier GnuPG versions"));

    // Note: we don't bother with locking because importing secret
    // keys is idempotent.

    config.info(format_args!(
        "porting secret keys from '{}' to gpg-agent",
        secring_name.display()));

    let mut s = crate::status::ImportResult::default();
    for cert in CertParser::from_reader(&mut secring)? {
        crate::import::do_import_cert(config, &mut s, cert?.into(), true)
            .await?;
    }

    if let Err(e) = fs::File::create(&flagfile_name) {
        config.error(format_args!(
            "error creating flag file '{}': {}", flagfile_name.display(), e));
    }
    config.info(format_args!("migration succeeded"));

    Ok(())
}
