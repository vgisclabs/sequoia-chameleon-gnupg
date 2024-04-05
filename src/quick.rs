//! Various --quick-* commands, like --quick-add-uid.

use std::{
    sync::Arc,
};

use anyhow::{Context, Result};

use sequoia_openpgp as openpgp;
use openpgp::{
    cert::{
        Preferences,
        UserIDRevocationBuilder,
    },
    packet::{
        UserID,
        Packet,
        signature::{
            SignatureBuilder,
        },
    },
    types::*,
};

use sequoia_cert_store::{
    StoreUpdate,
};

use crate::{
    Query,
    common::Common,
    error_codes,
    status::Status,
};

/// Dispatches the --quick-add-uid command.
pub fn cmd_quick_add_uid(config: &mut crate::Config, args: &[String])
                         -> Result<()>
{
    if args.len() != 2 {
        config.wrong_args(format_args!("--quick-add-uid USER-ID NEW-USER-ID"));
    }
    let query: Query = args[0].parse()?;
    let new_uid = UserID::from(args[1].clone());

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(add_uid(config, query, new_uid))
}

async fn add_uid(config: &mut crate::Config<'_>, query: Query, new_uid: UserID)
                 -> Result<()>
{
    // Lookup without groups.
    let certs = config.lookup_certs_with(
        config.trust_model_impl.with_policy(config, Some(config.now()))?.as_ref(),
        &query,
        false)?;

    // Cowardly refuse any queries that resolve to multiple keys.  In
    // my mind, using queries other than fingerprints is fragile and
    // should be avoided.
    let cert = match certs.len() {
        0 => return Err(anyhow::anyhow!("Key {} not found", query)),
        1 => &certs[0].1,
        n => return Err(anyhow::anyhow!(
            "Query {} maps to {} different keys: {:?}", query, n,
            certs.iter().map(|c| c.1.fingerprint().to_string())
                .collect::<Vec<_>>())),
    };

    let vcert = cert.with_policy(config.policy(), config.now())
        .context(format!("Key {} is not valid", query))?;

    let mut signer = config.get_signer(
        &vcert, vcert.primary_key().key().role_as_unspecified()).await?;

    let mut sig = SignatureBuilder::new(SignatureType::PositiveCertification)
        .set_signature_creation_time(config.now())?;

    match signer.public().version() {
        4 => {
            sig = sig
                .set_key_expiration_time(
                    vcert.primary_key().key(),
                    vcert.primary_key().key_expiration_time())?
                .set_preferred_hash_algorithms(
                    config.personal_digest_prefs.as_ref()
                        .unwrap_or(&config.def_preferences.hash).clone())?
                .set_preferred_symmetric_algorithms(
                    config.personal_cipher_prefs.as_ref()
                        .unwrap_or(&config.def_preferences.symmetric).clone())?
                .set_preferred_compression_algorithms(
                    config.personal_compress_prefs.as_ref()
                        .unwrap_or(&config.def_preferences.compression).clone())?
                .set_features(Features::sequoia())?;

            if let Some(f) = vcert.primary_key().key_flags() {
                sig = sig.set_key_flags(f)?;
            };

            if ! config.def_preferences.ks_modify {
                sig = sig.set_key_server_preferences(
                    KeyServerPreferences::empty().set_no_modify())?;
            }

            if let Some(u) = vcert.preferred_key_server() {
                sig = sig.set_preferred_key_server(u)?;
            }
        },
        n => return Err(anyhow::anyhow!("v{} keys are not supported", n)),
    };

    let binding = new_uid.bind(&mut signer, vcert.cert(), sig)?;
    let cert = cert.to_cert()?.clone()
        .insert_packets(vec![
            Packet::from(new_uid),
            binding.into(),
        ])?;

    // Actually store the cert.
    config.mut_keydb().update(
        Arc::new(cert.clone().strip_secret_key_material().into()))?;

    Ok(())
}

/// Dispatches the --quick-revoke-uid command.
pub fn cmd_quick_revoke_uid(config: &mut crate::Config, args: &[String])
                            -> Result<()>
{
    if args.len() < 2 {
        config.wrong_args(format_args!("--quick-revoke-uid USER-ID \
                                        USER-ID-TO-REVOKE"));
    }
    let query: Query = args[0].parse()?;
    let rev_uid = UserID::from(args[1].clone());

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(revoke_uid(config, query, rev_uid))
        .map_err(|e| {
            if let Some(e) = e.downcast_ref::<error_codes::Error>() {
                let _ = config.status_fd.emit(Status::Failure {
                    location: "keyedit.revoke.uid",
                    error: *e,
                });
            }
            anyhow::anyhow!("revoking the user ID failed: {}", e)
        })
}

async fn revoke_uid(config: &mut crate::Config<'_>, query: Query, rev_uid: UserID)
                    -> Result<()>
{
    // Lookup without groups.
    let certs = config.lookup_certs_with(
        config.trust_model_impl.with_policy(config, Some(config.now()))?.as_ref(),
        &query,
        false)?;

    // Cowardly refuse any queries that resolve to multiple keys.  In
    // my mind, using queries other than fingerprints is fragile and
    // should be avoided.
    let cert = match certs.len() {
        0 => return Err(anyhow::anyhow!("Key {} not found", query)),
        1 => &certs[0].1,
        n => return Err(anyhow::anyhow!(
            "Query {} maps to {} different keys: {:?}", query, n,
            certs.iter().map(|c| c.1.fingerprint().to_string())
                .collect::<Vec<_>>())),
    };

    let cert = cert.to_cert()?;

    if ! cert.userids().any(|u| u.userid() == &rev_uid) {
        return Err(error_codes::Error::GPG_ERR_NO_USER_ID.into());
    }

    let vcert = cert.with_policy(config.policy(), config.now())
        .context(format!("Key {} is not valid", query))?;

    let mut signer = config.get_signer(
        &vcert, cert.primary_key().key().role_as_unspecified()).await?;

    let rev = UserIDRevocationBuilder::new()
        .set_signature_creation_time(config.now())?
        .set_reason_for_revocation(ReasonForRevocation::UIDRetired, b"")?
        .build(&mut signer, cert, &rev_uid, None)?;

    let cert = cert.clone()
        .insert_packets(vec![
            Packet::from(rev),
        ])?;

    // Actually store the cert.
    config.mut_keydb().update(
        Arc::new(cert.clone().strip_secret_key_material().into()))?;

    Ok(())
}
