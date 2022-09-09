use std::{
    io,
};

use anyhow::{Context, Result};

use sequoia_openpgp as openpgp;
use openpgp::{
    Fingerprint,
    KeyHandle,
    armor::Kind,
    crypto,
    serialize::stream::*,
    types::{PublicKeyAlgorithm, SignatureType},
};

use crate::{
    common::Common,
    status::{self, Status},
    utils,
};

/// Dispatches the --sign command.
///
/// Creates inline-signed messages, detached signature, and messages
/// using the Cleartext Signature Framework.
///
/// When creating detached signatures, all inputs are concatenated,
/// then signed.  Otherwise, only a single input is allowed, which
/// defaults to stdin.
pub fn cmd_sign(config: &crate::Config, args: &[String],
                detached: bool, cleartext: bool)
                -> Result<()>
{
    assert!(detached ^ cleartext);

    let filenames =
        if args.is_empty() { vec!["-".into()] } else { args.to_vec() };

    if ! detached && filenames.len() != 1 {
        return Err(anyhow::anyhow!("Only a single file name is allowed"));
    }

    // First, get the signers.
    let (mut signers, signers_desc) = get_signers(config)?;

    let mut sink = if let Some(name) = config.outfile() {
        utils::create(config, name)?
    } else {
        Box::new(io::stdout())
    };

    let mut message = Message::new(&mut sink);
    if config.armor && ! cleartext {
        message = Armorer::new(message)
            .kind(if detached { Kind::Signature } else { Kind::Message })
            .build()?;
    }

    // We fix hash algorithm and timestamp here, we need that for the
    // status messages.
    let timestamp = openpgp::types::Timestamp::now();
    let hash_algo = config.def_digest;

    let mut signer = Signer::new(message, signers.pop().expect("at least one"))
        .creation_time(timestamp)
        .hash_algo(hash_algo)?;

    if detached {
        signer = signer.detached();
    }

    if cleartext {
        signer = signer.cleartext();
    }

    for additional_signer in signers {
        signer = signer.add_signer(additional_signer);
    }

    let mut message = signer.build()?;

    if ! detached && ! cleartext {
        message = LiteralWriter::new(message).build()?;
    }

    config.status().emit(Status::BeginSigning(hash_algo))?;

    // In detached-mode, we concatenate the given files.  In
    // inline-mode, only one filename is allowed.
    for filename in filenames {
        std::io::copy(&mut utils::open(config, &filename)?, &mut message)?;
    }
    message.finalize()?;

    let typ = if cleartext {
        status::SigType::Cleartext
    } else if detached {
        status::SigType::Detached
    } else {
        status::SigType::Standard
    };
    let class = SignatureType::Binary;
    for (pk_algo, fingerprint) in signers_desc {
        config.status().emit(
            Status::SigCreated {
                typ,
                pk_algo,
                hash_algo,
                class,
                timestamp,
                fingerprint,
            })?;
    }

    Ok(())
}

pub fn get_signers(config: &crate::Config)
                   -> Result<(Vec<Box<dyn crypto::Signer + Send + Sync>>,
                              Vec<(PublicKeyAlgorithm, Fingerprint)>)> {
    let mut signers = vec![];
    let mut signers_desc = vec![];
    for local_user in config.local_users()? {
        // XXX: currently, this only works with keyids and fingerprints
        let handle: KeyHandle = local_user.parse()
            .context("Local users and default keys must be key handles")?;

        let cert = config.keydb().get(&handle)
            .ok_or_else(|| anyhow::anyhow!("Key {:X} not found", handle))?;

        config.status().emit(
            Status::KeyConsidered {
                fingerprint: cert.fingerprint(),
                not_selected: false,
                all_expired_or_revoked: false,
            })?;

        let vcert = cert.with_policy(config.policy(), None)
            .context(format!("Key {:X} is not valid", handle))?;

        let rt = tokio::runtime::Runtime::new()?;
        let mut found_one = false;
        for key in vcert.keys().for_signing() {
            if let Ok(signer) = rt.block_on(config.get_signer(&vcert, &key)) {
                signers.push(signer);
                signers_desc.push((key.pk_algo(), key.fingerprint()));
                found_one = true;
            }
        }
        if ! found_one {
            return Err(anyhow::anyhow!(
                "Key {:X} is not signing-capable", handle));
        }
    }

    if signers.is_empty() {
        return Err(anyhow::anyhow!("No signing keys found"));
    }

    Ok((signers, signers_desc))
}
