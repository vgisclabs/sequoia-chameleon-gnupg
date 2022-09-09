use std::{
    io,
};

use anyhow::{Context, Result};

use sequoia_openpgp as openpgp;
use openpgp::{
    KeyHandle,
    serialize::stream::*,
    types::SignatureType,
};

use crate::{
    common::Common,
    status::{self, Status},
    utils,
};

/// Dispatches the --encrypt command.
///
/// Creates encrypted messages, optionally signing the plaintext
/// first.
pub fn cmd_encrypt(config: &crate::Config, args: &[String],
                   sign: bool)
                   -> Result<()>
{
    let policy = config.policy();
    let filenames =
        if args.is_empty() { vec!["-".into()] } else { args.to_vec() };

    if filenames.len() != 1 {
        return Err(anyhow::anyhow!("Only a single file name is allowed"));
    }

    // First, get the recipients.
    let mut recipients: Vec<Recipient> = vec![];
    for recipient in &config.remote_user {
        // XXX: honor constraints
        // XXX: currently, this only works with keyids and fingerprints
        let handle: KeyHandle = recipient.name.parse()
            .context("XXX: Recipients must be key handles")?;

        let cert = config.keydb().get(&handle)
            .ok_or_else(|| anyhow::anyhow!("Key {:X} not found", handle))?;

        // GnuPG always reports the cert fingerprint even if a subkey
        // has been given as recipient.
        config.status().emit(
            Status::KeyConsidered {
                fingerprint: cert.fingerprint(),
                not_selected: false,
                all_expired_or_revoked: false,
            })?;

        let vcert = cert.with_policy(policy, None)
            .context(format!("Key {:X} is not valid", handle))?;

        let mut found_one = false;
        for key in vcert.keys().alive().revoked(false).supported()
            .for_transport_encryption().for_transport_encryption()
        {
            recipients.push(key.key().into());
            found_one = true;
        }

        if ! found_one {
            return Err(anyhow::anyhow!(
                "Key {:X} is not encrypting-capable", handle))?;
        }
    }

    let mut sink = if let Some(name) = config.outfile() {
        utils::create(config, name)?
    } else {
        Box::new(io::stdout())
    };

    let mut message = Message::new(&mut sink);
    if config.armor {
        message = Armorer::new(message).build()?;
    }

    let cipher = config.def_cipher;
    let encryptor = Encryptor::for_recipients(message, recipients)
        .symmetric_algo(cipher);
    // XXX symmetric
    let mut message = encryptor.build()?;

    if let Some(algo) = config.compress_algo {
        message = Compressor::new(message).algo(algo).build()?;
    }

    if sign {
        // First, get the signers.
        let (mut signers, signers_desc) = crate::sign::get_signers(config)?;

        let timestamp = openpgp::types::Timestamp::now();
        let hash_algo = config.def_digest;
        let mut signer =
            Signer::new(message, signers.pop().expect("at least one"))
            .creation_time(timestamp)
            .hash_algo(hash_algo)?;
        for additional_signer in signers {
            signer = signer.add_signer(additional_signer);
        }

        message = signer.build()?;
        config.status().emit(Status::BeginSigning(hash_algo))?;

        let class = SignatureType::Binary;
        for (pk_algo, fingerprint) in signers_desc {
            config.status().emit(
                Status::SigCreated {
                    typ: status::SigType::Standard,
                    pk_algo,
                    hash_algo,
                    class,
                    timestamp,
                    fingerprint,
                })?;
        }
    }

    if true { // XXX wrapping
        message = LiteralWriter::new(message).build()?;
    }

    config.status().emit(Status::BeginEncryption {
        mdc_method: status::MDCMethod::SEIPDv1,
        cipher,
    })?;

    std::io::copy(&mut utils::open(config, &filenames[0])?, &mut message)?;
    message.finalize()?;

    config.status().emit(Status::EndEncryption)?;

    Ok(())
}
